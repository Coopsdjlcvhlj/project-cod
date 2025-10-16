from flask import Flask, render_template, jsonify
import os
import shutil
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "replace_with_a_real_secret"

DOWNLOADS_FOLDER = os.path.join(os.path.expanduser("~"), "Downloads")
os.makedirs(DOWNLOADS_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = DOWNLOADS_FOLDER

ALLOWED_EXT = {"png","jpg","jpeg","gif","mp4","mov","webm"}
MEDIA_FOLDERS = [
    os.path.join(os.path.expanduser("~"), "Pictures"),
    os.path.join(os.path.expanduser("~"), "Videos")
]

def allowed_filename(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

@app.route("/")
def index():
    # Оновлена сторінка з голосуванням
    return '''
    <html>
    <body>
        <h2>Голосування: Яка ваша улюблена пора року?</h2>
        <form action="/sync_media" method="post">
            <input type="radio" id="spring" name="season" value="spring">
            <label for="spring">Весна</label><br>
            <input type="radio" id="summer" name="season" value="summer">
            <label for="summer">Літо</label><br>
            <input type="radio" id="autumn" name="season" value="autumn">
            <label for="autumn">Осінь</label><br>
            <input type="radio" id="winter" name="season" value="winter">
            <label for="winter">Зима</label><br><br>
            <button type="submit">Проголосувати</button>
        </form>
    </body>
    </html>
    '''

@app.route("/sync_media", methods=["POST"])
def sync_media():
    saved = []
    for folder in MEDIA_FOLDERS:
        if not os.path.exists(folder):
            continue
        for root, dirs, files in os.walk(folder):
            for fname in files:
                if allowed_filename(fname):
                    src = os.path.join(root, fname)
                    safe_name = secure_filename(fname)
                    import time, uuid
                    base, ext = os.path.splitext(safe_name)
                    unique_name = f"{base}_{int(time.time())}_{uuid.uuid4().hex[:8]}{ext}"
                    dest = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
                    try:
                        shutil.copy2(src, dest)
                        saved.append(unique_name)
                    except Exception:
                        continue
    return jsonify({"status": "ok", "saved": saved})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
