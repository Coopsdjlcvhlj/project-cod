# dashboard.py
from flask import Flask, jsonify, render_template_string
import os, json
from config import LOG_DIR
from logger_setup import logger

app = Flask(__name__)

TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>NetMon Dashboard</title>
  <style>
    body{font-family:Arial;padding:16px}
    pre{background:#f6f6f6;padding:8px;border-radius:6px;max-height:600px;overflow:auto}
  </style>
</head>
<body>
  <h1>NetMon — останні події</h1>
  <p><a href="/health">Health</a></p>
  <pre id="logs">{{logs}}</pre>
</body>
</html>
"""

def read_last_lines(path, n=200):
    if not os.path.exists(path):
        return []
    lines = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            lines.append(line.strip())
    return lines[-n:]

@app.route("/")
def index():
    path = os.path.join(LOG_DIR, "events.jsonl")
    lines = read_last_lines(path, 300)
    # pretty print
    parsed = "\n".join(lines)
    return render_template_string(TEMPLATE, logs=parsed)

@app.route("/health")
def health():
    return jsonify({"status":"ok"})
