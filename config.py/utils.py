# utils.py
import re, hashlib, os
from config import HTTP_CREDENTIALS_FILE
import json

def mask_sensitive(s: str) -> str:
    # просте маскування password-like полів
    return re.sub(r'(?i)(password|passwd|pwd|pass)=([^&\s]+)', lambda m: f"{m.group(1)}=***", s)

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def save_http_cred(line: str):
    os.makedirs(os.path.dirname(HTTP_CREDENTIALS_FILE), exist_ok=True)
    with open(HTTP_CREDENTIALS_FILE, "a", encoding="utf-8") as f:
        f.write(line.strip()+"\n")
