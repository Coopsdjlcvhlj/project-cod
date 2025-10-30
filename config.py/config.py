
import os

BASE_DIR = os.path.dirname(__file__)
LOG_DIR = os.path.join(BASE_DIR, "security_logs")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
PCAP_DIR = os.path.join(BASE_DIR, "pcaps")
WHITELIST_FILE = os.path.join(BASE_DIR, "whitelist.json")
HTTP_CREDENTIALS_FILE = os.path.join(LOG_DIR, "http_credentials.txt")
ALERT_THROTTLE_SECONDS = 60  
MAX_PCAP_SECONDS = 30  

for d in (LOG_DIR, UPLOAD_DIR, PCAP_DIR):
    os.makedirs(d, exist_ok=True)
