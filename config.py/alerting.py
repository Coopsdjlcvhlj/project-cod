
import time
from logger_setup import logger
from config import ALERT_THROTTLE_SECONDS
import os
import requests

_last_alert_time = 0

TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN")  
TG_CHAT_ID = os.getenv("TG_CHAT_ID")      
def alert(message: str, severity: str = "medium"):
    """
    message: текст алерта
    severity: low/medium/high
    """
    global _last_alert_time
    now = time.time()
    if now - _last_alert_time < ALERT_THROTTLE_SECONDS:
        logger.info("Alert suppressed by throttle", extra={"extra":{"msg": message, "severity": severity}})
        return
    _last_alert_time = now

    
    logger.warning("ALERT: " + message, extra={"extra":{"severity": severity}})

    
    if TG_BOT_TOKEN and TG_CHAT_ID:
        try:
            send_telegram(TG_BOT_TOKEN, TG_CHAT_ID, f"[{severity.upper()}] {message}")
        except Exception as e:
            logger.exception("Failed to send telegram alert: %s" % e)

def send_telegram(token: str, chat_id: str, text: str):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text}
    r = requests.post(url, data=payload, timeout=10)
    if not r.ok:
        logger.error("Telegram API error", extra={"extra":{"status_code": r.status_code, "resp": r.text}})
    return r
