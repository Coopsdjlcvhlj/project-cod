# logger_setup.py
import logging, logging.handlers, json, os
from config import LOG_DIR

class JsonFormatter(logging.Formatter):
    def format(self, record):
        base = {
            "time": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "msg": record.getMessage()
        }
        if hasattr(record, "extra"):
            base.update(record.extra)
        return json.dumps(base, ensure_ascii=False)

logger = logging.getLogger("netmon")
logger.setLevel(logging.INFO)
handler = logging.handlers.RotatingFileHandler(os.path.join(LOG_DIR, "events.jsonl"), maxBytes=5*1024*1024, backupCount=5, encoding="utf-8")
handler.setFormatter(JsonFormatter())
logger.addHandler(handler)
# console
ch = logging.StreamHandler()
ch.setFormatter(JsonFormatter())
logger.addHandler(ch)
