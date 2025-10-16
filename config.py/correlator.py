import time
from logger_setup import logger
from alerting import alert

RECENT = []
TTL = 60  
def push_event(ev: dict):
    ev['time'] = time.time()
    RECENT.append(ev)
   
    _cleanup()
    _try_correlate(ev)

def _cleanup():
    now = time.time()
    while RECENT and now - RECENT[0]['time'] > TTL:
        RECENT.pop(0)

def _try_correlate(ev):
 
    if ev.get('type') == 'arp':
        candidates = [e for e in RECENT if e.get('type','').startswith('http') and e.get('src') == ev.get('src_ip')]
        if candidates:
            msg = f"Correlation detected: ARP + HTTP events from {ev.get('src_ip')}"
            logger.warning(msg, extra={"extra":{"arp": ev, "hits": candidates}})
            alert(msg, severity="high")
