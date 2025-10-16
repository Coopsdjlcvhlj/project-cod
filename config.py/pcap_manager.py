# pcap_manager.py
import os, time
from scapy.utils import PcapWriter
from scapy.all import sniff
from config import PCAP_DIR, MAX_PCAP_SECONDS
from logger_setup import logger

def save_window(duration=MAX_PCAP_SECONDS, iface=None, prefix="event"):
    """
    Захопити пакети протягом duration секунд і записати у pcap-файл.
    Повертає шлях до файлу або None при помилці.
    """
    ts = int(time.time())
    fname = os.path.join(PCAP_DIR, f"{prefix}_{ts}.pcap")
    try:
        logger.info("Starting pcap capture", extra={"extra":{"file": fname, "seconds": duration}})
        writer = PcapWriter(fname, append=False, sync=True)
        def _write(pkt):
            writer.write(pkt)
        sniff(timeout=duration, prn=_write, iface=iface)
        writer.close()
        logger.info("PCAP saved", extra={"extra":{"file": fname}})
        return fname
    except Exception as e:
        logger.exception("PCAP capture error: %s" % e)
        return None
