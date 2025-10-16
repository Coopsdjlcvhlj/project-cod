from scapy.all import sniff, ARP
from logger_setup import logger
import json, time
from config import WHITELIST_FILE, PCAP_DIR, MAX_PCAP_SECONDS
from correlator import push_event
import os

def load_whitelist():
    try:
        with open(WHITELIST_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"mac": [], "ip": []}

WHITELIST = load_whitelist()

def is_suspicious(pkt):
    
    if ARP in pkt and pkt[ARP].op == 2:
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        if ip in WHITELIST.get("ip", []) or mac in WHITELIST.get("mac", []):
            return False
       
        return True
    return False

def handle_arp(pkt):
    if ARP not in pkt: return
    rec = {
        "type": "arp",
        "time": time.time(),
        "src_ip": pkt[ARP].psrc,
        "src_mac": pkt[ARP].hwsrc,
        "op": pkt[ARP].op
    }
    if is_suspicious(pkt):
        logger.info("Suspicious ARP", extra={"extra":rec})
        push_event(rec)

    else:
        logger.info("ARP seen", extra={"extra":rec})

def start_arp_monitor(iface=None):
    logger.info("Starting ARP monitor", extra={"extra":{"iface": iface}})
    sniff(filter="arp", prn=handle_arp, store=False, iface=iface)
