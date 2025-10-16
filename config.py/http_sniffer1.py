import pyshark, time, os, mimetypes
from logger_setup import logger
from utils import mask_sensitive, save_http_cred, sha256_file
from config import UPLOAD_DIR
from correlator import push_event
from file_handler import try_extract_and_save_file

def parse_http_packet(pkt):
    try:
        layers = pkt.layers
       
        if hasattr(pkt, 'http'):
            http = pkt.http
            host = getattr(http, "host", None)
            uri = getattr(http, "request_uri", None) or getattr(http, "request_full_uri", None)
            raw = str(http)
            masked = mask_sensitive(raw)
            
            if re_search_credentials(masked):
                save_http_cred(f"{time.time()} {pkt.ip.src} {masked}")
                logger.warning("Possible credentials in HTTP", extra={"extra":{"src": pkt.ip.src, "data": masked}})
                push_event({"type":"http_creds","time":time.time(),"src":pkt.ip.src,"detail":masked})
           
            if hasattr(http, "file_data"):
              
                raw_data = http.file_data.binary_value
              
                try_extract_and_save_file(raw_data, host, uri, pkt.ip.src)
            else:
               
                logger.info("HTTP seen", extra={"extra":{"src": pkt.ip.src, "host": host, "uri": uri}})
    except Exception as e:
        logger.exception("Error parsing http pkt: %s" % e)

import re
CRED_RE = re.compile(r'(?i)(username|user|login|email|password|pass|pwd)=([^&\s]+)')
def re_search_credentials(s: str):
    return bool(CRED_RE.search(s))

def start_http_sniffer(iface=None):
    logger.info("Starting HTTP sniffer", extra={"extra":{"iface": iface}})
    capture = pyshark.LiveCapture(interface=iface, bpf_filter='tcp port 80 or tcp port 8080')
    for pkt in capture.sniff_continuously():
        parse_http_packet(pkt)
