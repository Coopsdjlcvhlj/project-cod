
import time, random
from correlator import push_event
from logger_setup import logger

def simulate_arp(ip="192.168.1.100", mac=None):
    if mac is None:
        mac = "de:ad:be:ef:" + ("%02x"%random.randint(0,255))
    ev = {"type":"arp","time":time.time(),"src_ip":ip,"src_mac":mac,"op":2}
    logger.info("Simulated ARP", extra={"extra":ev})
    push_event(ev)

def simulate_http_creds(src="192.168.1.100", payload="username=test&password=123456"):
    ev = {"type":"http_creds","time":time.time(),"src":src,"detail":payload}
    logger.info("Simulated HTTP creds", extra={"extra":ev})
    push_event(ev)

def run_demo_loop(interval=5, iterations=6):
    logger.info("Starting simulator demo loop", extra={"extra":{"interval":interval}})
    for i in range(iterations):
        simulate_arp(ip=f"192.168.1.{100+i}")
        time.sleep(1)
        if random.random() > 0.3:
            simulate_http_creds(src=f"192.168.1.{100+i}", payload=f"username=user{i}&password=pass{i}")
        time.sleep(interval)
    logger.info("Simulator demo finished")
