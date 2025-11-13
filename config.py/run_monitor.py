
import threading, time
from logger_setup import logger
from resource_monitor import monitor
from dashboard import app as dashboard_app
from simulator import run_demo_loop
import argparse
import os


try:
    from main1.arp_monitor import start_arp_monitor
except Exception as e:
    start_arp_monitor = None
    logger.warning("ARP monitor not available: %s" % e)

try:
    from http_sniffer import start_http_sniffer
except Exception as e:
    start_http_sniffer = None
    logger.warning("HTTP sniffer not available: %s" % e)

def start_dashboard():
    logger.info("Starting dashboard on http://127.0.0.1:5001")
    dashboard_app.run(port=5001, host="0.0.0.0", debug=False, use_reloader=False)

def main(args):
    threads = []

    
    t_res = threading.Thread(target=monitor, args=(10,), daemon=True)
    threads.append(t_res)
    t_res.start()

    
    t_dash = threading.Thread(target=start_dashboard, daemon=True)
    threads.append(t_dash)
    t_dash.start()

    
    if start_arp_monitor and not args.no_arp:
        t_arp = threading.Thread(target=start_arp_monitor, kwargs={"iface": args.iface}, daemon=True)
        threads.append(t_arp)
        t_arp.start()
    else:
        logger.info("ARP monitor skipped or unavailable")

    
    if start_http_sniffer and not args.no_http:
        t_http = threading.Thread(target=start_http_sniffer, kwargs={"iface": args.iface}, daemon=True)
        threads.append(t_http)
        t_http.start()
    else:
        logger.info("HTTP sniffer skipped or unavailable")

    
    if args.simulate:
        t_sim = threading.Thread(target=run_demo_loop, kwargs={"interval": 3, "iterations": 10}, daemon=True)
        threads.append(t_sim)
        t_sim.start()

    logger.info("All threads started. Main thread sleeping. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", help="Network interface to capture on", default=None)
    parser.add_argument("--no-arp", action="store_true", help="Disable ARP monitor")
    parser.add_argument("--no-http", action="store_true", help="Disable HTTP sniffer")
    parser.add_argument("--simulate", action="store_true", help="Run simulator instead of live capture")
    args = parser.parse_args()
    main(args)
