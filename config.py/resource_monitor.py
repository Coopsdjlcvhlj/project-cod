
import psutil, time
from logger_setup import logger

def monitor(interval=10):
    logger.info("Resource monitor started", extra={"extra":{"interval": interval}})
    while True:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        logger.info("Resource metrics", extra={"extra":{"cpu": cpu, "mem": mem, "disk": disk}})
       
        if cpu > 90 or mem > 90 or disk > 90:
            logger.warning("Resource usage high", extra={"extra":{"cpu": cpu, "mem": mem, "disk": disk}})
        time.sleep(interval)
