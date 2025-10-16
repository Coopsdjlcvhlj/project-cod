
import os, time, uuid, zipfile
from config import UPLOAD_DIR
from utils import sha256_file
from logger_setup import logger

def try_extract_and_save_file(raw_bytes, host, uri, src_ip):

    name = f"{int(time.time())}_{uuid.uuid4().hex[:8]}"
    path = os.path.join(UPLOAD_DIR, name)
    with open(path, "wb") as f:
        f.write(raw_bytes)
    h = sha256_file(path)
    logger.info("Saved HTTP resource", extra={"extra":{"src": src_ip, "host": host, "uri": uri, "path": path, "sha256": h}})

    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, 'r') as z:
                dest = os.path.join(UPLOAD_DIR, f"{name}_extracted")
                os.makedirs(dest, exist_ok=True)
                z.extractall(dest)
                logger.info("Unzipped file", extra={"extra":{"path": path, "extracted_to": dest}})
    except Exception as e:
        logger.exception("Error while extracting zip: %s" % e)
