import os

def tail(filename, n=20):
    try:
        with open(filename, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 1024
            data = b""
            while size > 0 and data.count(b"\n") < n:
                read_size = min(block, size)
                f.seek(size - read_size)
                data = f.read(read_size) + data
                size -= read_size
            return data.decode(errors="ignore").splitlines()[-n:]
    except Exception:
        return []

def detect_suspicious_activity(output_dir, last_alerts):
    arp_log = f"{output_dir}/arp_log.txt"
    if os.path.exists(arp_log):
        lines = tail(arp_log, 10)
        for line in lines:
            if "claims to be" in line and line != last_alerts.get('arp', ''):
                print("[!] Виявлено можливий ARP-спуфінг!")
                last_alerts['arp'] = line
                break
    http_log = f"{output_dir}/http_log.txt"
    if os.path.exists(http_log):
        lines = tail(http_log, 10)
        for line in lines:
            if "password=" in line and line != last_alerts.get('http', ''):
                print("[!] Виявлено передачу паролів через HTTP!")
                last_alerts['http'] = line
                break
    cred_log = f"{output_dir}/http_credentials.txt"
    if os.path.exists(cred_log):
        lines = tail(cred_log, 5)
        for line in lines:
            if line.strip() and line != last_alerts.get('cred', ''):
                print("[!] Виявлено можливі логіни/паролі у HTTP-трафіку!")
                last_alerts['cred'] = line
                break
