from scapy.all import sniff, ARP
from datetime import datetime
import os

def arp_monitor(output_dir):
    def arp_callback(packet):
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            msg = f"{packet[ARP].psrc} claims to be {packet[ARP].hwsrc}"
            print(f"[!] ARP-відповідь: {packet[ARP].psrc} -> {packet[ARP].pdst}")
            with open(f"{output_dir}/arp_log.txt", "a") as f:
                f.write(f"{datetime.now()}: {msg}\n")
    print("[*] Запуск ARP-монітора...")
    sniff(filter="arp", prn=arp_callback, store=0)

if __name__ == "__main__":
    OUTPUT_DIR = "security_logs"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    arp_monitor(OUTPUT_DIR)
