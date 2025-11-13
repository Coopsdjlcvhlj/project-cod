import sys
import platform

if platform.system() != "Windows":
    print("Цей скрипт призначений для запуску на Windows.")
else:
    print("На Windows немає підтримки інструментів aircrack-ng через Python.")
    print("Використовуйте Kali Linux або іншу Linux-систему для роботи з Wi-Fi моніторингом та зламом.")
    sys.exit(1)