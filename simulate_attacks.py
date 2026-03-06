import random
from datetime import datetime
import os

LOG_FILE = "logs/log.txt"
ips = ["192.168.1.10", "192.168.1.15", "10.0.0.5", "172.16.0.8", "10.0.0.20"]
common_ports = [21, 22, 23, 80, 443, 445, 3306, 8080]

def generate_log_line():
    ip = random.choice(ips)
    attack_type = random.choice(["SSH", "WebLogin", "FTP", "PortScan"])
    timestamp = datetime.now().strftime('%b %d %H:%M:%S')

    if attack_type == "SSH":
        return f"{timestamp} Failed password for root from {ip}\n"
    elif attack_type == "WebLogin":
        return f"{timestamp} login failed for admin from {ip}\n"
    elif attack_type == "FTP":
        return f"{timestamp} Authentication failed for ftp_user from {ip}\n"
    elif attack_type == "PortScan":
        port = random.choice(common_ports)
        return f"{timestamp} Connection attempt on port {port} from {ip}\n"

def simulate_attacks(n=10): 
    if not os.path.exists("logs"):
        os.makedirs("logs")
    with open(LOG_FILE, "a") as f:
        for _ in range(n):
            f.write(generate_log_line())

if __name__ == "__main__":
    simulate_attacks(100)
    print(f"STATUS : Generation de logs hybrides terminee dans {LOG_FILE}")
