import scapy.all as scapy
import socket
import ipaddress
import requests
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_ip(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        answered_list = scapy.srp(broadcast / arp_request, timeout=1, verbose=False)[0]

        devices = [{'ip': element[1].psrc, 'mac': element[1].hwsrc} for element in answered_list]
        
        if not devices:
            response = subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL)
            if response.returncode == 0:
                devices.append({'ip': ip, 'mac': 'Unknown'})

        return devices
    except Exception:
        return []

def check_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1) 
            return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False

def scan_ports(ip, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_port, ip, port): port for port in ports}
        for future in as_completed(futures):
            if future.result():
                open_ports.append(futures[future])
    return open_ports

def check_vulnerabilities(open_ports):
    known_vulnerabilities = {
        22: "SSH may be vulnerable to brute-force attacks. Use key-based authentication.",
        80: "HTTP may be vulnerable to XSS, SQL injection. Secure your web apps.",
        443: "HTTPS may have SSL/TLS vulnerabilities. Use updated certificates.",
        21: "FTP may be vulnerable to brute-force attacks. Use FTPS/SFTP.",
        25: "SMTP may allow spamming. Secure your mail server.",
        3306: "MySQL may be vulnerable. Ensure strong passwords.",
        3389: "RDP may be vulnerable to brute-force attacks. Use network-level authentication."
    }
    return [known_vulnerabilities[port] for port in open_ports if port in known_vulnerabilities]

def scan_network(ip_range, ports):
    results = {}
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_ip, ip): ip for ip in ip_range}
        for future in as_completed(futures):
            devices = future.result()
            if devices:
                for device in devices:
                    ip = device['ip']
                    open_ports = scan_ports(ip, ports)
                    results[ip] = {
                        'open_ports': open_ports,
                        'vulnerabilities': check_vulnerabilities(open_ports)
                    }

    return results

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def check_for_update():
    repo_url = "https://raw.githubusercontent.com/your-username/your-repository/main/version.txt"
    try:
        response = requests.get(repo_url, timeout=2)
        if response.status_code == 200:
            with open("version.txt", "r") as file:
                current_version = file.read().strip()
            latest_version = response.text.strip()

            if current_version != latest_version:
                print("🔔 A new version is available.")
                if input("Update? (yes/no): ").strip().lower() == 'yes':
                    os.system("git pull origin main")
                    print("✅ Updated successfully.")
                    exit()
                else:
                    print("⚠ Using current version.")
    except requests.RequestException:
        print("⚠ Unable to check for updates.")

def main():
    check_for_update()

    user_input = input("Enter IP (e.g., 192.168.1.1 or 192.168.1.1-192.168.1.254): ")
    ports = [22, 80, 443, 21, 25, 3306, 3389] 

    if '-' in user_input:
        start_ip, end_ip = user_input.split('-')
        if not (validate_ip(start_ip) and validate_ip(end_ip)):
            print("❌ Invalid IP range.")
            return
        ip_range = [str(ip) for ip in range(int(ipaddress.IPv4Address(start_ip)), int(ipaddress.IPv4Address(end_ip)) + 1)]
    else:
        if not validate_ip(user_input):
            print("❌ Invalid IP.")
            return
        ip_range = [user_input]

    print("\n🔍 Scanning...\n")

    results = scan_network(ip_range, ports)

    if not results:
        print("⚠ No active devices found.")
        return

    for ip, details in results.items():
        if not details['open_ports']:
            print(f"\n📌 IP: {ip} (No open ports)")
        else:
            print(f"\n📌 IP: {ip}")
            print(f"   🔓 Open Ports: {details['open_ports']}")
            if details['vulnerabilities']:
                print("   ⚠ Vulnerabilities:")
                for v in details['vulnerabilities']:
                    print(f"     - {v}")
            else:
                print("   ✅ No known vulnerabilities.")

if __name__ == "__main__":
    main()
