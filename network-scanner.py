import scapy.all as scapy
import socket
from concurrent.futures import ThreadPoolExecutor
import threading
import ipaddress
import requests
import os

lock = threading.Lock()

def scan_ip(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        devices = [{'ip': element[1].psrc, 'mac': element[1].hwsrc} for element in answered_list]
        return devices
    except Exception:
        return []

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            if sock.connect_ex((ip, port)) == 0:
                return port
    except Exception:
        return None

def scan_ports(ip, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)
    return open_ports

def check_vulnerabilities(open_ports):
    vulnerabilities = {
        22: "SSH may be vulnerable to brute-force attacks. Use strong authentication.",
        80: "HTTP may be vulnerable to XSS, SQL injection. Secure web applications.",
        443: "HTTPS may have SSL/TLS vulnerabilities. Use updated certificates.",
        21: "FTP may be insecure. Prefer SFTP or FTPS.",
        25: "SMTP can be exploited for spamming. Secure mail servers.",
        3306: "MySQL may be vulnerable to unauthorized access. Enforce strong security.",
        3389: "RDP may be vulnerable to brute-force attacks. Use network-level authentication."
    }
    return [vulnerabilities[port] for port in open_ports if port in vulnerabilities]

def scan_network(ip_range, ports):
    devices = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_ip, ip) for ip in ip_range]
        for future in futures:
            devices.extend(future.result())
    
    results = {}
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
    url = "https://raw.githubusercontent.com/kar-ik/network-scanner/main/version.txt"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        latest_version = response.text.strip()

        if os.path.exists("version.txt"):
            with open("version.txt", "r") as file:
                current_version = file.read().strip()
        else:
            current_version = "0.0.0"

        if current_version != latest_version:
            print("A new version of the tool is available.")
            choice = input("Do you want to update the tool? (yes/no): ").strip().lower()
            if choice == 'yes':
                update_tool()
            else:
                print("Continuing with the current version.")
    except requests.RequestException:
        print("Failed to check for updates. Please check your internet connection.")

def update_tool():
    print("Updating the tool...")
    os.system("git pull origin main")  
    print("Update complete. Restarting...")
    os.execv(__file__, ['python'] + os.sys.argv)

def main():
    check_for_update()
    user_input = input("Enter IP address or IP range (e.g., 192.168.1.1 or 192.168.1.1-192.168.1.254): ")
    ports = [22, 80, 443, 21, 25, 3306, 3389]  

    if '-' in user_input:
        start_ip, end_ip = user_input.split('-')
        if not (validate_ip(start_ip) and validate_ip(end_ip)):
            print("Invalid IP range. Please enter a valid IP address or range.")
            return
        
        start_ip = ipaddress.IPv4Address(start_ip)
        end_ip = ipaddress.IPv4Address(end_ip)
        ip_range = [str(ip) for ip in range(int(start_ip), int(end_ip) + 1)]
    else:
        if not validate_ip(user_input):
            print("Invalid IP address. Please enter a valid IP address.")
            return
        ip_range = [user_input]

    print("Starting network scan...")
    results = scan_network(ip_range, ports)

    if not results:
        print("No active devices found in the specified range.")
        return

    for ip, details in results.items():
        if not details['open_ports']:
            print(f"\nIP Address: {ip} is not connected or has no open ports.")
        else:
            print(f"\nIP Address: {ip}")
            print(f"Open Ports: {details['open_ports']}")
            if details['vulnerabilities']:
                print("Vulnerabilities:")
                for vulnerability in details['vulnerabilities']:
                    print(f"  - {vulnerability}")
            else:
                print("No known vulnerabilities detected.")

if __name__ == "__main__":
    main()
