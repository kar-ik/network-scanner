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
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        devices = []
        for element in answered_list:
            devices.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})
        return devices
    except Exception as e:
        return []

def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def check_vulnerabilities(ip, open_ports):
    vulnerabilities = []
    for port in open_ports:
        if port == 22:
            vulnerabilities.append('SSH may be vulnerable to brute-force attacks.')
        elif port == 80:
            vulnerabilities.append('HTTP may be vulnerable to attacks if not properly secured.')
    return vulnerabilities

def scan_network(ip_range, ports):
    devices = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_ip, ip) for ip in ip_range]
        for future in futures:
            devices.extend(future.result())

    results = {}
    for device in devices:
        ip = device['ip']
        open_ports = scan_ports(ip, ports)
        vulnerabilities = check_vulnerabilities(ip, open_ports)
        results[ip] = {'open_ports': open_ports, 'vulnerabilities': vulnerabilities}

    return results

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def check_for_update():
    url = "https://raw.githubusercontent.com/your-username/your-repository/main/version.txt"
    response = requests.get(url)
    
    if response.status_code == 200:
        with open("version.txt", "r") as file:
            current_version = file.read().strip()
        latest_version = response.text.strip()
        
        if current_version != latest_version:
            print("A new version of the tool is available.")
            choice = input("Do you want to update the tool? (yes/no): ").strip().lower()
            if choice == 'yes':
                os.system("python update_tool.py")
                exit()
            else:
                print("Continuing with the current version.")
    else:
        print("Failed to check for updates. Please check your internet connection.")

def main():
    check_for_update()
    
    user_input = input("Enter IP address or IP range (e.g., 192.168.1.1 or 192.168.1.1-192.168.1.254): ")
    ports = [22, 80, 443, 8080]

    if '-' in user_input:
        start_ip, end_ip = user_input.split('-')
        if not (validate_ip(start_ip) and validate_ip(end_ip)):
            print("Invalid IP range. Please enter a valid IP address or range.")
            return

        start_ip = ipaddress.IPv4Address(start_ip)
        end_ip = ipaddress.IPv4Address(end_ip)
        ip_range = [str(ip) for ip in ipaddress.summarize_address_range(start_ip, end_ip)]
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
