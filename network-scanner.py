import scapy.all as scapy
import socket
from concurrent.futures import ThreadPoolExecutor
import threading

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
    # Placeholder function for vulnerability checks.
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

def main():
    ip_prefix = "192.168.1."
    ip_range = [f"{ip_prefix}{i}" for i in range(1, 255)]
    ports = [22, 80, 443, 8080]

    print("Starting network scan...")
    results = scan_network(ip_range, ports)

    for ip, details in results.items():
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
