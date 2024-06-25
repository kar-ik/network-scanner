from scapy.all import sniff
import pandas as pd
from datetime import datetime

# Define a list to store packet data
packets_data = []

def process_packet(packet):
    packet_time = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
    src_ip = packet[0][1].src
    dst_ip = packet[0][1].dst
    protocol = packet[0][1].proto

    packet_info = {
        'Time': packet_time,
        'Source IP': src_ip,
        'Destination IP': dst_ip,
        'Protocol': protocol
    }
    packets_data.append(packet_info)

def start_sniffing(interface):
    sniff(iface=interface, prn=process_packet, store=False)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Network Traffic Monitoring Tool")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to monitor")
    parser.add_argument("-o", "--output", default="network_traffic.csv", help="Output CSV file")

    args = parser.parse_args()
    
    print(f"Starting network traffic monitoring on interface {args.interface}...")
    try:
        start_sniffing(args.interface)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
        if packets_data:
            df = pd.DataFrame(packets_data)
            df.to_csv(args.output, index=False)
            print(f"Captured packets saved to {args.output}")
        else:
            print("No packets captured.")
