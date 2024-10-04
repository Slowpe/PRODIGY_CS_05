from scapy.layers.inet import IP, TCP, UDP
from scapy.all import sniff

def packet_sniffer(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if packet.haslayer(TCP):
            proto = "TCP"
            payload = packet[TCP].payload
        elif packet.haslayer(UDP):
            proto = "UDP"
            payload = packet[UDP].payload
        else:
            proto = packet[IP].proto
            payload = None

        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst} | Protocol: {proto}")
        if payload:
            print(f"Payload: {payload}\n")

def start_sniffer(interface):
    print(f"Starting packet sniffer on interface: {interface}.......")
    sniff(iface=interface, prn=packet_sniffer, store=False)

if __name__ == "__main__":
    interface = "Wi-Fi"
    start_sniffer(interface)
