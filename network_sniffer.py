from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    
    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print("\n----------------------------")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        if packet.haslayer(TCP):
            print("Protocol       : TCP")
        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
        else:
            print("Protocol       : Other")

        if packet.haslayer(TCP):
            print("Transport Layer: TCP")

        elif packet.haslayer(UDP):
            print("Transport Layer: UDP")

        print("----------------------------")

print("Starting Network Sniffer...")
print("Press CTRL + C to stop.\n")

sniff(prn=packet_callback, store=False)