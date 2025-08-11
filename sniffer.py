from scapy.all import sniff

def process_packet(packet):
    if packet.haslayer("IP"): 
        ip_layer = packet["IP"]
        print(f"[+] Source: {ip_layer.src} --> Destination: {ip_layer.dst}")
        print(f"    Protocol: {ip_layer.proto}")
        
        if packet.haslayer("Raw"):
            print(f"    Payload: {packet['Raw'].load[:50]}") 
        print("-" * 50)

print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)  
