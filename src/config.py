#!/usr/bin/python3

# Network Configuration

#Target
X_TERMINAL_IP = "10.9.0.5"
X_TERMINAL_PORT = 514      # Standard port for RSH (Shell) service

#Trusted Server
TRUSTED_SERVER_IP = "10.9.0.6"
TRUSTED_SERVER_PORT = 1023 # Must be this port for RSH to accept it

#The Attacker
ATTACKER_IP = "10.9.0.1"



# Interface Configuration
IFACE = "br-2b6f9583e546"
