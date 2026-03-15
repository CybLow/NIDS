#!/bin/bash
# Victim startup script — launches lightweight services for NIDS testing.
set -e

echo "[victim] Starting services..."

# SSH server (dropbear, lightweight)
echo "[victim] Starting SSH on port 22..."
dropbear -R -F -E -p 22 &

# Python HTTP server
echo "[victim] Starting HTTP on port 8080..."
python3 -m http.server 8080 --directory /var/www &

# iperf3 server for bandwidth tests
echo "[victim] Starting iperf3 on port 5201..."
iperf3 -s -p 5201 &

# Netcat listener for raw TCP tests
echo "[victim] Starting netcat on port 9999..."
while true; do
    echo "NIDS test target" | nc -l -p 9999 -q 1 2>/dev/null || true
    sleep 0.1
done &

echo "[victim] All services running."
echo "[victim] IP address: $(hostname -I | awk '{print $1}')"

# Keep container alive
wait
