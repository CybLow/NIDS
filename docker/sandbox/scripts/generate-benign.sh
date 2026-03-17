#!/bin/bash
# Generate benign traffic patterns for NIDS baseline testing.
#
# Usage: ./generate-benign.sh [victim_ip] [duration_seconds]
#
# Traffic patterns:
#   - HTTP GET/POST requests at various rates
#   - SSH connections (key exchange only)
#   - iperf3 bandwidth test (TCP bulk transfer)
#   - ICMP ping (normal rate)
#   - DNS lookups

set -e

VICTIM="${1:-victim}"
DURATION="${2:-60}"
END_TIME=$((SECONDS + DURATION))

echo "[benign] Generating benign traffic to ${VICTIM} for ${DURATION}s..."

# ── HTTP traffic (moderate rate) ────────────────────────────────
echo "[benign] HTTP requests..."
while [ $SECONDS -lt $END_TIME ]; do
    curl -s -o /dev/null "http://${VICTIM}:8080/" 2>/dev/null || true
    curl -s -o /dev/null -X POST -d "user=test&action=login" \
        "http://${VICTIM}:8080/" 2>/dev/null || true
    sleep 0.5
done &

# ── ICMP ping (1 per second, normal) ───────────────────────────
echo "[benign] ICMP ping..."
ping -c "$DURATION" -i 1 "$VICTIM" > /dev/null 2>&1 &

# ── iperf3 bandwidth test (10s burst) ─────────────────────────
echo "[benign] iperf3 TCP test..."
sleep 5
iperf3 -c "$VICTIM" -p 5201 -t 10 > /dev/null 2>&1 &

# ── Netcat connections (periodic TCP connect/disconnect) ───────
echo "[benign] TCP connect/disconnect..."
while [ $SECONDS -lt $END_TIME ]; do
    echo "hello" | nc -w 1 "$VICTIM" 9999 2>/dev/null || true
    sleep 2
done &

wait
echo "[benign] Done."
