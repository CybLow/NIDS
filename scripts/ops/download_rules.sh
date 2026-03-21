#!/usr/bin/env bash
# download_rules.sh — Download community IDS rules and threat intel feeds.
#
# Fetches:
#   - Emerging Threats Open (ET Open) ruleset (~40K Suricata/Snort rules)
#   - Abuse.ch threat intel feeds (Feodo, URLhaus, SSL blocklist)
#   - Spamhaus DROP/EDROP
#
# Usage:
#   ./download_rules.sh [--rules-dir DIR] [--feeds-dir DIR] [--all|--rules|--feeds]

set -euo pipefail

RULES_DIR="${RULES_DIR:-data/rules}"
FEEDS_DIR="${FEEDS_DIR:-data/threat_intel}"
ACTION="all"

# Parse arguments.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rules-dir) RULES_DIR="$2"; shift 2 ;;
        --feeds-dir) FEEDS_DIR="$2"; shift 2 ;;
        --rules) ACTION="rules"; shift ;;
        --feeds) ACTION="feeds"; shift ;;
        --all) ACTION="all"; shift ;;
        -h|--help)
            echo "Usage: $0 [--rules-dir DIR] [--feeds-dir DIR] [--all|--rules|--feeds]"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

mkdir -p "$RULES_DIR" "$FEEDS_DIR"

# ── Rule downloads ───────────────────────────────────────────────────

download_et_open() {
    echo "[*] Downloading Emerging Threats Open ruleset..."
    local url="https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules"
    local out="$RULES_DIR/emerging-all.rules"

    if curl -fsSL --connect-timeout 30 --max-time 120 -o "$out.tmp" "$url"; then
        mv "$out.tmp" "$out"
        local count
        count=$(grep -c '^alert\|^drop\|^pass\|^reject' "$out" 2>/dev/null || echo 0)
        echo "    Downloaded $count rules -> $out"
    else
        echo "    [!] Failed to download ET Open rules (non-fatal)"
        rm -f "$out.tmp"
    fi
}

download_etpro_sample() {
    echo "[*] Downloading ET Open category rulesets..."
    local base="https://rules.emergingthreats.net/open/suricata-7.0/rules"
    local categories=(
        "emerging-malware.rules"
        "emerging-exploit.rules"
        "emerging-scan.rules"
        "emerging-dos.rules"
        "emerging-web_server.rules"
        "emerging-sql.rules"
        "emerging-shellcode.rules"
        "emerging-trojan.rules"
    )

    for category in "${categories[@]}"; do
        local out="$RULES_DIR/$category"
        if curl -fsSL --connect-timeout 10 --max-time 30 -o "$out.tmp" "$base/$category" 2>/dev/null; then
            mv "$out.tmp" "$out"
            echo "    $category OK"
        else
            echo "    $category skipped (download failed)"
            rm -f "$out.tmp"
        fi
    done
}

# ── Threat intel feed downloads ──────────────────────────────────────

download_feeds() {
    echo "[*] Downloading threat intelligence feeds..."

    local feeds=(
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt|feodo.txt"
        "https://urlhaus.abuse.ch/downloads/text/|urlhaus.txt"
        "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt|sslbl.txt"
        "https://www.spamhaus.org/drop/drop.txt|spamhaus_drop.txt"
        "https://www.spamhaus.org/drop/edrop.txt|spamhaus_edrop.txt"
        "https://cinsscore.com/list/ci-badguys.txt|cins_score.txt"
        "https://lists.blocklist.de/lists/all.txt|blocklist_de.txt"
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt|emerging_threats.txt"
    )

    for entry in "${feeds[@]}"; do
        local url="${entry%%|*}"
        local file="${entry##*|}"
        local out="$FEEDS_DIR/$file"

        if curl -fsSL --connect-timeout 10 --max-time 30 -o "$out.tmp" "$url" 2>/dev/null; then
            # Strip comments and blank lines, count IPs.
            grep -v '^#\|^$\|^;' "$out.tmp" > "$out" 2>/dev/null || mv "$out.tmp" "$out"
            local count
            count=$(wc -l < "$out" 2>/dev/null || echo 0)
            echo "    $file: $count entries"
            rm -f "$out.tmp"
        else
            echo "    $file: download failed (keeping existing)"
            rm -f "$out.tmp"
        fi
    done
}

# ── Execute ──────────────────────────────────────────────────────────

echo "=== NIDS Rule & Feed Downloader ==="
echo "Rules directory: $RULES_DIR"
echo "Feeds directory: $FEEDS_DIR"
echo ""

case "$ACTION" in
    rules)
        download_et_open
        download_etpro_sample
        ;;
    feeds)
        download_feeds
        ;;
    all)
        download_et_open
        download_etpro_sample
        download_feeds
        ;;
esac

echo ""
echo "=== Download complete ==="
echo "Rules: $(find "$RULES_DIR" -name '*.rules' | wc -l) files"
echo "Feeds: $(find "$FEEDS_DIR" -type f | wc -l) files"
