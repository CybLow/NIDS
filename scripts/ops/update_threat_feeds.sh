#!/usr/bin/env bash
# update_threat_feeds.sh -- Download latest threat intelligence feeds.
#
# Downloads plain-text IP blocklists from free, reputable sources into
# the data/threat_intel/ directory. These feeds are loaded by the NIDS
# ThreatIntelProvider at startup.
#
# Usage:
#   ./scripts/ops/update_threat_feeds.sh [output_dir]
#
# Default output directory: data/threat_intel/ (relative to project root)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${1:-${PROJECT_ROOT}/data/threat_intel}"

mkdir -p "$OUTPUT_DIR"

echo "=== NIDS Threat Intelligence Feed Updater ==="
echo "Output directory: $OUTPUT_DIR"
echo ""

# Track success/failure
SUCCESS=0
FAILED=0

download_feed() {
    local name="$1"
    local url="$2"
    local output="${OUTPUT_DIR}/${name}.txt"

    echo -n "  Downloading ${name}... "
    if curl -sS --fail --max-time 30 -o "$output" "$url" 2>/dev/null; then
        local lines
        lines=$(grep -cvE '^\s*(#|;|$)' "$output" 2>/dev/null || echo 0)
        echo "OK (${lines} entries)"
        SUCCESS=$((SUCCESS + 1))
    else
        echo "FAILED"
        rm -f "$output"
        FAILED=$((FAILED + 1))
    fi
}

echo "Downloading feeds:"
echo ""

# 1. abuse.ch Feodo Tracker -- C2 botnet IPs (recommended blocklist)
download_feed "feodo" \
    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"

# 2. Spamhaus DROP -- Known bad CIDR ranges (Don't Route Or Peer)
download_feed "spamhaus_drop" \
    "https://www.spamhaus.org/drop/drop.txt"

# 3. Spamhaus EDROP -- Extended DROP list
download_feed "spamhaus_edrop" \
    "https://www.spamhaus.org/drop/edrop.txt"

# 4. Emerging Threats -- Compromised IPs
download_feed "emerging_threats" \
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

# 5. CINS Score -- Bad actor IPs
download_feed "cins_score" \
    "https://cinsscore.com/list/ci-badguys.txt"

# 6. Blocklist.de -- Fail2ban reported IPs (all categories)
download_feed "blocklist_de" \
    "https://lists.blocklist.de/lists/all.txt"

echo ""
echo "=== Summary ==="
echo "  Successful: $SUCCESS"
echo "  Failed:     $FAILED"
echo "  Output:     $OUTPUT_DIR/"
echo ""

if [ "$FAILED" -gt 0 ]; then
    echo "WARNING: Some feeds failed to download. This is normal if the"
    echo "server is temporarily unavailable. Retry later."
    exit 1
fi

echo "All feeds updated successfully."
