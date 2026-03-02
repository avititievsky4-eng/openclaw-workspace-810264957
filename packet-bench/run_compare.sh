#!/usr/bin/env bash
set -euo pipefail

DURATION="${1:-5}"
PAYLOAD="${2:-64}"
PORT=9999
OUTDIR="$(dirname "$0")/results"
mkdir -p "$OUTDIR"

SCAPY_JSON="$OUTDIR/scapy_${DURATION}s.json"
PCAP_JSON="$OUTDIR/libpcap_${DURATION}s.json"

echo "[+] Running Scapy benchmark..."
echo 'aviavi11' | sudo -S "$(dirname "$0")/scapy_project/.venv312/bin/python" "$(dirname "$0")/scapy_project/benchmark_scapy.py" \
  --duration "$DURATION" --payload "$PAYLOAD" --port "$PORT" > "$SCAPY_JSON"

echo "[+] Running libpcap benchmark..."
echo 'aviavi11' | sudo -S "$(dirname "$0")/libpcap_project/.venv312/bin/python" "$(dirname "$0")/libpcap_project/benchmark_libpcap.py" \
  --duration "$DURATION" --payload "$PAYLOAD" --port "$PORT" > "$PCAP_JSON"

python3 - <<'PY'
import json
from pathlib import Path
out = Path('packet-bench/results')
s = json.loads((out / sorted([p.name for p in out.glob('scapy_*.json')])[-1]).read_text())
p = json.loads((out / sorted([p.name for p in out.glob('libpcap_*.json')])[-1]).read_text())
print('\n=== RESULTS ===')
for r in [s,p]:
    print(f"{r['tool']}: captured={r['captured']:,} sent={r['sent']:,} ratio={r['capture_ratio']:.2%} captured_pps={r['captured_pps']:.0f}")
print('\nWinner by captured packets:', s['tool'] if s['captured']>p['captured'] else p['tool'])
PY

echo "\nSaved JSON results to:"
echo "  $SCAPY_JSON"
echo "  $PCAP_JSON"
