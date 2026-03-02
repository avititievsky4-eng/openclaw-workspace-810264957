#!/usr/bin/env bash
set -euo pipefail

DURATION="${1:-5}"
PAYLOAD="${2:-64}"
PORT=9999
BASE="$(dirname "$0")"
OUTDIR="$BASE/results"
mkdir -p "$OUTDIR"

run_json () {
  local name="$1"
  shift
  local out="$OUTDIR/${name}_${DURATION}s.json"
  echo "[+] Running $name benchmark..."
  echo 'aviavi11' | sudo -S "$@" > "$out"
  echo "$out"
}

SCAPY_JSON=$(run_json scapy "$BASE/scapy_project/.venv312/bin/python" "$BASE/scapy_project/benchmark_scapy.py" --duration "$DURATION" --payload "$PAYLOAD" --port "$PORT")
LIBPCAP_JSON=$(run_json libpcap "$BASE/libpcap_project/.venv312/bin/python" "$BASE/libpcap_project/benchmark_libpcap.py" --duration "$DURATION" --payload "$PAYLOAD" --port "$PORT")
TCPDUMP_JSON=$(run_json tcpdump python3 "$BASE/tcpdump_project/benchmark_tcpdump.py" --duration "$DURATION" --payload "$PAYLOAD" --port "$PORT")
RAWSOCK_JSON=$(run_json rawsocket python3 "$BASE/rawsocket_project/benchmark_rawsocket.py" --duration "$DURATION" --payload "$PAYLOAD" --port "$PORT")

python3 - <<'PY'
import glob, json, os
files = sorted(glob.glob('packet-bench/results/*_5s.json'))
# if different duration passed, just pick newest per tool
by_tool = {}
for p in glob.glob('packet-bench/results/*.json'):
    try:
        j = json.load(open(p))
        by_tool[j['tool']] = (p,j)
    except Exception:
        pass
rows = [v[1] for v in by_tool.values()]
rows.sort(key=lambda r: r['captured'], reverse=True)
print('\n=== RESULTS (all methods) ===')
for r in rows:
    print(f"{r['tool']}: captured={r['captured']:,} sent={r['sent']:,} ratio={r['capture_ratio']:.2%} captured_pps={r['captured_pps']:.0f}")
if rows:
    print('\nWinner by captured packets:', rows[0]['tool'])
PY

echo "\nSaved JSON results in: $OUTDIR"
