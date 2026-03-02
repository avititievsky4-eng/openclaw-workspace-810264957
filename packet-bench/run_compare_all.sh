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
  echo "[+] Running $name benchmark..." >&2
  echo 'aviavi11' | sudo -S "$@" > "$out"
  echo "$out"
}

SCAPY_JSON=$(run_json scapy "$BASE/scapy_project/.venv312/bin/python" "$BASE/scapy_project/benchmark_scapy.py" --duration "$DURATION" --payload "$PAYLOAD" --port "$PORT")
LIBPCAP_JSON=$(run_json libpcap "$BASE/libpcap_project/.venv312/bin/python" "$BASE/libpcap_project/benchmark_libpcap.py" --duration "$DURATION" --payload "$PAYLOAD" --port "$PORT")
TCPDUMP_JSON=$(run_json tcpdump python3 "$BASE/tcpdump_project/benchmark_tcpdump.py" --duration "$DURATION" --payload "$PAYLOAD" --port "$PORT")
RAWSOCK_JSON=$(run_json rawsocket python3 "$BASE/rawsocket_project/benchmark_rawsocket.py" --duration "$DURATION" --payload "$PAYLOAD" --port "$PORT")
EBPF_JSON=$(run_json ebpf python3 "$BASE/ebpf_project/benchmark_ebpf.py" --duration "$DURATION" --payload "$PAYLOAD" --port "$PORT")

SCAPY_JSON="$SCAPY_JSON" LIBPCAP_JSON="$LIBPCAP_JSON" TCPDUMP_JSON="$TCPDUMP_JSON" RAWSOCK_JSON="$RAWSOCK_JSON" EBPF_JSON="$EBPF_JSON" python3 - <<'PY'
import json, os
files = [os.environ['SCAPY_JSON'], os.environ['LIBPCAP_JSON'], os.environ['TCPDUMP_JSON'], os.environ['RAWSOCK_JSON'], os.environ['EBPF_JSON']]
rows = []
for p in files:
    rows.append(json.load(open(p)))
rows.sort(key=lambda r: r['captured'], reverse=True)
print('\n=== RESULTS (all methods) ===')
for r in rows:
    print(f"{r['tool']}: captured={r['captured']:,} sent={r['sent']:,} ratio={r['capture_ratio']:.2%} captured_pps={r['captured_pps']:.0f}")
print('\nWinner by captured packets:', rows[0]['tool'])
PY

echo "\nSaved JSON results in: $OUTDIR"
