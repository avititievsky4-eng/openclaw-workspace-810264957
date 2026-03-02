#!/usr/bin/env bash
set -euo pipefail

DURATION="${1:-3}"
PAYLOAD="${2:-64}"
BASE="$(dirname "$0")"
OUTDIR="$BASE/results"
mkdir -p "$OUTDIR"

run_json () {
  local name="$1"
  shift
  local out="$OUTDIR/sctp_${name}_${DURATION}s.json"
  echo "[+] Running $name SCTP benchmark..." >&2
  echo 'aviavi11' | sudo -S "$@" > "$out"
  echo "$out"
}

SCAPY_JSON=$(run_json scapy "$BASE/scapy_project/.venv312/bin/python" "$BASE/sctp_bench/benchmark_sctp_scapy.py" --duration "$DURATION" --payload "$PAYLOAD")
TCPDUMP_JSON=$(run_json tcpdump python3 "$BASE/sctp_bench/benchmark_sctp_tcpdump.py" --duration "$DURATION" --payload "$PAYLOAD")
LIBPCAP_JSON=$(run_json libpcap "$BASE/libpcap_project/.venv312/bin/python" "$BASE/sctp_bench/benchmark_sctp_libpcap.py" --duration "$DURATION" --payload "$PAYLOAD")
PYPCAP_JSON=$(run_json pypcap "$BASE/pypcap_project/.venv311/bin/python" "$BASE/sctp_bench/benchmark_sctp_pypcap.py" --duration "$DURATION" --payload "$PAYLOAD")
RAWSOCK_JSON=$(run_json rawsocket python3 "$BASE/sctp_bench/benchmark_sctp_rawsocket.py" --duration "$DURATION" --payload "$PAYLOAD")
EBPF_JSON=$(run_json ebpf /usr/bin/python3 "$BASE/sctp_bench/benchmark_sctp_ebpf.py" --duration "$DURATION" --payload "$PAYLOAD")

SCAPY_JSON="$SCAPY_JSON" TCPDUMP_JSON="$TCPDUMP_JSON" LIBPCAP_JSON="$LIBPCAP_JSON" PYPCAP_JSON="$PYPCAP_JSON" RAWSOCK_JSON="$RAWSOCK_JSON" EBPF_JSON="$EBPF_JSON" python3 - <<'PY'
import json, os
files=[os.environ['SCAPY_JSON'], os.environ['TCPDUMP_JSON'], os.environ['LIBPCAP_JSON'], os.environ['PYPCAP_JSON'], os.environ['RAWSOCK_JSON'], os.environ['EBPF_JSON']]
rows=[json.load(open(p)) for p in files]
for r in rows:
    r['_score'] = r.get('capture_ratio_normalized', r['capture_ratio'])
rows.sort(key=lambda r:r['_score'], reverse=True)
print('\n=== SCTP capture results ===')
for r in rows:
    if 'captured_normalized' in r:
        print(f"{r['tool']}: sent={r['sent']:,} captured={r['captured']:,} normalized={r['captured_normalized']:,} ratio={r['capture_ratio']:.2%} normalized_ratio={r['capture_ratio_normalized']:.2%}")
    else:
        print(f"{r['tool']}: sent={r['sent']:,} captured={r['captured']:,} ratio={r['capture_ratio']:.2%}")
top = rows[0]['_score'] if rows else 0
winners = [r['tool'] for r in rows if abs(r['_score'] - top) < 1e-12]
print('\nWinner(s):', ', '.join(winners))
PY

echo "\nSaved JSON in: $OUTDIR"
