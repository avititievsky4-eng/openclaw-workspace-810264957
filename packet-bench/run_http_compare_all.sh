#!/usr/bin/env bash
set -euo pipefail

DURATION="${1:-8}"
WORKERS="${2:-4}"
PORT=18080
BASE="$(dirname "$0")"
OUTDIR="$BASE/results"
mkdir -p "$OUTDIR"

run_json () {
  local name="$1"
  shift
  local out="$OUTDIR/http_${name}_${DURATION}s.json"
  echo "[+] Running $name HTTP-session benchmark..." >&2
  echo 'aviavi11' | sudo -S "$@" > "$out"
  echo "$out"
}

SCAPY_JSON=$(run_json scapy "$BASE/scapy_project/.venv312/bin/python" "$BASE/http_bench/benchmark_http_scapy.py" --duration "$DURATION" --workers "$WORKERS" --port "$PORT")
LIBPCAP_JSON=$(run_json libpcap "$BASE/libpcap_project/.venv312/bin/python" "$BASE/http_bench/benchmark_http_libpcap.py" --duration "$DURATION" --workers "$WORKERS" --port "$PORT")
TCPDUMP_JSON=$(run_json tcpdump python3 "$BASE/http_bench/benchmark_http_tcpdump.py" --duration "$DURATION" --workers "$WORKERS" --port "$PORT")
RAWSOCK_JSON=$(run_json rawsocket python3 "$BASE/http_bench/benchmark_http_rawsocket.py" --duration "$DURATION" --workers "$WORKERS" --port "$PORT")
RAWSOCK_TP_JSON=$(run_json rawsocket_tpacketv3 python3 "$BASE/http_bench/benchmark_http_rawsocket_tpacketv3.py" --duration "$DURATION" --workers "$WORKERS" --port "$PORT")
PYPCAP_JSON=$(run_json pypcap "$BASE/pypcap_project/.venv311/bin/python" "$BASE/http_bench/benchmark_http_pypcap.py" --duration "$DURATION" --workers "$WORKERS" --port "$PORT")
DPKT_JSON=$(run_json dpkt "$BASE/pypcap_project/.venv311/bin/python" "$BASE/http_bench/benchmark_http_dpkt.py" --duration "$DURATION" --workers "$WORKERS" --port "$PORT")
EBPF_JSON=$(run_json ebpf /usr/bin/python3 "$BASE/http_bench/benchmark_http_ebpf.py" --duration "$DURATION" --workers "$WORKERS" --port "$PORT")
TSHARK_JSON=$(run_json tshark python3 "$BASE/http_bench/benchmark_http_tshark.py" --duration "$DURATION" --workers "$WORKERS" --port "$PORT")
SURI_JSON=$(run_json suricata python3 "$BASE/http_bench/benchmark_http_suricata.py" --duration "$DURATION" --workers "$WORKERS" --port "$PORT")
NETSNIFF_JSON=$(run_json netsniff python3 "$BASE/http_bench/benchmark_http_netsniff.py" --duration "$DURATION" --workers "$WORKERS" --port "$PORT")

SCAPY_JSON="$SCAPY_JSON" LIBPCAP_JSON="$LIBPCAP_JSON" TCPDUMP_JSON="$TCPDUMP_JSON" RAWSOCK_JSON="$RAWSOCK_JSON" RAWSOCK_TP_JSON="$RAWSOCK_TP_JSON" PYPCAP_JSON="$PYPCAP_JSON" DPKT_JSON="$DPKT_JSON" EBPF_JSON="$EBPF_JSON" TSHARK_JSON="$TSHARK_JSON" SURI_JSON="$SURI_JSON" NETSNIFF_JSON="$NETSNIFF_JSON" python3 - <<'PY'
import json, os
files=[os.environ['SCAPY_JSON'],os.environ['LIBPCAP_JSON'],os.environ['TCPDUMP_JSON'],os.environ['RAWSOCK_JSON'],os.environ['RAWSOCK_TP_JSON'],os.environ['PYPCAP_JSON'],os.environ['DPKT_JSON'],os.environ['EBPF_JSON'],os.environ['TSHARK_JSON'],os.environ['SURI_JSON'],os.environ['NETSNIFF_JSON']]
rows=[json.load(open(p)) for p in files]
rows_l7=[r for r in rows if 'http_get_seen' in r]
rows_l7.sort(key=lambda r:r['http_get_seen'], reverse=True)
print('\n=== HTTP session parse results (L7 where available) ===')
for r in rows:
    if 'http_get_seen' in r:
        print(f"{r['tool']}: req_ok={r['requests_ok']:,} GET_seen={r['http_get_seen']:,} 200_seen={r['http_200_seen']:,} GET_ratio={r['get_seen_ratio']:.2%}")
    else:
        print(f"{r['tool']}: req_ok={r['requests_ok']:,} sessions={r['http_sessions_established']:,} ratio={r['session_to_request_ratio']:.2%}")
if rows_l7:
    print('\nWinner by HTTP GET parsed:', rows_l7[0]['tool'])
PY

echo "\nSaved JSON results in: $OUTDIR"
