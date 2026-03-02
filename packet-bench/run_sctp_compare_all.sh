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

TCPDUMP_JSON=$(run_json tcpdump python3 "$BASE/sctp_bench/benchmark_sctp_tcpdump.py" --duration "$DURATION" --payload "$PAYLOAD")
LIBPCAP_JSON=$(run_json libpcap "$BASE/libpcap_project/.venv312/bin/python" "$BASE/sctp_bench/benchmark_sctp_libpcap.py" --duration "$DURATION" --payload "$PAYLOAD")
RAWSOCK_JSON=$(run_json rawsocket python3 "$BASE/sctp_bench/benchmark_sctp_rawsocket.py" --duration "$DURATION" --payload "$PAYLOAD")

TCPDUMP_JSON="$TCPDUMP_JSON" LIBPCAP_JSON="$LIBPCAP_JSON" RAWSOCK_JSON="$RAWSOCK_JSON" python3 - <<'PY'
import json, os
files=[os.environ['TCPDUMP_JSON'], os.environ['LIBPCAP_JSON'], os.environ['RAWSOCK_JSON']]
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
print('\nWinner:', rows[0]['tool'])
PY

echo "\nSaved JSON in: $OUTDIR"
