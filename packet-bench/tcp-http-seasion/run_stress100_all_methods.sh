#!/usr/bin/env bash
set -euo pipefail

BASE="$(cd "$(dirname "$0")/.." && pwd)"
DURATION="${1:-30}"
WORKERS="${2:-1}"

cd "$BASE"

# Run all HTTP methods benchmark first.
echo "[+] Running all HTTP methods (duration=${DURATION}s workers=${WORKERS})"
echo 'aviavi11' | sudo -S ./run_http_compare_all.sh "$DURATION" "$WORKERS"

# Build stress-100 session report.
python3 "$BASE/tcp-session-stress100/summarize_stress100.py" --suffix "${DURATION}s"

echo "[+] Done. See:"
echo "  - $BASE/results/http_tcp_sessions_stress100.md"
echo "  - $BASE/results/http_tcp_sessions_stress100.csv"
