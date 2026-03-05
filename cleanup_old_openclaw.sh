#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/avi/.openclaw"

# Stop gateway if running
openclaw gateway stop || true

# Remove old temp/session artifacts (safe targets only)
rm -rf "$ROOT"/tmp/* 2>/dev/null || true
rm -rf "$ROOT"/logs/*.old 2>/dev/null || true

# Optional: prune stale media > 14 days
find "$ROOT/media" -type f -mtime +14 -delete 2>/dev/null || true

echo "Cleanup done."
