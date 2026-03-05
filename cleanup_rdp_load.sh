#!/usr/bin/env bash
set -euo pipefail

# Cleanup XRDP load for avi-rdp:
# 1) disable xscreensaver autostart (prevents cubestorm/pipes/headroom CPU spikes)
# 2) kill current screensaver processes
# 3) terminate stale avi-rdp sessions
# 4) restart xrdp services

RDP_USER="${1:-avi-rdp}"

if command -v sudo >/dev/null 2>&1; then
  if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
  else
    SUDO="sudo"
  fi
else
  if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (no sudo installed)." >&2
    exit 1
  fi
  SUDO=""
fi

run() { ${SUDO} "$@"; }
run_user() { ${SUDO} -u "$RDP_USER" "$@"; }

echo "[1/4] Disable xscreensaver autostart for $RDP_USER"
run_user bash -lc 'mkdir -p ~/.config/lxsession/LXDE; cat > ~/.config/lxsession/LXDE/autostart <<"EOF"
@lxpanel --profile LXDE
@pcmanfm --desktop --profile LXDE
#@xscreensaver -no-splash
EOF'

echo "[2/4] Kill screensaver animations if running"
run_user pkill -f xscreensaver || true
run_user pkill -f cubestorm || true
run_user pkill -f headroom || true
run_user pkill -f pipes || true

echo "[3/4] Terminate stale sessions for $RDP_USER"
for sid in $(run loginctl list-sessions --no-legend | awk -v u="$RDP_USER" '$3==u{print $1}'); do
  run loginctl terminate-session "$sid" || true
done

echo "[4/4] Restart XRDP services"
run systemctl restart xrdp xrdp-sesman

echo "Done ✅"
