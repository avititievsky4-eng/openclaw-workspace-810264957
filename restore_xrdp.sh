#!/usr/bin/env bash
set -euo pipefail

# One-shot XRDP restore (fresh machine friendly, idempotent)
# Usage: ./restore_xrdp.sh [rdp_user] [rdp_password]

RDP_USER="${1:-avi-rdp}"
RDP_PASS="${2:-aviavi11}"
RDP_HOME="/home/${RDP_USER}"

export DEBIAN_FRONTEND=noninteractive

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

echo "[1/10] Install packages"
run apt-get update
run apt-get install -y \
  xrdp \
  xfce4 xfce4-goodies \
  dbus-x11 \
  lxde-core \
  terminator xfce4-terminal \
  fonts-dejavu-core xfonts-terminus fonts-noto-core

echo "[2/10] Enable xrdp"
run systemctl enable --now xrdp

echo "[3/10] Allow xrdp cert key access"
run adduser xrdp ssl-cert || true

echo "[4/10] Create/update RDP user"
if ! getent passwd "$RDP_USER" >/dev/null; then
  run useradd -m -s /bin/bash "$RDP_USER"
fi
echo "$RDP_USER:$RDP_PASS" | run chpasswd
run usermod -aG ssl-cert,xrdp "$RDP_USER" || true

echo "[5/10] Configure /etc/xrdp/startwm.sh"
run tee /etc/xrdp/startwm.sh >/dev/null <<'SH'
#!/bin/sh
if [ -r /etc/profile ]; then . /etc/profile; fi
if [ -r "$HOME/.profile" ]; then . "$HOME/.profile"; fi
unset WAYLAND_DISPLAY
export XDG_SESSION_TYPE=x11
# Force smaller virtual resolution so UI appears larger
(sleep 2; xrandr -s 1280x720 || xrandr -s 1366x768 || xrandr -s 1024x768 || true) &
exec /usr/bin/startlxde
SH
run chmod 755 /etc/xrdp/startwm.sh

echo "[6/10] Configure user session files"
run_user bash -lc "echo startlxde > ~/.xsession"
run_user bash -lc "cat > ~/.xsessionrc <<'EOF'
unset WAYLAND_DISPLAY
export XDG_SESSION_TYPE=x11
EOF"
run_user chmod 644 "$RDP_HOME/.xsession" "$RDP_HOME/.xsessionrc"

echo "[7/10] Set default terminal emulator to terminator"
if [ -x /usr/bin/terminator ]; then
  run update-alternatives --set x-terminal-emulator /usr/bin/terminator || true
fi

echo "[8/10] Configure terminal font"
run_user bash -lc "mkdir -p ~/.config/xfce4/terminal && cat > ~/.config/xfce4/terminal/terminalrc <<'EOF'
[Configuration]
FontName=DejaVu Sans Mono 16
MiscAlwaysShowTabs=FALSE
ScrollingLines=10000
MiscMenubarDefault=FALSE
EOF"

echo "[9/10] Configure LXDE/Openbox title bar font size=25"
run_user bash -lc "mkdir -p ~/.config/openbox; [ -f ~/.config/openbox/lxde-rc.xml ] || cp /etc/xdg/openbox/lxde-rc.xml ~/.config/openbox/lxde-rc.xml"
RDP_HOME_ENV="$RDP_HOME" run_user python3 - <<'PY'
from pathlib import Path
import os, re
p = Path(os.environ['RDP_HOME_ENV']) / '.config/openbox/lxde-rc.xml'
s = p.read_text()
s = re.sub(r'<size>\d+</size>', '<size>25</size>', s)
p.write_text(s)
print('openbox title font set to 25')
PY

echo "[10/10] Restart XRDP services"
run systemctl restart xrdp xrdp-sesman

echo
echo "Done ✅"
echo "RDP user: $RDP_USER"
echo "RDP pass: $RDP_PASS"
echo
printf "Status: "
run systemctl is-active xrdp xrdp-sesman | tr '\n' ' '
echo
