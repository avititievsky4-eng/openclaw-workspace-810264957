#!/usr/bin/env bash
set -euo pipefail

USER_NAME="${SUDO_USER:-${USER}}"
HOME_DIR="$(getent passwd "$USER_NAME" | cut -d: -f6)"

echo "[1/8] Install xrdp + xfce + dbus-x11"
sudo apt-get update
sudo apt-get install -y xrdp xfce4 xfce4-goodies dbus-x11

echo "[2/8] Enable xrdp service"
sudo systemctl enable --now xrdp

echo "[3/8] Allow xrdp to read TLS key"
sudo adduser xrdp ssl-cert || true

echo "[4/8] Configure user session files"
echo 'startxfce4' | sudo -u "$USER_NAME" tee "$HOME_DIR/.xsession" >/dev/null
sudo -u "$USER_NAME" chmod 644 "$HOME_DIR/.xsession"
printf "unset WAYLAND_DISPLAY\nexport XDG_SESSION_TYPE=x11\n" | sudo -u "$USER_NAME" tee "$HOME_DIR/.xsessionrc" >/dev/null

echo "[5/8] Write /etc/xrdp/startwm.sh"
sudo tee /etc/xrdp/startwm.sh >/dev/null <<'SH'
#!/bin/sh
if [ -r /etc/profile ]; then . /etc/profile; fi
if [ -r "$HOME/.profile" ]; then . "$HOME/.profile"; fi
unset WAYLAND_DISPLAY
unset XDG_CURRENT_DESKTOP
unset XDG_SESSION_DESKTOP
unset DESKTOP_SESSION
export XDG_SESSION_TYPE=x11
export XDG_CURRENT_DESKTOP=XFCE
export XDG_SESSION_DESKTOP=xfce
export DESKTOP_SESSION=xfce
export DISPLAY=${DISPLAY:-:10.0}
exec /usr/bin/startxfce4
SH
sudo chmod 755 /etc/xrdp/startwm.sh

echo "[6/8] Clean stale user auth/session files"
sudo -u "$USER_NAME" rm -f "$HOME_DIR/.Xauthority" "$HOME_DIR/.xsession-errors"

echo "[7/8] Restart xrdp services"
sudo systemctl restart xrdp xrdp-sesman

echo "[8/8] Done. Service status:"
systemctl status xrdp --no-pager -l | sed -n '1,25p'

echo
echo "RDP fix completed. Try reconnecting now."
