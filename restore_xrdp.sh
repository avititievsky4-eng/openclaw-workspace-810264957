#!/usr/bin/env bash
set -euo pipefail

USER_NAME="${1:-avi}"
USER_PASS="${2:-}"

if [[ $(id -u) -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi

$SUDO apt-get update
$SUDO apt-get install -y xrdp xorgxrdp gnome-session dbus-x11

id "$USER_NAME" >/dev/null 2>&1 || { echo "User $USER_NAME not found"; exit 1; }

$SUDO usermod -aG ssl-cert "$USER_NAME" || true

HOME_DIR="$(getent passwd "$USER_NAME" | cut -d: -f6)"
cat > "$HOME_DIR/.xsession" <<'EOF'
gnome-session
EOF
chown "$USER_NAME":"$USER_NAME" "$HOME_DIR/.xsession"
chmod 644 "$HOME_DIR/.xsession"

if [[ -n "$USER_PASS" ]]; then
  echo "$USER_NAME:$USER_PASS" | $SUDO chpasswd
fi

$SUDO systemctl enable xrdp
$SUDO systemctl restart xrdp

systemctl is-active xrdp
ss -ltnp | grep 3389 || true

echo "XRDP restored for user: $USER_NAME"
