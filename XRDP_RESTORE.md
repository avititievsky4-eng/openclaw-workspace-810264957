# XRDP Restore Guide (Avi)

Use this file to rebuild the current working XRDP setup after reinstall/format.

## 0) Install + enable XRDP

```bash
sudo apt-get update
sudo apt-get install -y xrdp
sudo systemctl enable --now xrdp
```

## 1) Install desktop/session packages used

```bash
sudo apt-get install -y xfce4 xfce4-goodies dbus-x11 lxde-core terminator xfce4-terminal fonts-dejavu-core xfonts-terminus fonts-noto-core
```

## 2) Allow xrdp TLS key access

```bash
sudo adduser xrdp ssl-cert
```

## 3) Create dedicated RDP user

```bash
sudo useradd -m -s /bin/bash avi-rdp || true
echo 'avi-rdp:aviavi11' | sudo chpasswd
sudo usermod -aG ssl-cert,xrdp avi-rdp || true
```

## 4) XRDP session launcher (stable, LXDE)

Write `/etc/xrdp/startwm.sh` exactly:

```bash
sudo tee /etc/xrdp/startwm.sh >/dev/null <<'SH'
#!/bin/sh
if [ -r /etc/profile ]; then . /etc/profile; fi
if [ -r "$HOME/.profile" ]; then . "$HOME/.profile"; fi
unset WAYLAND_DISPLAY
export XDG_SESSION_TYPE=x11
# Force smaller virtual resolution so UI appears larger
(sleep 2; xrandr -s 1280x720 || xrandr -s 1366x768 || xrandr -s 1024x768 || true) &
exec /usr/bin/startlxde
SH
sudo chmod 755 /etc/xrdp/startwm.sh
```

## 5) User session files for `avi-rdp`

```bash
sudo -u avi-rdp bash -lc "echo startlxde > ~/.xsession"
sudo -u avi-rdp bash -lc "cat > ~/.xsessionrc <<'EOF'
unset WAYLAND_DISPLAY
export XDG_SESSION_TYPE=x11
EOF"
sudo -u avi-rdp chmod 644 /home/avi-rdp/.xsession /home/avi-rdp/.xsessionrc
```

## 6) Terminal default + font settings

Set terminal alternative to Terminator:

```bash
sudo update-alternatives --set x-terminal-emulator /usr/bin/terminator
```

Set XFCE terminal font (if opened):

```bash
sudo -u avi-rdp bash -lc "mkdir -p ~/.config/xfce4/terminal && cat > ~/.config/xfce4/terminal/terminalrc <<'EOF'
[Configuration]
FontName=DejaVu Sans Mono 16
MiscAlwaysShowTabs=FALSE
ScrollingLines=10000
MiscMenubarDefault=FALSE
EOF"
```

## 7) Title bar font (Openbox/LXDE) — CURRENT VALUE = 25

```bash
sudo -u avi-rdp bash -lc "mkdir -p ~/.config/openbox; [ -f ~/.config/openbox/lxde-rc.xml ] || cp /etc/xdg/openbox/lxde-rc.xml ~/.config/openbox/lxde-rc.xml"
sudo -u avi-rdp python3 - <<'PY'
from pathlib import Path
import re
p=Path('/home/avi-rdp/.config/openbox/lxde-rc.xml')
s=p.read_text()
s=re.sub(r'<size>\d+</size>','<size>25</size>',s)
p.write_text(s)
print('openbox title font set to 25')
PY
```

## 8) Restart XRDP services

```bash
sudo systemctl restart xrdp xrdp-sesman
```

## 9) Quick checks

```bash
systemctl is-active xrdp xrdp-sesman
sudo tail -n 50 /var/log/xrdp-sesman.log
```

Expected: both services `active` and no immediate WM exit loop.

---

## Notes

- If connection opens then immediately closes, check `/var/log/xrdp-sesman.log` for:
  - `Window manager ... exited quickly`
- If screen looks tiny, it is usually client-side negotiated resolution + high-DPI.
- Current server-side fallback forces 1280x720 (with 1366x768/1024x768 fallbacks).
