# TOOLS.md - Local Notes

Skills define _how_ tools work. This file is for _your_ specifics — the stuff that's unique to your setup.

## What Goes Here

Things like:

- Camera names and locations
- SSH hosts and aliases
- Preferred voices for TTS
- Speaker/room names
- Device nicknames
- Anything environment-specific

## Examples

```markdown
### Cameras

- living-room → Main area, 180° wide angle
- front-door → Entrance, motion-triggered

### SSH

- home-server → 192.168.1.100, user: admin

### TTS

- Preferred voice: "Nova" (warm, slightly British)
- Default speaker: Kitchen HomePod
```

### XRDP (Working Configuration)

- Service: `xrdp` + `xrdp-sesman`
- Dedicated RDP user: `avi-rdp`
- Session launcher: `/etc/xrdp/startwm.sh` loads `~/.xprofile` and `~/.Xresources`
- Current working values (as of now):
  - `GDK_SCALE=2`
  - `GDK_DPI_SCALE=1.0`
  - `QT_SCALE_FACTOR=0.5`
  - `XCURSOR_SIZE=46`
- Terminal defaults:
  - `x-terminal-emulator` → `terminator`
  - XFCE terminal font: `DejaVu Sans Mono 16`
  - XTerm fallback: `DejaVu Sans Mono 18`, geometry `140x42`
- User files used:
  - `/home/avi-rdp/.xprofile`
  - `/home/avi-rdp/.Xresources`
  - `/home/avi-rdp/.config/xfce4/terminal/terminalrc`

## Why Separate?

Skills are shared. Your setup is yours. Keeping them apart means you can update skills without losing your notes, and share skills without leaking your infrastructure.

---

Add whatever helps you do your job. This is your cheat sheet.
