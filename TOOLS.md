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
- Working scale values (for readable UI on high-res clients):
  - `GDK_SCALE=2`
  - `QT_SCALE_FACTOR=1.5`
  - `XCURSOR_SIZE=48`
  - `Xft.dpi: 168`
- User files used:
  - `/home/avi-rdp/.xprofile`
  - `/home/avi-rdp/.Xresources`

## Why Separate?

Skills are shared. Your setup is yours. Keeping them apart means you can update skills without losing your notes, and share skills without leaking your infrastructure.

---

Add whatever helps you do your job. This is your cheat sheet.
