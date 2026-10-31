#!/bin/sh
# Macht die Systemeinrichtung von setup-system.sh rückgängig (uninstall.sh und Debian-Paket, prerm).
# Programmdateien bleiben, das erledigt der Aufrufer.
#   teardown-system.sh PROGRAMMORDNER
set -eu
BIN=$1
# Kioskmodus aus, Anmeldung wieder wie vorher
if [ -x "$BIN/firebridge-kiosk" ]; then
    "$BIN/firebridge-kiosk" aus --benutzer-entfernen || true
fi
systemctl disable --now firebridged firebridge-update.timer 2>/dev/null || true
nft delete table inet firebridge 2>/dev/null || true
rm -f /etc/systemd/system/firebridged.service /etc/systemd/system/firebridge-update.service \
      /etc/systemd/system/firebridge-update.timer /etc/systemd/system/firebridge-kiosk@.service
systemctl daemon-reload
# Debians eigenes Signatur-Update wieder einschalten (die Firebridge hatte es durch ihren Timer ersetzt)
systemctl enable --now clamav-freshclam 2>/dev/null || true
# USBGuard abschalten (die Firebridge hatte es eingerichtet). Neue Geräte wieder ohne Rückfrage
# zulassen, sonst bleiben neu eingesteckte Tastaturen bis zum Neustart gesperrt.
systemctl disable --now usbguard 2>/dev/null || true
rm -f /etc/usbguard/rules.d/50-firebridge.conf
for f in /sys/bus/usb/devices/usb*/authorized_default; do
    if [ -w "$f" ]; then echo 1 > "$f"; fi
done
rm -f /etc/dbus-1/system.d/io.github.boas2834.Firebridge1.conf
systemctl reload dbus 2>/dev/null || true
rm -f /etc/udev/rules.d/90-firebridge.rules /etc/polkit-1/rules.d/50-firebridge.rules
udevadm control --reload
udevadm trigger --subsystem-match=block --action=change || true
rm -f /usr/share/applications/io.github.boas2834.Firebridge.desktop \
      /etc/xdg/autostart/io.github.boas2834.Firebridge.desktop \
      /usr/share/xsessions/firebridge-kiosk.desktop
