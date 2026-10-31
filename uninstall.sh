#!/bin/sh
# Entfernt die Firebridge wieder. ClamAV und die Python-Pakete bleiben installiert,
# Berichte unter /var/lib/firebridge bleiben erhalten.
set -eu
if [ "$(id -u)" -ne 0 ]; then
    echo "Bitte mit sudo ausführen: sudo $0" >&2
    exit 1
fi
SRC=$(cd "$(dirname "$0")" && pwd)
if dpkg -s firebridge >/dev/null 2>&1; then
    echo "Die Firebridge ist als Debian-Paket installiert. Entfernen mit: sudo apt remove firebridge" >&2
    exit 1
fi
sh "$SRC/packaging/teardown-system.sh" /usr/local/bin
rm -f /usr/local/bin/firebridged /usr/local/bin/firebridge-gui /usr/local/bin/firebridge-update \
      /usr/local/bin/firebridge-admin-passwort /usr/local/bin/firebridge-kiosk /usr/local/bin/firebridge-kiosk-session
rm -rf /opt/firebridge
echo "Firebridge entfernt. Konfiguration (/etc/firebridge) und Berichte (/var/lib/firebridge) sind noch da."
