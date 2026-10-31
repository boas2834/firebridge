#!/bin/sh
# Installiert die Firebridge aus dem Git-Klon auf Debian 13 bzw. einem Debian-13-Live-System.
#
#   sudo ./install.sh            installieren oder aktualisieren
#   sudo ./install.sh --no-apt   ohne Paketinstallation (Pakete schon vorhanden)
#
# Alternativ als Debian-Paket: tools/build-deb.sh baut firebridge_<version>_amd64.deb.
#
# Entfernen: sudo ./uninstall.sh
set -eu

PREFIX=/opt/firebridge
SRC=$(cd "$(dirname "$0")" && pwd)
APT=1
[ "${1:-}" = "--no-apt" ] && APT=0

if [ "$(id -u)" -ne 0 ]; then
    echo "Bitte mit sudo ausführen: sudo $0" >&2
    exit 1
fi
TARGET_USER=${SUDO_USER:-}
if dpkg -s firebridge >/dev/null 2>&1; then
    echo "Die Firebridge ist schon als Debian-Paket installiert. Erst entfernen (sudo apt remove firebridge)" >&2
    echo "oder das neue Paket installieren (tools/build-deb.sh, dann sudo apt install ./firebridge_….deb)." >&2
    exit 1
fi

step() { printf '\n==> %s\n' "$1"; }

if [ "$APT" = 1 ]; then
    step "Pakete installieren"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 python3-pyside6.qtwidgets python3-dbus-next python3-pyudev \
        python3-cryptography python3-magic python3-pip nftables \
        clamav clamav-daemon clamav-freshclam \
        udisks2 eject util-linux exfatprogs gpgv unar
fi

step "Python-Bibliotheken nach $PREFIX/vendor"
# Debian 13 hat keine Pakete für YARA-X, oletools und smbprotocol. Sie kommen nur für die
# Firebridge nach $PREFIX/vendor, das System-Python bleibt unverändert. Feste Versionen,
# damit jede Installation gleich ist.
VENDOR_PKGS=$(grep -v '^#' "$SRC/packaging/vendor.txt" | tr '\n' ' ')
if python3 -c 'import smbclient' 2>/dev/null; then
    echo "smbprotocol ist im System vorhanden."
elif [ "$APT" = 1 ] && apt-cache show python3-smbprotocol >/dev/null 2>&1 \
        && DEBIAN_FRONTEND=noninteractive apt-get install -y python3-smbprotocol; then
    echo "smbprotocol aus den Debian-Paketen installiert."
else
    VENDOR_PKGS="$VENDOR_PKGS $(grep -v '^#' "$SRC/packaging/vendor-smb.txt" | tr '\n' ' ')"   # cryptography kommt aus apt
fi
rm -rf "$PREFIX/vendor.new"
mkdir -p "$PREFIX"
# shellcheck disable=SC2086
if python3 -m pip install --quiet --no-deps --only-binary=:all: --target "$PREFIX/vendor.new" $VENDOR_PKGS; then
    rm -rf "$PREFIX/vendor"
    mv "$PREFIX/vendor.new" "$PREFIX/vendor"
    echo "Installiert: $VENDOR_PKGS"
else
    rm -rf "$PREFIX/vendor.new"
    if [ -d "$PREFIX/vendor" ]; then
        echo "WARNUNG: pip fehlgeschlagen (Netz?), die bisherigen Bibliotheken bleiben." >&2
    else
        echo "FEHLER: pip fehlgeschlagen. Ohne diese Bibliotheken fehlen SMB, YARA und Makro-Erkennung." >&2
        exit 1
    fi
fi

step "Programm nach $PREFIX kopieren"
rm -rf "$PREFIX/firebridge"
mkdir -p "$PREFIX"
cp -r "$SRC/firebridge" "$PREFIX/"
# Build-Nummer für die Statuszeile (fortlaufende Commit-Nummer und Commit; im öffentlichen
# Repo steht sie fest in BUILD_NUMBER, weil dort der Verlauf fehlt)
git_src() { git -C "$SRC" -c safe.directory="$SRC" "$@" 2>/dev/null; }
if git_src rev-parse HEAD >/dev/null; then
    DIRTY=""
    [ -n "$(git_src status --porcelain --untracked-files=no)" ] && DIRTY="+"
    BUILD=$(cat "$SRC/BUILD_NUMBER" 2>/dev/null || git_src rev-list --count HEAD)
    printf '{"build": "%s", "commit": "%s%s", "date": "%s"}\n' \
        "$BUILD" "$(git_src rev-parse --short=7 HEAD)" "$DIRTY" \
        "$(git_src log -1 --format=%cs)" > "$PREFIX/firebridge/BUILD.json"
    echo "Build $BUILD ($(git_src rev-parse --short=7 HEAD)$DIRTY)"
fi
find "$PREFIX" -name '__pycache__' -prune -exec rm -rf {} +
sh "$SRC/packaging/make-wrappers.sh" /usr/local/bin "$PREFIX" "$SRC/packaging"

TARGET_USER="$TARGET_USER" sh "$SRC/packaging/setup-system.sh" "$SRC/packaging" /usr/local/bin "$APT"

cat <<EOF

Fertig.
  Dienst:   systemctl status firebridged
  Protokoll: journalctl -u firebridged -f
  Update:   systemctl list-timers firebridge-update.timer · journalctl -u firebridge-update
  USB:      sudo usbguard list-devices · Regeln: /etc/usbguard/rules.d/50-firebridge.conf
  GUI:      firebridge-gui   (oder im Menü "Firebridge")
  Kiosk:    sudo firebridge-kiosk an   (ausschalten: sudo firebridge-kiosk aus)

Hinweis: Wechseldatenträger werden ab jetzt nicht mehr automatisch eingebunden.
Neue Tastaturen, Mäuse und andere USB-Geräte sind gesperrt, bis du sie in der Firebridge freigibst.
Was beim Einschalten schon steckt, bleibt erlaubt.
Zum Rückgängigmachen: sudo $SRC/uninstall.sh
EOF
