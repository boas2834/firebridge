#!/bin/sh
# Startskripte der Firebridge anlegen (install.sh und Bau des Debian-Pakets).
#   make-wrappers.sh ZIELORDNER PROGRAMMORDNER PAKETDATEIEN
#     ZIELORDNER      z. B. /usr/local/bin
#     PROGRAMMORDNER  wo firebridge/ und vendor/ liegen (/opt/firebridge)
set -eu
DEST=$1
PREFIX=$2
PKG=$3
mkdir -p "$DEST"
wrap() {
    cat > "$DEST/$1" <<EOW
#!/bin/sh
export PYTHONPATH=$PREFIX:$PREFIX/vendor
exec /usr/bin/python3 -m $2 "\$@"
EOW
    chmod 755 "$DEST/$1"
}
wrap firebridged firebridge
wrap firebridge-gui firebridge.gui
wrap firebridge-update firebridge.update
wrap firebridge-admin-passwort firebridge.admin
wrap firebridge-kiosk firebridge.kiosk
install -m 755 "$PKG/kiosk/firebridge-kiosk-session" "$DEST/"
