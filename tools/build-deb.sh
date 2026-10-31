#!/bin/sh
# Baut das Debian-Paket der Firebridge aus diesem Git-Klon.
#
#   tools/build-deb.sh [--arch amd64|arm64] [AUSGABEORDNER]
#                               → firebridge_<version>-<build>_<arch>.deb (Standard: amd64)
#
# arm64 ist für den Raspberry Pi 4/5 (mind. 4 GB RAM) mit Raspberry Pi OS auf Basis von
# Debian 13 (Trixie); ältere Ausgaben haben kein PySide6. Gebaut werden kann auf jedem Rechner,
# pip holt dafür die arm64-Ausgabe von YARA-X.
#
# Braucht dpkg-deb, git und Netz (pip lädt YARA-X, oletools und smbprotocol, die Debian 13 nicht
# als Paket hat, in das Paket hinein). Ohne root, das Paket wird mit dpkg-deb --root-owner-group gebaut.
# Installieren: sudo apt install ./firebridge_<version>-<build>_amd64.deb
set -eu
SRC=$(cd "$(dirname "$0")/.." && pwd)
ARCH=amd64     # YARA-X kommt fertig übersetzt, deshalb je Architektur ein Paket
if [ "${1:-}" = --arch ]; then
    ARCH=${2:-}
    shift 2
fi
case "$ARCH" in
    amd64) MACHINE=x86_64 ;;
    arm64) MACHINE=aarch64 ;;
    *) echo "Unbekannte Architektur: $ARCH (amd64 oder arm64)" >&2; exit 2 ;;
esac
OUT=${1:-$SRC/dist}
PREFIX=/opt/firebridge

git_src() { git -C "$SRC" -c safe.directory="$SRC" "$@"; }
VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$SRC/firebridge/__init__.py")
# Im öffentlichen Repo fehlt der Verlauf, dort steht die Build-Nummer fest in BUILD_NUMBER
BUILD=$(cat "$SRC/BUILD_NUMBER" 2>/dev/null || git_src rev-list --count HEAD)
COMMIT=$(git_src rev-parse --short=7 HEAD)
DIRTY=""
[ -n "$(git_src status --porcelain --untracked-files=no)" ] && DIRTY="+"
DEBVER="$VERSION-$BUILD"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
ROOT=$WORK/firebridge

echo "==> Programm"
mkdir -p "$ROOT$PREFIX"
cp -r "$SRC/firebridge" "$ROOT$PREFIX/"
find "$ROOT$PREFIX" -name '__pycache__' -prune -exec rm -rf {} +
printf '{"build": "%s", "commit": "%s%s", "date": "%s"}\n' "$BUILD" "$COMMIT" "$DIRTY" \
    "$(git_src log -1 --format=%cs)" > "$ROOT$PREFIX/firebridge/BUILD.json"

echo "==> Python-Bibliotheken"
# Für Debian 13 (Python 3.13, glibc 2.41), unabhängig vom Rechner, auf dem gebaut wird
PLATFORMS=""
for g in 17 28 31 34 35 36 38 39 40 41; do PLATFORMS="$PLATFORMS --platform manylinux_2_${g}_$MACHINE"; done
PLATFORMS="$PLATFORMS --platform manylinux2014_$MACHINE --platform any"
# shellcheck disable=SC2046
python3 -m pip install --quiet --no-deps --only-binary=:all: --no-compile --python-version 3.13 \
    $PLATFORMS --implementation cp --target "$ROOT$PREFIX/vendor" \
    $(grep -hv '^#' "$SRC/packaging/vendor.txt" "$SRC/packaging/vendor-smb.txt")
find "$ROOT$PREFIX/vendor" -name '__pycache__' -prune -exec rm -rf {} +

echo "==> Startskripte und Systemdateien"
sh "$SRC/packaging/make-wrappers.sh" "$ROOT/usr/bin" "$PREFIX" "$SRC/packaging"
mkdir -p "$ROOT/usr/share/firebridge" "$ROOT/usr/share/doc/firebridge"
cp -r "$SRC/packaging" "$ROOT/usr/share/firebridge/"
cp "$SRC/README.md" "$SRC/docs/HANDBUCH.md" "$ROOT/usr/share/doc/firebridge/"
cp "$SRC/LICENSE" "$ROOT/usr/share/doc/firebridge/copyright"

echo "==> Steuerdateien"
mkdir -p "$ROOT/DEBIAN"
SIZE=$(du -sk "$ROOT" | cut -f1)
sed -e "s/@VERSION@/$DEBVER/" -e "s/@ARCH@/$ARCH/" -e "s/@SIZE@/$SIZE/" \
    "$SRC/packaging/debian/control" > "$ROOT/DEBIAN/control"
for f in preinst postinst prerm postrm; do
    install -m 755 "$SRC/packaging/debian/$f" "$ROOT/DEBIAN/$f"
done

mkdir -p "$OUT"
DEB="$OUT/firebridge_${DEBVER}_$ARCH.deb"
dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$DEB" >/dev/null
echo "Fertig: $DEB (Build $BUILD, $COMMIT$DIRTY)"
