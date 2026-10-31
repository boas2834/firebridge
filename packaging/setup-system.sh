#!/bin/sh
# Richtet das System für die Firebridge ein: Gruppe, D-Bus, Automount aus, USBGuard, ClamAV,
# Dienste, Startmenü. Gemeinsam für install.sh und das Debian-Paket (postinst).
#
#   setup-system.sh PAKETDATEIEN PROGRAMMORDNER APT
#     PAKETDATEIEN    Ordner mit dbus/, udev/, systemd/ … (packaging/ im Repository)
#     PROGRAMMORDNER  wo firebridged, firebridge-gui … liegen (/usr/local/bin oder /usr/bin)
#     APT             1 = fehlendes usbguard mit apt nachinstallieren
#   TARGET_USER       dieser Benutzer kommt in die Gruppe firebridge
set -eu
PKG=$1
BIN=$2
APT=${3:-0}
TARGET_USER=${TARGET_USER:-}

step() { printf '\n==> %s\n' "$1"; }

step "Gruppe 'firebridge' und Berechtigungen"
getent group firebridge >/dev/null || groupadd --system firebridge
USER_POLICY=""
if [ -n "$TARGET_USER" ] && [ "$TARGET_USER" != root ]; then
    usermod -aG firebridge "$TARGET_USER"
    # Zusätzlich direkt für diesen Benutzer freigeben, damit es ohne Neuanmeldung klappt
    USER_POLICY="<policy user=\"$TARGET_USER\"><allow send_destination=\"io.github.boas2834.Firebridge1\"/></policy>"
    echo "Benutzer $TARGET_USER darf die Firebridge bedienen."
fi
sed "s|<!--@USER_POLICY@-->|$USER_POLICY|" "$PKG/dbus/io.github.boas2834.Firebridge1.conf" \
    > /etc/dbus-1/system.d/io.github.boas2834.Firebridge1.conf
systemctl reload dbus 2>/dev/null || true

step "Automount abschalten (udev + polkit)"
install -m 644 "$PKG/udev/90-firebridge.rules" /etc/udev/rules.d/
mkdir -p /etc/polkit-1/rules.d
install -m 644 "$PKG/polkit/50-firebridge.rules" /etc/polkit-1/rules.d/
udevadm control --reload
udevadm trigger --subsystem-match=block --action=change || true

step "BadUSB-Schutz: USBGuard"
# USBGuard sperrt jedes neu eingesteckte USB-Gerät, das kein reiner Speicher oder Hub ist
# (packaging/usbguard/50-firebridge.conf). Die Firebridge zeigt dazu einen Alarm und gibt
# Tastaturen nur nach einer Tipp-Probe frei.
if ! command -v usbguard >/dev/null 2>&1 && [ "$APT" = 1 ]; then
    # Das Paket würde den Dienst sofort mit Debians Standard starten. Der sperrt auch Geräte, die
    # schon stecken und nicht in der Regel-Liste stehen. Deshalb erst einrichten, dann starten.
    NO_START=0
    if [ ! -e /usr/sbin/policy-rc.d ]; then
        printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
        chmod 755 /usr/sbin/policy-rc.d
        NO_START=1
    fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y usbguard || echo "WARNUNG: usbguard ließ sich nicht installieren." >&2
    if [ "$NO_START" = 1 ]; then rm -f /usr/sbin/policy-rc.d; fi
fi
UG_CONF=/etc/usbguard/usbguard-daemon.conf
if command -v usbguard >/dev/null 2>&1 && [ -f "$UG_CONF" ]; then
    set_ug() {
        if grep -q "^$1=" "$UG_CONF"; then
            sed -i "s|^$1=.*|$1=$2|" "$UG_CONF"
        else
            echo "$1=$2" >> "$UG_CONF"
        fi
    }
    # Was beim Start von USBGuard schon steckt (eigene Tastatur, Maus, Boot-Stick), bleibt, wie es ist.
    # So sperrt sich niemand aus, auch nicht, wenn der Live-Stick an einem anderen Rechner startet.
    set_ug PresentDevicePolicy keep
    set_ug PresentControllerPolicy keep
    # Neu eingesteckte Geräte: Regeln anwenden, was auf keine passt, bleibt gesperrt
    set_ug InsertedDevicePolicy apply-policy
    set_ug ImplicitPolicyTarget block
    set_ug RuleFolder /etc/usbguard/rules.d/
    [ -f /etc/usbguard/rules.conf ] || install -m 600 /dev/null /etc/usbguard/rules.conf
    mkdir -p /etc/usbguard/rules.d
    install -m 600 "$PKG/usbguard/50-firebridge.conf" /etc/usbguard/rules.d/
    systemctl enable usbguard
    systemctl restart usbguard || echo "WARNUNG: usbguard startet nicht, Details: journalctl -u usbguard" >&2
    sleep 1
    usbguard list-devices >/dev/null 2>&1 && echo "USBGuard aktiv." \
        || echo "WARNUNG: USBGuard antwortet nicht. Die Firebridge sperrt neue Geräte dann selbst (schwächer)." >&2
else
    echo "WARNUNG: USBGuard fehlt. Die Firebridge sperrt neue Geräte dann selbst, aber erst kurz nach dem Einstecken." >&2
fi

step "Konfiguration"
mkdir -p /etc/firebridge
if [ ! -e /etc/firebridge/firebridge.toml ]; then
    install -m 640 "$PKG/firebridge.toml" /etc/firebridge/
else
    echo "/etc/firebridge/firebridge.toml existiert, bleibt unverändert."
    echo "Neue Einstellungen (Etappe 3: Richtlinie, YARA; Etappe 4: BadUSB; [virustotal]) stehen in $PKG/firebridge.toml."
fi
mkdir -p /etc/firebridge/yara
[ -e /etc/firebridge/yara/LIESMICH ] || cat > /etc/firebridge/yara/LIESMICH <<'EOF'
Eigene YARA-Regeln als *.yar hier ablegen. Sie werden beim täglichen Update
zusammen mit YARA Forge übersetzt, sofort mit: sudo firebridge-update --offline
EOF

step "ClamAV einrichten"
CLAMD_CONF=/etc/clamav/clamd.conf
if [ -f "$CLAMD_CONF" ]; then
    # Große Dateien nicht stillschweigend als sauber melden, sondern als "nicht vollständig geprüft"
    set_opt() {
        if grep -q "^$1 " "$CLAMD_CONF"; then
            sed -i "s|^$1 .*|$1 $2|" "$CLAMD_CONF"
        else
            echo "$1 $2" >> "$CLAMD_CONF"
        fi
    }
    set_opt AlertExceedsMax true
    set_opt MaxFileSize 400M
    set_opt MaxScanSize 1000M
    # Verschlüsselte Archive melden statt still als sauber durchzulassen (Richtlinie "verschlüsselt")
    set_opt AlertEncryptedArchive true
fi
if ! ls /var/lib/clamav/daily.c?d >/dev/null 2>&1; then
    echo "Noch keine Virensignaturen vorhanden, lade sie jetzt (kann einige Minuten dauern) …"
    systemctl stop clamav-freshclam 2>/dev/null || true
    freshclam || echo "WARNUNG: freshclam fehlgeschlagen. Netzwerk prüfen und später 'sudo freshclam' ausführen." >&2
fi
# Ab Etappe 3 aktualisiert firebridge-update.timer einmal täglich (ClamAV und YARA).
# Der eigene freshclam-Dienst von Debian würde sich mit ihm um die Sperrdatei streiten.
systemctl disable --now clamav-freshclam 2>/dev/null || true
systemctl enable clamav-daemon
systemctl restart clamav-daemon || echo "WARNUNG: clamd startet nicht (Signaturen fehlen?). Firebridge nutzt dann clamscan." >&2

step "Dienst firebridged und tägliches Update"
for unit in firebridged.service firebridge-update.service firebridge-update.timer firebridge-kiosk@.service; do
    sed "s|/usr/local/bin/|$BIN/|g" "$PKG/systemd/$unit" > "/etc/systemd/system/$unit"
    chmod 644 "/etc/systemd/system/$unit"
done
systemctl daemon-reload
systemctl enable --now firebridge-update.timer
echo "Erstes Update (ClamAV und YARA-Regeln von YARA Forge), dauert 1 bis 3 Minuten …"
if ! systemctl start firebridge-update.service; then
    echo "WARNUNG: Update fehlgeschlagen, Details: journalctl -u firebridge-update" >&2
    echo "         Später erneut: sudo systemctl start firebridge-update (oder in der Oberfläche)" >&2
fi
systemctl enable firebridged
systemctl restart firebridged

step "Admin-Passwort"
if [ -s /var/lib/firebridge/admin.json ]; then
    echo "Admin-Passwort ist schon festgelegt (ändern: sudo firebridge-admin-passwort)."
elif [ -t 0 ] && [ -z "${FIREBRIDGE_NO_PROMPT:-}" ]; then
    echo "Einstellungen, Freigaben und Verlauf löschen sind mit einem Admin-Passwort geschützt."
    "$BIN/firebridge-admin-passwort" || echo "Kein Passwort gesetzt. Später: sudo firebridge-admin-passwort" >&2
else
    echo "Noch kein Admin-Passwort. Festlegen mit: sudo firebridge-admin-passwort (oder in der Oberfläche)"
fi

step "Startmenü und Autostart"
install -m 644 "$PKG/desktop/io.github.boas2834.Firebridge.desktop" /usr/share/applications/
mkdir -p /etc/xdg/autostart
install -m 644 "$PKG/desktop/io.github.boas2834.Firebridge.desktop" /etc/xdg/autostart/

step "Kioskmodus (ein/aus: Einstellungen oder sudo firebridge-kiosk an|aus)"
mkdir -p /usr/share/xsessions
install -m 644 "$PKG/kiosk/firebridge-kiosk.desktop" /usr/share/xsessions/
"$BIN/firebridge-kiosk" status

