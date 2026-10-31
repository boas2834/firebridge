"""Kioskmodus: die Station startet direkt in die Firebridge, ohne Desktop.

    sudo firebridge-kiosk an      einschalten (wirkt ab dem nächsten Start)
    sudo firebridge-kiosk aus     ausschalten, Anmeldung wieder wie vorher
    firebridge-kiosk status

Eingeschaltet meldet LightDM beim Start automatisch den Benutzer
firebridge-kiosk an (ohne Passwort, kann sich sonst nirgends anmelden) und
startet die Sitzung „Firebridge-Kiosk“: nur die Oberfläche im Vollbild, kein
Desktop, kein Startmenü, kein Browser. Stürzt sie ab, startet sie neu.
„Kiosk verlassen“ in der Oberfläche (nur mit Admin-Passwort) beendet die
Sitzung, dann erscheint die normale Anmeldung.

Alles ist umkehrbar: „an“ legt eine eigene Datei in /etc/lightdm/lightdm.conf.d
an und schaltet eine vorhandene automatische Anmeldung in
/etc/lightdm/lightdm.conf ab (die Zeilen werden nur auskommentiert und
markiert). „aus“ löscht die Datei und stellt die Zeilen wieder her. Der Benutzer
firebridge-kiosk bleibt, er kann sich ohne Kiosk nicht anmelden
(„aus --benutzer-entfernen“ löscht ihn).

Nur LightDM wird unterstützt (Debian mit Xfce, Linux Mint).

Aus der Oberfläche (Einstellungen → Kioskmodus, mit Admin-Passwort) startet der
Dienst dafür die Unit firebridge-kiosk@an.service bzw. @aus.service: der Dienst
selbst darf /etc nicht beschreiben (ProtectSystem=strict).
"""

from __future__ import annotations

import argparse
import grp
import os
import pwd
import re
import shutil
import subprocess
import sys
from pathlib import Path

USER = "firebridge-kiosk"
HOME = Path("/var/lib/firebridge-kiosk")
SESSION = "firebridge-kiosk"
LIGHTDM_DIR = Path("/etc/lightdm")
DROPIN_NAME = "90-firebridge-kiosk.conf"
MARK = "#firebridge-kiosk# "
XSESSION = Path("/usr/share/xsessions/firebridge-kiosk.desktop")

DROPIN = f"""# Von firebridge-kiosk angelegt. Entfernen mit: sudo firebridge-kiosk aus
[Seat:*]
autologin-user={USER}
autologin-session={SESSION}
"""

# Zeilen in lightdm.conf, die eine andere automatische Anmeldung festlegen
_AUTOLOGIN = re.compile(r"^\s*autologin-(user|session|user-timeout)\s*=")


class KioskError(Exception):
    pass


def dropin_path(lightdm_dir: Path = LIGHTDM_DIR) -> Path:
    return lightdm_dir / "lightdm.conf.d" / DROPIN_NAME


def is_on(lightdm_dir: Path = LIGHTDM_DIR) -> bool:
    return dropin_path(lightdm_dir).exists()


def status(lightdm_dir: Path = LIGHTDM_DIR) -> dict:
    """Für Statusanzeige und Einstellungen: an, möglich, und warum nicht."""
    reason = ""
    if not lightdm_dir.is_dir():
        reason = "Der Kioskmodus braucht LightDM als Anmeldung (Debian mit Xfce, Linux Mint)."
    elif not XSESSION.exists():
        reason = "Die Kiosk-Sitzung fehlt: bitte die Firebridge neu installieren."
    return {"on": is_on(lightdm_dir), "available": not reason, "reason": reason}


def disable_other_autologin(text: str) -> str:
    """Aktive autologin-Zeilen auskommentieren und markieren (lightdm.conf wird nach conf.d gelesen
    und würde unsere Einstellung sonst überstimmen)."""
    out = []
    for line in text.splitlines(keepends=True):
        out.append(MARK + line if _AUTOLOGIN.match(line) else line)
    return "".join(out)


def restore_other_autologin(text: str) -> str:
    return "".join(line[len(MARK):] if line.startswith(MARK) else line
                   for line in text.splitlines(keepends=True))


def _rewrite(path: Path, fn) -> bool:
    try:
        old = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return False
    new = fn(old)
    if new == old:
        return False
    tmp = path.with_name(path.name + ".firebridge-tmp")
    tmp.write_text(new, encoding="utf-8")
    shutil.copymode(path, tmp)
    os.replace(tmp, path)
    return True


def enable_lightdm(lightdm_dir: Path = LIGHTDM_DIR) -> list[str]:
    if not lightdm_dir.is_dir():
        raise KioskError("LightDM ist nicht installiert. Der Kioskmodus braucht LightDM als Anmeldung "
                         "(Debian mit Xfce, Linux Mint).")
    done = []
    d = dropin_path(lightdm_dir)
    d.parent.mkdir(parents=True, exist_ok=True)
    d.write_text(DROPIN, encoding="utf-8")
    done.append(f"{d} angelegt")
    if _rewrite(lightdm_dir / "lightdm.conf", disable_other_autologin):
        done.append(f"bisherige automatische Anmeldung in {lightdm_dir / 'lightdm.conf'} auskommentiert")
    return done


def disable_lightdm(lightdm_dir: Path = LIGHTDM_DIR) -> list[str]:
    done = []
    d = dropin_path(lightdm_dir)
    if d.exists():
        d.unlink()
        done.append(f"{d} entfernt")
    if _rewrite(lightdm_dir / "lightdm.conf", restore_other_autologin):
        done.append(f"bisherige automatische Anmeldung in {lightdm_dir / 'lightdm.conf'} wiederhergestellt")
    return done


def ensure_user() -> str:
    try:
        pwd.getpwnam(USER)
        msg = f"Benutzer {USER} vorhanden"
    except KeyError:
        subprocess.run(["useradd", "--system", "--home-dir", str(HOME), "--create-home", "--shell", "/bin/sh",
                        "--comment", "Firebridge Kiosk", USER], check=True)
        msg = f"Benutzer {USER} angelegt"
    # Kein Passwort: anmelden kann er sich nur über die automatische Anmeldung von LightDM
    subprocess.run(["passwd", "--lock", USER], check=True, stdout=subprocess.DEVNULL)
    try:
        grp.getgrnam("firebridge")
        subprocess.run(["usermod", "-aG", "firebridge", USER], check=True)
    except KeyError:
        raise KioskError("Gruppe firebridge fehlt: ist die Firebridge installiert?")
    return msg


def remove_user() -> str:
    try:
        pwd.getpwnam(USER)
    except KeyError:
        return f"Benutzer {USER} gibt es nicht"
    subprocess.run(["userdel", "--remove", USER], check=False, stderr=subprocess.DEVNULL)
    return f"Benutzer {USER} entfernt"


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="firebridge-kiosk", description="Kioskmodus der Firebridge ein- oder ausschalten")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("an", help="einschalten (ab dem nächsten Start)")
    off = sub.add_parser("aus", help="ausschalten, Anmeldung wie vorher")
    off.add_argument("--benutzer-entfernen", action="store_true", help=f"auch den Benutzer {USER} löschen")
    sub.add_parser("status", help="anzeigen, ob der Kiosk eingeschaltet ist")
    args = ap.parse_args(argv)

    if args.cmd == "status":
        print("Kioskmodus: " + ("an" if is_on() else "aus"))
        return
    if os.geteuid() != 0:
        sys.exit(f"Bitte mit sudo starten: sudo firebridge-kiosk {args.cmd}")
    try:
        if args.cmd == "an":
            if not XSESSION.exists():
                raise KioskError(f"{XSESSION} fehlt: bitte die Firebridge neu installieren")
            steps = [ensure_user(), *enable_lightdm()]
            tail = ("Kioskmodus ist an. Er beginnt beim nächsten Start des Rechners "
                    "(oder sofort mit: sudo systemctl restart lightdm, das beendet die laufende Sitzung).\n"
                    "Verlassen: in der Oberfläche „Kiosk verlassen“ (Admin-Passwort). Ganz ausschalten: "
                    "sudo firebridge-kiosk aus")
        else:
            steps = disable_lightdm()
            if args.benutzer_entfernen:
                steps.append(remove_user())
            tail = ("Kioskmodus ist aus. Ab dem nächsten Start ist die Anmeldung wieder wie vorher."
                    if steps else "Kioskmodus war schon aus.")
    except (KioskError, subprocess.CalledProcessError, OSError) as exc:
        sys.exit(f"Fehler: {exc}")
    for s in steps:
        print(" · " + s)
    print(tail)


if __name__ == "__main__":
    main()
