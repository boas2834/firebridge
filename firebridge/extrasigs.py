"""Zusatzsignaturen für ClamAV von Sanesecurity.

Die offiziellen ClamAV-Signaturen erkennen vor allem bekannte Schadprogramme.
Zusätzlich lädt firebridge-update täglich von Sanesecurity (sanesecurity.com)
Signaturen gegen Makro-Schadsoftware, Hashes von Schadprogrammen, Webshells und
eine Liste bekannter Fehlalarme der offiziellen Signaturen. Jede Datei ist mit
dem GPG-Schlüssel von Sanesecurity signiert (Fingerabdruck
4E02 5A1C BA90 A065 3F38 D2D8 D691 DED9 31EA 4D9E); der Schlüssel liegt dem
Programm bei (keys/sanesecurity.asc), die Signatur wird vor dem Einspielen
geprüft.

URLhaus (abuse.ch) war im Konzept vorgesehen, bietet seine ClamAV-Signaturen
aber nicht mehr an (urlhaus.ndb liefert inzwischen „410 Gone“).

Bewusst nicht dabei sind die Sanesecurity-Sätze für Spam, Phishing-Mails und
„Foxhole“ (meldet jedes Programm in einem Archiv als Virus): für E-Mails
gedacht, auf einem USB-Stick nur Fehlalarme. Was in Archiven steckt, regelt die
Richtlinie der Firebridge.

Vor dem Einspielen lädt clamscan jede Datei einmal zur Probe. Was nicht lädt,
falsch signiert ist oder sich nicht laden lässt, wird nicht übernommen; der
letzte funktionierende Stand bleibt. Was in der Konfiguration abgewählt wird,
räumt das nächste Update wieder weg (nur Dateien, die es selbst angelegt hat).

Einstellungen unter [extra_signatures] in /etc/firebridge/firebridge.toml.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pwd
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from . import __version__

KEY_FILE = Path(__file__).with_name("keys") / "sanesecurity.asc"
STATE_NAME = "extra-signatures.json"
MAX_DB = 100 * 1024 * 1024

DEFAULTS = {
    "sanesecurity": True,
    "sanesecurity_mirror": "https://mirror.rollernet.us/sanesecurity",
    # Nur Sätze gegen Schadsoftware mit geringer Fehlalarm-Gefahr
    "sanesecurity_dbs": ["badmacro.ndb", "malwarehash.hsb", "hackingteam.hsb", "shelter.ldb", "rogue.hdb",
                         "sigwhitelist.ign2"],
}
DB_SUFFIXES = (".ndb", ".hdb", ".hsb", ".ldb", ".cdb", ".mdb", ".msb", ".ign2", ".fp", ".sfp", ".yara", ".yar")


def settings(raw: dict | None) -> dict:
    """[extra_signatures] mit Standardwerten auffüllen und prüfen."""
    raw = dict(raw or {})
    unknown = set(raw) - set(DEFAULTS)
    if unknown:
        raise ValueError(f"Unbekannte Einstellung unter [extra_signatures]: {sorted(unknown)[0]}")
    s = {**DEFAULTS, **raw}
    for name in s["sanesecurity_dbs"]:
        if not isinstance(name, str) or "/" in name or name.startswith(".") or not name.endswith(DB_SUFFIXES):
            raise ValueError(f"[extra_signatures] sanesecurity_dbs: ungültiger Dateiname {name!r}")
    if not str(s["sanesecurity_mirror"]).startswith("https://"):
        raise ValueError("[extra_signatures] sanesecurity_mirror muss mit https:// beginnen")
    return s


def wanted(s: dict) -> list[tuple[str, str, str]]:
    """(Dateiname, Quelle, URL) aller gewünschten Signaturdateien."""
    out = []
    if s["sanesecurity"]:
        base = s["sanesecurity_mirror"].rstrip("/")
        out += [(name, "Sanesecurity", f"{base}/{name}") for name in s["sanesecurity_dbs"]]
    return out


def _get(url: str, limit: int = MAX_DB) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": f"firebridge/{__version__}"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"größer als {limit // (1024 * 1024)} MB")
    return data


def dearmor(text: str) -> bytes:
    """ASCII-Armor eines öffentlichen Schlüssels in die Binärform, die gpgv als Keyring liest."""
    lines = text.strip().splitlines()
    try:
        body = lines[lines.index("") + 1:]
    except ValueError:
        raise ValueError("kein ASCII-Armor-Schlüssel")
    body = [ln for ln in body if not ln.startswith("-----") and not ln.startswith("=")]
    return base64.b64decode("".join(body), validate=True)


class Verifier:
    """Prüft Sanesecurity-Signaturen mit gpgv gegen den mitgelieferten Schlüssel (gpg selbst wird nicht gebraucht)."""

    def __init__(self, workdir: Path, key_file: Path = KEY_FILE, gpgv: str = "gpgv"):
        self.gpgv = gpgv
        self.keyring = workdir / "sanesecurity.gpg"
        try:
            self.keyring.write_bytes(dearmor(key_file.read_text(encoding="ascii")))
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"Schlüssel von Sanesecurity fehlt oder ist kaputt: {exc}")

    def check(self, data_file: Path, sig_file: Path) -> None:
        try:
            res = subprocess.run([self.gpgv, "--keyring", str(self.keyring), str(sig_file), str(data_file)],
                                 capture_output=True, text=True, timeout=120)
        except FileNotFoundError:
            raise RuntimeError("gpgv nicht installiert (Paket gpgv)")
        if res.returncode != 0:
            raise ValueError("GPG-Signatur ungültig")


def test_load(clamscan: str, db: Path, workdir: Path) -> None:
    """Datei zur Probe mit clamscan laden (ohne clamd anzufassen)."""
    empty = workdir / "leer"
    empty.touch()
    try:
        res = subprocess.run([clamscan, "--no-summary", "--quiet", "-d", str(db), str(empty)],
                             capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        raise RuntimeError("clamscan nicht installiert")
    if res.returncode != 0:
        raise ValueError(f"lässt sich nicht laden: {(res.stderr or res.stdout).strip()[-200:]}")


def _install(src: Path, dest: Path) -> None:
    """Atomar nach DatabaseDirectory, Besitzer wie freshclam (clamav)."""
    tmp = dest.with_name(f".{dest.name}.firebridge-tmp")
    shutil.copyfile(src, tmp)
    os.chmod(tmp, 0o644)
    try:
        pw = pwd.getpwnam("clamav")
        os.chown(tmp, pw.pw_uid, pw.pw_gid)
    except (KeyError, PermissionError):
        pass
    os.replace(tmp, dest)


def update(cfg, *, fetch=_get, verifier_factory=Verifier, loader=test_load) -> list[tuple[str, bool, str]]:
    """Lädt, prüft und spielt die Zusatzsignaturen ein. Ergebnis: Schritte (Name, ok, Meldung)."""
    s = settings(cfg.extra_signatures)
    db_dir = Path(cfg.clamav_db_dir)
    state_file = Path(cfg.state_dir) / STATE_NAME
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    installed: dict = state.get("files", {})
    steps: list[tuple[str, bool, str]] = []
    changed = False
    want = wanted(s)
    by_source: dict[str, list[str]] = {}
    errors: dict[str, list[str]] = {}

    with tempfile.TemporaryDirectory(prefix="firebridge-sigs-") as tmp:
        work = Path(tmp)
        verifier = None
        if any(src == "Sanesecurity" for _, src, _ in want):
            try:
                verifier = verifier_factory(work)
            except Exception as exc:
                errors.setdefault("Sanesecurity", []).append(str(exc))
        for name, source, url in want:
            if source == "Sanesecurity" and verifier is None:
                continue
            try:
                data = fetch(url)
                if not data.strip():
                    raise ValueError("leer")
                f = work / name
                f.write_bytes(data)
                if source == "Sanesecurity":
                    sig = work / f"{name}.sig"
                    sig.write_bytes(fetch(f"{url}.sig", 64 * 1024))
                    verifier.check(f, sig)
                digest = hashlib.sha256(data).hexdigest()
                dest = db_dir / name
                if installed.get(name, {}).get("sha256") == digest and dest.exists():
                    by_source.setdefault(source, []).append(name)
                    continue
                loader(cfg.clamscan_binary, f, work)
                _install(f, dest)
                installed[name] = {"source": source, "sha256": digest, "size": len(data), "url": url}
                changed = True
                by_source.setdefault(source, []).append(name)
            except Exception as exc:
                errors.setdefault(source, []).append(f"{name}: {exc}")

    # Abgewählte Dateien wegräumen, aber nur die, die wir selbst angelegt haben
    keep = {name for name, _, _ in want}
    for name in sorted(set(installed) - keep):
        try:
            (db_dir / name).unlink(missing_ok=True)
            changed = True
        except OSError as exc:
            errors.setdefault("Aufräumen", []).append(f"{name}: {exc}")
            continue
        installed.pop(name)

    for source in ("Sanesecurity",):
        if not any(src == source for _, src, _ in want):
            continue
        ok_files = by_source.get(source, [])
        errs = errors.pop(source, [])
        if errs:
            msg = "; ".join(errs[:3]) + (f" (und {len(errs) - 3} weitere)" if len(errs) > 3 else "")
            if ok_files:
                msg = f"{len(ok_files)} Dateien aktuell, Fehler: {msg}"
            steps.append((source, False, msg))
        else:
            steps.append((source, True, f"{len(ok_files)} Signaturdatei{'en' if len(ok_files) != 1 else ''} "
                                        f"aktuell ({', '.join(ok_files)})"))
    for source, errs in errors.items():
        steps.append((source, False, "; ".join(errs[:3])))

    state = {"files": installed, "changed": changed}
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
        os.replace(tmp, state_file)
    except OSError:
        pass
    return steps
