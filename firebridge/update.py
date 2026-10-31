"""firebridge-update: Virensignaturen und YARA-Regeln aktualisieren.

Läuft einmal täglich über firebridge-update.timer (03:00, bis 30 min
verzögert, nach dem Einschalten nachgeholt), von Hand mit

    sudo systemctl start firebridge-update      (wie der Timer)
    sudo firebridge-update --offline            nur neu übersetzen, ohne Download

Schritte:
  1. freshclam: ClamAV-Signaturen
  2. Zusatzsignaturen: Sanesecurity (GPG-geprüft), siehe extrasigs.py
  3. clamd lädt die neuen Signaturen (RELOAD)
  4. YARA Forge: neuestes Release von GitHub laden, SHA-256 gegen die von
     GitHub angegebene Prüfsumme prüfen, zusammen mit eigenen Regeln aus
     /etc/firebridge/yara/*.yar übersetzen

Schlägt ein Schritt fehl, bleibt der letzte funktionierende Stand aktiv. Das
Ergebnis steht in /var/lib/firebridge/update.json und in der Oberfläche.

Dieser Dienst läuft getrennt vom Prüfdienst (eigene systemd-Unit). Die
Netzwerk-Sperre von firebridged gilt für ihn nicht, er sieht aber auch keinen
eingebundenen Datenträger (die liegen im privaten Mount-Namespace von firebridged).
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import logging
import os
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

from . import __version__
from . import config as config_mod
from . import extrasigs
from .analysis import yararules
from .clamav import ClamdClient

log = logging.getLogger("firebridge-update")

FORGE_API = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
MAX_DOWNLOAD = 200 * 1024 * 1024


def now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


class StatusFile:
    """update.json: läuft gerade? wann zuletzt? welche Schritte ok?"""

    def __init__(self, path: Path):
        self.path = path
        self.data: dict = {"running": True, "started": now(), "finished": "", "ok": None, "steps": []}

    def write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, self.path)

    def step(self, name: str, ok: bool, message: str) -> None:
        (log.info if ok else log.error)("%s: %s", name, message)
        self.data["steps"].append({"name": name, "ok": ok, "message": message})
        self.write()

    def finish(self) -> bool:
        ok = all(s["ok"] for s in self.data["steps"])
        self.data.update(running=False, finished=now(), ok=ok)
        self.write()
        return ok


def read_status(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


# --------------------------------------------------------------------- ClamAV

def update_clamav(cfg) -> tuple[bool, str]:
    active = subprocess.run(["systemctl", "is-active", "--quiet", "clamav-freshclam.service"]).returncode == 0
    if active:
        return True, "übersprungen, der Dienst clamav-freshclam hält die Signaturen selbst aktuell"
    try:
        res = subprocess.run([cfg.freshclam_binary, "--stdout"], capture_output=True,
                             text=True, timeout=1800)
    except FileNotFoundError:
        return False, "freshclam nicht installiert"
    except subprocess.TimeoutExpired:
        return False, "freshclam: Zeitlimit überschritten"
    lines = [ln.strip() for ln in (res.stdout + res.stderr).splitlines() if ln.strip()]
    interesting = [ln for ln in lines if any(k in ln for k in ("daily", "main", "bytecode", "ERROR", "WARNING"))]
    summary = "; ".join(interesting[-3:]) or (lines[-1] if lines else "")
    if res.returncode in (0, 1):   # 1 = schon aktuell
        return True, summary or "Signaturen aktuell"
    return False, f"freshclam fehlgeschlagen (Code {res.returncode}): {summary}"


def reload_clamd(cfg) -> tuple[bool, str]:
    if not Path(cfg.clamd_socket).exists():
        return True, "clamd läuft nicht, nichts neu zu laden"
    try:
        reply = ClamdClient(cfg.clamd_socket, timeout=30).command("RELOAD").strip("\0\n")
    except OSError as exc:
        return False, f"clamd RELOAD: {exc}"
    return reply == "RELOADING", "clamd lädt die Signaturen neu" if reply == "RELOADING" else reply


# ---------------------------------------------------------------------- YARA

def _get(url: str, accept: str = "application/octet-stream", limit: int = MAX_DOWNLOAD) -> bytes:
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": f"firebridge/{__version__}"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"Download größer als {limit // (1024 * 1024)} MB")
    return data


def download_forge(cfg, current_tag: str, force: bool) -> tuple[str, str, bool]:
    """Lädt das neueste YARA-Forge-Release. Ergebnis: (Tag, Meldung, neu geladen)."""
    rel = json.loads(_get(FORGE_API, "application/vnd.github+json", 5 * 1024 * 1024))
    tag = rel.get("tag_name", "")
    name = f"yara-forge-rules-{cfg.yara_forge_set}.zip"
    asset = next((a for a in rel.get("assets", []) if a.get("name") == name), None)
    if asset is None:
        raise ValueError(f"{name} fehlt im Release {tag}")
    source = cfg.yara_dir / f"forge-{cfg.yara_forge_set}.yar"
    if tag and tag == current_tag and source.exists() and not force:
        return tag, f"YARA Forge {tag} ist schon aktuell", False
    data = _get(asset["browser_download_url"])
    digest = hashlib.sha256(data).hexdigest()
    expected = (asset.get("digest") or "").removeprefix("sha256:")
    if expected and expected != digest:
        raise ValueError(f"Prüfsumme stimmt nicht (erwartet {expected[:16]}…, erhalten {digest[:16]}…)")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        member = next((n for n in z.namelist() if n.endswith(f"yara-rules-{cfg.yara_forge_set}.yar")), None)
        if member is None:
            raise ValueError("Regeldatei fehlt im Archiv")
        text = z.read(member)
    cfg.yara_dir.mkdir(parents=True, exist_ok=True)
    tmp = source.with_suffix(".tmp")
    tmp.write_bytes(text)
    os.replace(tmp, source)
    (cfg.yara_dir / "forge.json").write_text(json.dumps({
        "tag": tag, "set": cfg.yara_forge_set, "sha256": digest, "checked": bool(expected),
        "url": asset["browser_download_url"], "downloaded": now()}, indent=2), encoding="utf-8")
    note = "Prüfsumme geprüft" if expected else "GitHub liefert keine Prüfsumme, nur per HTTPS geladen"
    return tag, f"YARA Forge {tag} geladen ({len(data) // 1024} KB, {note})", True


def compile_yara(cfg) -> tuple[bool, str]:
    sources: list[tuple[str, str]] = []
    forge_file = cfg.yara_dir / f"forge-{cfg.yara_forge_set}.yar"
    forge_info = {}
    if forge_file.exists():
        sources.append(("forge", forge_file.read_text(encoding="utf-8", errors="replace")))
        try:
            forge_info = json.loads((cfg.yara_dir / "forge.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    custom = sorted(Path(cfg.yara_custom_dir).glob("*.yar")) + sorted(Path(cfg.yara_custom_dir).glob("*.yara"))
    for path in custom:
        sources.append((f"eigene_{path.stem}", path.read_text(encoding="utf-8", errors="replace")))
    if not sources:
        return False, "Keine YARA-Regeln vorhanden (Download fehlgeschlagen und keine eigenen Regeln)"
    rules, stats = yararules.compile_sources(sources)
    total = sum(s["rules"] for s in stats)
    if total == 0:
        return False, "Keine einzige Regel ließ sich übersetzen, alter Stand bleibt"
    skipped = [dict(s, namespace=st["namespace"]) for st in stats for s in st["skipped"]]
    forge_rules = sum(s["rules"] for s in stats if s["namespace"] == "forge")
    meta = {
        "compiled": now(),
        "yara_x": yararules.version(),
        "source": f"YARA Forge {forge_info.get('set', cfg.yara_forge_set)}" if forge_rules else "eigene Regeln",
        "source_version": forge_info.get("tag", ""),
        "rules": total,
        "forge_rules": forge_rules,
        "custom_rules": total - forge_rules,
        "custom_files": [p.name for p in custom],
        "skipped_count": len(skipped),
        "skipped": skipped[:200],
    }
    yararules.save(rules, meta, cfg.yara_dir)
    msg = f"{total} Regeln übersetzt"
    if total - forge_rules:
        msg += f" (davon {total - forge_rules} eigene)"
    if skipped:
        msg += f", {len(skipped)} mit YARA-X nicht übersetzbar und übersprungen"
    return True, msg


def update_yara(cfg, offline: bool, force: bool, status: StatusFile) -> None:
    if not yararules.available():
        status.step("YARA", False, "YARA-X (Python-Modul yara_x) ist nicht installiert")
        return
    if not offline:
        meta = {}
        try:
            meta = json.loads((cfg.yara_dir / yararules.META_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        try:
            _tag, msg, _new = download_forge(cfg, meta.get("source_version", ""), force)
            status.step("YARA Forge", True, msg)
        except Exception as exc:
            status.step("YARA Forge", False, f"Download fehlgeschlagen: {exc}")
    try:
        ok, msg = compile_yara(cfg)
    except Exception as exc:
        ok, msg = False, f"Übersetzen fehlgeschlagen: {exc}"
    status.step("YARA-X", ok, msg)


def run(cfg, offline: bool = False, force: bool = False, clamav: bool = True) -> bool:
    status = StatusFile(cfg.update_status_file)
    status.write()
    try:
        if clamav and not offline:
            status.step("ClamAV", *update_clamav(cfg))
            for name, ok, msg in extrasigs.update(cfg):
                status.step(name, ok, msg)
            status.step("clamd", *reload_clamd(cfg))
        update_yara(cfg, offline, force, status)
    except Exception as exc:  # nie mit "running" stehen bleiben
        status.step("Update", False, f"Abgebrochen: {exc}")
    return status.finish()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Firebridge: Virensignaturen und YARA-Regeln aktualisieren")
    ap.add_argument("--config", type=Path, help="Pfad zur Konfigurationsdatei")
    ap.add_argument("--offline", action="store_true", help="nichts laden, nur YARA-Regeln neu übersetzen")
    ap.add_argument("--force", action="store_true", help="YARA Forge auch laden, wenn die Version gleich ist")
    ap.add_argument("--no-clamav", action="store_true", help="ClamAV auslassen (nur YARA)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    cfg = config_mod.load(args.config)
    ok = run(cfg, args.offline, args.force, not args.no_clamav)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
