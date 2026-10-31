"""Build-Nummer: Version, fortlaufende Commit-Nummer und Commit des installierten Stands.

install.sh schreibt beim Kopieren BUILD.json neben dieses Modul. Läuft die
Firebridge direkt aus einem Git-Klon (Entwicklung, --demo), fragt sie git selbst.
"""

from __future__ import annotations

import functools
import json
import subprocess
from pathlib import Path

from . import __version__

REPO_URL = "https://github.com/boas2834/firebridge"
BUILD_FILE = Path(__file__).with_name("BUILD.json")


def _git(*args: str) -> str:
    src = Path(__file__).resolve().parent.parent
    try:
        res = subprocess.run(["git", "-C", str(src), "-c", f"safe.directory={src}", *args],
                             capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return res.stdout.strip() if res.returncode == 0 else ""


@functools.lru_cache(maxsize=1)
def info() -> dict:
    """{"version", "build", "commit", "date"}; unbekannte Felder leer."""
    data = {}
    try:
        data = json.loads(BUILD_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        src = Path(__file__).resolve().parent.parent
        if (src / ".git").exists():
            try:   # im öffentlichen Repo fehlt der Verlauf, dort steht die Nummer fest
                number = (src / "BUILD_NUMBER").read_text(encoding="ascii").strip()
            except OSError:
                number = _git("rev-list", "--count", "HEAD")
            data = {"build": number, "commit": _git("rev-parse", "--short=7", "HEAD"),
                    "date": _git("log", "-1", "--format=%cs")}
            if data["commit"] and _git("status", "--porcelain", "--untracked-files=no"):
                data["commit"] += "+"   # mit ungespeicherten Änderungen
    out = {"version": __version__}
    for key in ("build", "commit", "date"):
        out[key] = str(data.get(key) or "") if isinstance(data, dict) else ""
    return out


def label(data: dict | None = None) -> str:
    """Kurz für Statuszeile und Info-Fenster, z. B. „Build 42 · 30.10.2026“."""
    d = data or info()
    parts = [f"Build {d['build']}" if d.get("build") else f"Version {d.get('version', '?')}"]
    if d.get("date"):
        parts.append(".".join(reversed(d["date"].split("-"))))
    return " · ".join(parts)
