"""Blick in 7z-, RAR-, CAB- und TAR-Archive für die Richtlinie.

Für ZIP reicht Pythons zipfile (archive.py). Die übrigen Formate liest lsar aus
dem Debian-Paket unar: Es listet nur das Inhaltsverzeichnis (Namen, Größen,
verschlüsselt ja/nein) und packt nichts aus. Bewertet wird deshalb nur der Name
jedes Eintrags (setup.exe, install.ps1, Rechnung.pdf.lnk …), nicht sein Inhalt;
nach Schadsoftware im Inneren sucht ClamAV, das diese Archive selbst entpackt.

Ein Archiv, dessen Inhaltsverzeichnis selbst verschlüsselt ist (7z mit -mhe,
RAR mit -hp), lässt sich gar nicht ansehen und zählt als verschlüsselt.

lsar läuft als eigener Prozess mit Zeit- und Speichergrenze, damit ein
präpariertes Archiv die Prüfung nicht aufhalten kann.
"""

from __future__ import annotations

import json
import os
import resource
import shutil
import subprocess
import tempfile

from . import filetype
from .archive import SHOW, ext_is_macro
from .hits import Hit

LSAR = "lsar"
TIMEOUT = 60
MAX_OUTPUT = 32 * 1024 * 1024
MAX_ENTRIES = 20000

# Anfang der Datei → Formatname für Meldung und Regel
MAGIC = [
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"MSCF\x00\x00\x00\x00", "cab"),
]
TAR_EXT = ("tar", "tgz", "tbz", "tbz2", "txz", "tzst")
COMPRESSED_TAR = (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst")
LABEL = {"7z": "7z-Archiv", "rar": "RAR-Archiv", "cab": "CAB-Archiv", "tar": "TAR-Archiv"}


def available() -> bool:
    return shutil.which(LSAR) is not None


def kind(name: str, head: bytes) -> str:
    """"7z", "rar", "cab", "tar" oder "" (kein Archiv, das hier angesehen wird; ZIP macht archive.py)."""
    for magic, fmt in MAGIC:
        if head.startswith(magic):
            return fmt
    if head[257:262] == b"ustar":
        return "tar"
    lower = name.lower()
    if lower.endswith(COMPRESSED_TAR) or filetype.ext_of(name) in TAR_EXT:
        return "tar"
    return ""


def _limits() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT, TIMEOUT))


def listing(path: str, pass_fds: tuple = ()) -> tuple[list[tuple[str, bool]], bool, str]:
    """Inhaltsverzeichnis: ([(Name, verschlüsselt)], Verzeichnis selbst verschlüsselt, Fehler)."""
    try:
        res = subprocess.run([LSAR, "-j", path], stdin=subprocess.DEVNULL, capture_output=True,
                             timeout=TIMEOUT, pass_fds=pass_fds, preexec_fn=_limits)
    except FileNotFoundError:
        return [], False, "lsar fehlt (Paket unar)"
    except subprocess.TimeoutExpired:
        return [], False, "Zeitlimit beim Lesen des Inhaltsverzeichnisses"
    out = res.stdout[:MAX_OUTPUT]
    text = out.decode("utf-8", "replace")
    if "requires a password" in text or "requires a password" in res.stderr.decode("utf-8", "replace"):
        return [], True, ""
    start = text.find("{")
    try:
        data = json.loads(text[start:]) if start >= 0 else {}
    except ValueError:
        return [], False, "Inhaltsverzeichnis nicht lesbar"
    entries = []
    for e in (data.get("lsarContents") or [])[:MAX_ENTRIES]:
        if not isinstance(e, dict) or e.get("XADIsDirectory") or not e.get("XADFileName"):
            continue
        entries.append((str(e["XADFileName"]), bool(e.get("XADIsEncrypted"))))
    if not entries and data.get("lsarError"):
        return [], False, "Archiv beschädigt oder unbekanntes Format"
    return entries, False, ""


def judge(fmt: str, entries: list[tuple[str, bool]], header_encrypted: bool, label: str) -> list[Hit]:
    """Treffer wie bei ZIP: Programme, Skripte, Verknüpfungen, Makros und Verschlüsseltes im Archiv."""
    what = LABEL.get(fmt, "Archiv")
    if header_encrypted:
        return [Hit("Archiv", "encrypted", f"{fmt}-verschluesselt",
                    f"{what} mit verschlüsseltem Inhaltsverzeichnis, Inhalt nicht prüfbar")]
    found: dict[str, list[str]] = {}
    for name, encrypted in entries:
        if encrypted:
            found.setdefault("encrypted", []).append(name)
            continue
        categories = {hit.category for hit in filetype.detect(f"{label}/{name}", b"")}
        if ext_is_macro(name):
            categories.add("macro")
        for category in sorted(categories):
            found.setdefault(category, []).append(name)
    hits = []
    encrypted = found.pop("encrypted", [])
    if encrypted:
        hits.append(Hit("Archiv", "encrypted", f"{fmt}-verschluesselt",
                        (f"{what} mit {len(encrypted)} verschlüsselten Einträgen" if len(encrypted) > 1
                         else f"{what} mit verschlüsseltem Eintrag ({encrypted[0]})") + ", Inhalt nicht prüfbar"))
    names_of = {"executable": "Programme", "script": "Skripte", "autostart": "Verknüpfungen",
                "macro": "Makro-Dokumente"}
    for category, names in found.items():
        shown = ", ".join(names[:SHOW]) + (f" und {len(names) - SHOW} weitere" if len(names) > SHOW else "")
        hits.append(Hit("Archiv", category, f"{fmt}-{category}",
                        f"{what} enthält {names_of.get(category, category)}: {shown}"))
    return hits


def analyze(fd: int, name: str, head: bytes) -> tuple[list[Hit], str]:
    """Treffer und ggf. ein Hinweis für eine geöffnete Datei (fd)."""
    fmt = kind(name, head)
    if not fmt:
        return [], ""
    if not available():
        return [], f"{LABEL[fmt]}: Inhalt nicht angesehen (lsar fehlt, Paket unar installieren)"
    # lsar erkennt manche Formate (tar.gz) am Namen: Verweis mit dem echten Dateinamen auf die offene Datei
    base = name.rsplit("/", 1)[-1]
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in base)[-120:] or "archiv"
    with tempfile.TemporaryDirectory(prefix="firebridge-lsar-") as tmp:
        link = os.path.join(tmp, safe)
        os.symlink(f"/proc/{os.getpid()}/fd/{fd}", link)
        entries, header_encrypted, error = listing(link, pass_fds=(fd,))
    if error:
        return [], f"{LABEL[fmt]}: {error}"
    return judge(fmt, entries, header_encrypted, name.rsplit("/", 1)[-1]), ""
