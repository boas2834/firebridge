"""Blick in ZIP-Archive: Programme, Skripte und Verschlüsseltes im Inneren.

ClamAV entpackt Archive selbst und sucht darin nach Schadsoftware. Hier geht
es um die Richtlinie: Ein harmloses setup.exe in einer ZIP-Datei ist für
ClamAV sauber, soll aber genauso behandelt werden wie ein setup.exe direkt
auf dem Stick. Geprüft werden Name und Anfang jedes Eintrags, verschachtelte
ZIPs bis zur eingestellten Tiefe. Gelesen werden nur die ersten Bytes jedes
Eintrags, ZIP-Bomben werden dadurch nicht ausgepackt.

Office- (OOXML) und LibreOffice-Dateien (ODF) sind auch ZIPs; bei ihnen
zählen nur Makros. JAR- und APK-Dateien sind Programme.
"""

from __future__ import annotations

import io
import zipfile

from . import filetype
from .hits import Hit

MAX_ENTRIES = 5000          # mehr Einträge werden nicht einzeln angesehen
HEAD_ENTRIES = 1000         # bei so vielen Einträgen wird auch der Inhalt angelesen
NESTED_MAX = 50 * 1024 * 1024
SHOW = 3                    # so viele Namen je Kategorie im Detail


def is_zip(head: bytes) -> bool:
    return head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06")


def names(fileobj) -> list[str] | None:
    try:
        with zipfile.ZipFile(fileobj) as z:
            return z.namelist()
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, NotImplementedError, EOFError):
        return None


def container_kind(namelist: list[str]) -> str:
    """"ooxml", "odf", "jar", "apk" oder "zip"."""
    lower = {n.lower() for n in namelist[:MAX_ENTRIES]}
    if "[content_types].xml" in lower:
        return "ooxml"
    if "mimetype" in lower and ("content.xml" in lower or "meta-inf/manifest.xml" in lower):
        return "odf"
    if "androidmanifest.xml" in lower and "classes.dex" in lower:
        return "apk"
    if "meta-inf/manifest.mf" in lower and any(n.endswith(".class") for n in lower):
        return "jar"
    return "zip"


def _odf_macros(namelist: list[str]) -> str:
    basic = [n for n in namelist if n.startswith("Basic/") and n.endswith(".xml")
             and n.rsplit("/", 1)[-1] not in ("script-lc.xml", "script-lb.xml", "dialog-lc.xml", "dialog-lb.xml")]
    scripts = [n for n in namelist if n.startswith("Scripts/") and not n.endswith("/")]
    if basic:
        return "LibreOffice-Basic-Makros"
    if scripts:
        return "LibreOffice-Skripte (" + scripts[0].split("/")[1] + ")"
    return ""


def analyze(fileobj, label: str, depth: int, max_depth: int) -> list[Hit]:
    """fileobj: lesbares, seekbares Dateiobjekt; label: Name für die Meldung."""
    try:
        z = zipfile.ZipFile(fileobj)
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, NotImplementedError, EOFError):
        return []   # kaputte ZIPs meldet ClamAV
    with z:
        infos = z.infolist()
        kind = container_kind([i.filename for i in infos])
        if kind == "apk":
            return [Hit("Archiv", "executable", "apk", "Android-App (APK)")]
        if kind == "jar":
            return [Hit("Archiv", "executable", "jar", "Java-Programm (JAR)")]
        if kind == "odf":
            macros = _odf_macros([i.filename for i in infos])
            return [Hit("Archiv", "macro", "odf-makro", macros)] if macros else []
        if kind == "ooxml":
            return []   # Makros findet olevba
        found: dict[str, list[str]] = {}
        _collect(z, "", label, depth, max_depth, found)
    hits = []
    encrypted = found.pop("encrypted", [])
    if encrypted:
        hits.append(Hit("Archiv", "encrypted", "zip-verschluesselt",
                        (f"Archiv mit {len(encrypted)} verschlüsselten Einträgen" if len(encrypted) > 1
                         else f"Archiv mit verschlüsseltem Eintrag ({encrypted[0]})") + ", Inhalt nicht prüfbar"))
    names_of = {"executable": "Programme", "script": "Skripte", "autostart": "Verknüpfungen",
                "macro": "Makro-Dokumente"}
    for category, entries in found.items():
        shown = ", ".join(entries[:SHOW]) + (f" und {len(entries) - SHOW} weitere" if len(entries) > SHOW else "")
        hits.append(Hit("Archiv", category, f"zip-{category}",
                        f"Archiv enthält {names_of.get(category, category)}: {shown}"))
    return hits


def _collect(z: zipfile.ZipFile, prefix: str, label: str, depth: int, max_depth: int,
             found: dict[str, list[str]]) -> None:
    """Sammelt Kategorie → Pfade im Archiv (verschachtelte als "innen.zip/datei.exe")."""
    for n, info in enumerate(z.infolist()[:MAX_ENTRIES]):
        if info.is_dir():
            continue
        path = prefix + info.filename
        if info.flag_bits & 0x1:
            found.setdefault("encrypted", []).append(path)
            continue
        head = b""
        if n < HEAD_ENTRIES:
            try:
                with z.open(info) as fh:
                    head = fh.read(4096)
            except Exception:
                head = b""
        categories = {hit.category for hit in filetype.detect(f"{label}/{path}", head)}
        if ext_is_macro(info.filename):
            categories.add("macro")
        for category in sorted(categories):
            found.setdefault(category, []).append(path)
        if depth < max_depth and is_zip(head) and info.file_size <= NESTED_MAX:
            try:
                with z.open(info) as fh:
                    data = fh.read(NESTED_MAX + 1)
                if len(data) <= NESTED_MAX:
                    with zipfile.ZipFile(io.BytesIO(data)) as inner:
                        if container_kind(inner.namelist()) == "zip":
                            _collect(inner, path + "/", label, depth + 1, max_depth, found)
            except Exception:
                pass


def ext_is_macro(name: str) -> bool:
    return filetype.ext_of(name) in filetype.MACRO_EXT
