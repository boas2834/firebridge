"""Tiefenprüfung (Etappe 3): Dateityp, Makros, PDF, Archiv-Inhalt und YARA-X.

Läuft für jede Datei zusätzlich zu ClamAV, auf demselben Dateideskriptor,
den der Scanner schon geöffnet hat. Gelesen wird nur mit pread, die
Dateiposition (die clamd beim FILDES-Scan mitbenutzt) bleibt unberührt.
Ein Fehler in einem Baustein bricht die Prüfung nicht ab, er steht als
Hinweis im Bericht.
"""

from __future__ import annotations

import io
import os
from pathlib import Path

from . import archive, filetype, office, otherarchive, pdf, yararules
from .hits import Hit
from .yararules import YaraEngine

HEAD = 64 * 1024


class PreadFile(io.RawIOBase):
    """Dateiobjekt über einen fremden Deskriptor, mit eigener Position (für zipfile)."""

    def __init__(self, fd: int, size: int):
        self.fd = fd
        self.size = size
        self.pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        data = os.pread(self.fd, len(b), self.pos)
        b[:len(data)] = data
        self.pos += len(data)
        return len(data)

    def seek(self, offset: int, whence: int = 0) -> int:
        base = {0: 0, 1: self.pos, 2: self.size}[whence]
        self.pos = max(0, base + offset)
        return self.pos

    def tell(self) -> int:
        return self.pos


class Analyzer:
    def __init__(self, yara_dir: Path, yara_timeout: int = 60, yara_max_mb: int = 256,
                 office_max_mb: int = 100, archive_depth: int = 2):
        self.yara = YaraEngine(yara_dir, yara_timeout, yara_max_mb * 1024 * 1024)
        self.office_max = office_max_mb * 1024 * 1024
        self.archive_depth = archive_depth

    def prepare(self) -> None:
        """Vor jeder Prüfung: neue YARA-Regeln übernehmen, falls das Update welche gebracht hat."""
        self.yara.reload_if_changed()

    def analyze(self, fd: int, name: str, size: int) -> tuple[list[Hit], list[str]]:
        """Treffer und Hinweise für eine geöffnete Datei. name = Pfad im Bericht."""
        hits: list[Hit] = []
        notes: list[str] = []
        head = os.pread(fd, HEAD, 0)

        def step(label: str, fn):
            try:
                fn()
            except Exception as exc:  # ein Baustein darf die Prüfung nicht abbrechen
                notes.append(f"{label}: Fehler bei der Auswertung ({exc.__class__.__name__}: {exc})")

        step("Dateityp", lambda: hits.extend(filetype.detect(name, head)))
        zip_names = None
        if archive.is_zip(head):
            def zip_step():
                nonlocal zip_names
                zip_names = archive.names(io.BufferedReader(PreadFile(fd, size)))
                found = archive.analyze(io.BufferedReader(PreadFile(fd, size)), name.rsplit("/", 1)[-1],
                                        0, self.archive_depth)
                if any(h.rule in ("jar", "apk") for h in found):  # nicht doppelt: ".jar" + "Java-Programm"
                    hits[:] = [h for h in hits if h.category != "executable"]
                hits.extend(found)
            step("Archiv", zip_step)
        elif otherarchive.kind(name, head):
            def other_step():
                found, note = otherarchive.analyze(fd, name, head)
                hits.extend(found)
                if note:
                    notes.append(note)
            step("Archiv", other_step)
        if office.available() and office.looks_like_office(name, head, zip_names):
            if size > self.office_max:
                notes.append(f"olevba: übersprungen (größer als {self.office_max // (1024 * 1024)} MB)")
            else:
                def office_step():
                    found, note = office.analyze(name, _read_all(fd, size))
                    hits.extend(found)
                    if note:
                        notes.append(note)
                step("olevba", office_step)
        if pdf.is_pdf(head):
            step("PDF", lambda: hits.extend(pdf.analyze(lambda off, n: os.pread(fd, n, off), size)))
        if self.yara.ready:
            def yara_step():
                found, note = self.yara.scan_path(f"/proc/self/fd/{fd}", size)
                hits.extend(found)
                if note:
                    notes.append(note)
            step("YARA", yara_step)
        return hits, notes

    def info(self) -> dict:
        return {"yara": self.yara.info(), "olevba": office.available(), "magic": filetype.magic_available(),
                "lsar": otherarchive.available()}

    def fingerprint(self) -> dict:
        """Alles, was das Ergebnis beeinflusst (für den Zwischenspeicher). Nach prepare() aufrufen."""
        y = self.yara
        return {"yara_rules": y._mtime if y.ready else None, "yara_compiled": (y.meta or {}).get("compiled", ""),
                "yara_x": yararules.version(), "yara_timeout": y.timeout, "yara_max": y.max_bytes,
                "office_max": self.office_max, "archive_depth": self.archive_depth,
                "olevba": office.available(), "magic": filetype.magic_available(),
                "lsar": otherarchive.available()}


def _read_all(fd: int, size: int) -> bytes:
    chunks, pos = [], 0
    while pos < size:
        chunk = os.pread(fd, min(8 * 1024 * 1024, size - pos), pos)
        if not chunk:
            break
        chunks.append(chunk)
        pos += len(chunk)
    return b"".join(chunks)


__all__ = ["Analyzer", "Hit", "PreadFile"]
