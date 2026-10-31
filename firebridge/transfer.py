"""Übertragung der sauberen Dateien auf das Ziel-Share.

Regeln:
  * Übertragen wird nur, was im Prüfbericht als "clean" steht, und auffällige
    Dateien, die laut Richtlinie freigegeben werden durften und freigegeben
    wurden. Infizierte, gesperrte, nicht lesbare und übersprungene Dateien
    (Symlinks, Sonderdateien) nie.
  * Jede Datei landet zuerst unter "<name>.fbpart". Erst wenn
      - der SHA-256 beim Lesen vom Stick dem Wert aus dem Prüfbericht entspricht
        (sonst hätte sich die Datei seit dem Scan verändert) und
      - der SHA-256 beim Zurücklesen vom Share stimmt,
    wird sie in den endgültigen Namen umbenannt. Sonst wird sie gelöscht.
  * Vorhandenes auf dem Share wird nie überschrieben: Jede Übertragung bekommt
    einen eigenen Ordner (Name = Berichts-ID), Dateien werden exklusiv angelegt.
  * Zum Schluss kommt der Prüfbericht als _firebridge-bericht.json dazu.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import stat
import threading
import time
from pathlib import Path
from typing import Callable

from .share import NameMapper

CHUNK = 1024 * 1024
PARTIAL = ".fbpart"
REPORT_NAME = "_firebridge-bericht.json"


class TransferCancelled(Exception):
    pass


class FileChanged(Exception):
    pass


@dataclasses.dataclass
class PlanItem:
    rel: str                  # wie im Bericht: "sdb1/Ordner/datei.txt"
    source: Path              # Pfad im Read-only-Mount
    target: tuple[str, ...]   # relativ zum Übertragungsordner
    size: int
    sha256: str


@dataclasses.dataclass
class TransferProgress:
    phase: str = "verbinden"  # verbinden, kopieren, abschließen, trennen
    total: int = 0
    done: int = 0
    copied: int = 0
    failed: int = 0
    bytes_total: int = 0
    bytes_done: int = 0
    current: str = ""
    target: str = ""
    connection: str = ""
    started: float = 0.0

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        elapsed = time.monotonic() - self.started if self.started else 0
        d["elapsed"] = elapsed
        if self.bytes_done and self.bytes_total > self.bytes_done:
            d["eta"] = elapsed * (self.bytes_total - self.bytes_done) / self.bytes_done
        else:
            d["eta"] = None
        return d


def transferable(f: dict) -> bool:
    """Sauber, oder auffällig mit "Freigabe nötig" und freigegeben."""
    if not f.get("sha256"):
        return False
    if f.get("status") == "clean":
        return True
    return f.get("status") == "suspicious" and f.get("action") == "freigabe" and bool(f.get("released"))


def plan(report: dict, roots: dict[str, Path],
         only: set[str] | None = None) -> tuple[list[PlanItem], list[dict]]:
    """Welche Dateien werden wohin kopiert? roots: Partition ("sdb1") → Einhängepunkt.

    only: nur diese Berichtspfade (Auswahl in der Oberfläche); auch dann nur saubere oder freigegebene.
    Bei nur einer Partition fällt der Partitionsordner auf dem Share weg.
    """
    items: list[PlanItem] = []
    renamed: list[dict] = []
    mapper = NameMapper()
    single = len(roots) == 1
    for f in report.get("files", []):
        if not transferable(f):
            continue
        if only is not None and f["path"] not in only:
            continue
        label, _, rel = f["path"].partition("/")
        root = roots.get(label)
        if root is None or not rel or rel.startswith("/") or ".." in Path(rel).parts:
            continue
        target = mapper.map(rel if single else f"{label}/{rel}")
        wanted = tuple(Path(rel if single else f"{label}/{rel}").parts)
        if target != wanted:
            renamed.append({"path": f["path"], "target": "/".join(target)})
        items.append(PlanItem(f["path"], root / rel, target, int(f.get("size", 0)), f["sha256"]))
    return items, renamed


def _open_source(path: Path) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise OSError(0, "keine reguläre Datei")
    return fd


class Transfer:
    """Kopiert einen Plan über eine bereits verbundene SmbSession."""

    def __init__(self, session, items: list[PlanItem], verify: bool, cancel: threading.Event,
                 on_progress: Callable[[TransferProgress], None], log: Callable[[str], None],
                 prog: TransferProgress):
        self.session = session
        self.items = items
        self.verify = verify
        self.cancel = cancel
        self.on_progress = on_progress
        self.log = log
        self.prog = prog
        self.results: list[dict] = []
        self.folder = ""
        self._last_emit = 0.0

    def _emit(self, force: bool = False) -> None:
        now = time.monotonic()
        if force or now - self._last_emit > 0.25:
            self._last_emit = now
            self.on_progress(self.prog)

    def _check_cancel(self) -> None:
        if self.cancel.is_set():
            raise TransferCancelled()

    def run(self, folder_name: str) -> list[dict]:
        p = self.prog
        p.total = len(self.items)
        p.bytes_total = sum(i.size for i in self.items)
        self.session.makedirs(())
        self.folder = self.session.mkdir_unique(folder_name)
        p.target = self.session.settings.unc(None, self.folder)
        p.phase = "kopieren"
        self.log(f"Zielordner {p.target} angelegt")
        self._emit(True)
        made: set[tuple[str, ...]] = set()
        for item in self.items:
            self._check_cancel()
            p.current = item.rel
            start_bytes = p.bytes_done
            parent = (self.folder, *item.target[:-1])
            if parent not in made:
                self.session.makedirs(parent)
                made.add(parent)
            try:
                self._copy(item)
            except (TransferCancelled, ConnectionError):
                raise
            except FileChanged as exc:
                p.failed += 1
                self.results.append({"path": item.rel, "status": "failed", "detail": str(exc)})
                self.log(f"NICHT übertragen (verändert seit der Prüfung): {item.rel}")
            except OSError as exc:
                if not self._session_alive(exc):
                    raise
                p.failed += 1
                detail = exc.strerror or str(exc)
                self.results.append({"path": item.rel, "status": "failed", "detail": detail})
                self.log(f"Fehler bei {item.rel}: {detail}")
            else:
                p.copied += 1
                self.results.append({"path": item.rel, "status": "copied", "target": "/".join(item.target),
                                     "sha256": item.sha256})
            p.done += 1
            p.bytes_done = start_bytes + item.size
            self._emit(p.done == p.total)
        return self.results

    @staticmethod
    def _session_alive(exc: OSError) -> bool:
        # Verbindungsabbrüche brechen die ganze Übertragung ab, Dateifehler nur die Datei
        text = str(exc).lower()
        return not any(k in text for k in ("connection", "broken pipe", "reset by peer", "timed out",
                                           "network_name_deleted", "user_session_deleted"))

    def _copy(self, item: PlanItem) -> None:
        final = (self.folder, *item.target)
        part = (*final[:-1], final[-1] + PARTIAL)
        fd = _open_source(item.source)
        h = hashlib.sha256()
        written = False
        try:
            with self.session.create(part) as out:
                written = True
                while chunk := os.read(fd, CHUNK):
                    self._check_cancel()
                    h.update(chunk)
                    out.write(chunk)
                    self.prog.bytes_done += len(chunk)
                    self._emit()
            if h.hexdigest() != item.sha256:
                raise FileChanged("Inhalt weicht vom geprüften Stand ab (SHA-256)")
            if self.verify:
                remote = self.session.sha256(part, lambda: self._check_cancel() or False)
                if remote != item.sha256:
                    raise OSError(0, "SHA-256 auf dem Share stimmt nicht (Übertragungsfehler)")
            self.session.rename(part, final)
            written = False
        finally:
            os.close(fd)
            if written:
                try:
                    self.session.remove(part)
                except Exception:
                    self.log(f"Teildatei konnte nicht gelöscht werden: {'/'.join(part)}")

    def upload_report(self, report: dict) -> None:
        data = json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")
        with self.session.create((self.folder, REPORT_NAME)) as out:
            out.write(data)
