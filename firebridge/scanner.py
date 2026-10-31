"""Prüft alle Dateien der eingebundenen Partitionen.

Sicherheitsregeln beim Durchlaufen:
  * Symlinks werden nie verfolgt (ein ext4-Stick könnte auf /etc zeigen),
  * Dateien werden mit O_NOFOLLOW|O_NONBLOCK geöffnet und per fstat geprüft,
    damit FIFOs oder Gerätedateien den Scan nicht blockieren,
  * SHA-256 jeder Datei landet im Bericht (Grundlage für Etappe 2).

Ab Etappe 3 läuft nach ClamAV die Tiefenprüfung (firebridge.analysis) auf
demselben Deskriptor. Ihre Treffer bewertet die Richtlinie: "blockieren" und
"freigabe" machen die Datei "suspicious" (auffällig), "zulassen" lässt sie
sauber und vermerkt den Treffer nur.

Mit einem Zwischenspeicher (firebridge.cache) übernimmt der Scanner für schon
bekannte Inhalte das Ergebnis der letzten Prüfung, statt ClamAV und
Tiefenprüfung erneut laufen zu lassen. Gehasht wird trotzdem jede Datei.
"""

from __future__ import annotations

import concurrent.futures as cf
import dataclasses
import hashlib
import os
import stat
import threading
import time
from pathlib import Path
from typing import Callable, Iterable

from . import policy as policy_mod
from .analysis import Analyzer, Hit
from .cache import ScanCache
from .clamav import ClamdClient, Verdict, clamscan_files


@dataclasses.dataclass
class FileResult:
    path: str            # relativ, mit Partition vorangestellt: "sdb1/Ordner/datei.txt"
    size: int = 0
    sha256: str = ""
    status: str = ""     # clean, suspicious, infected, error, skipped
    detail: str = ""
    hits: list = dataclasses.field(default_factory=list)    # Treffer der Tiefenprüfung (dicts)
    action: str = ""     # nach Richtlinie: blockieren, freigabe, zulassen ("" = keine Treffer)
    notes: list = dataclasses.field(default_factory=list)   # Hinweise, z. B. "YARA: Zeitlimit"
    cached: bool = False # Ergebnis aus dem Zwischenspeicher übernommen

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class Progress:
    total: int = 0
    done: int = 0
    infected: int = 0
    errors: int = 0
    skipped: int = 0
    bytes_total: int = 0
    bytes_done: int = 0
    current: str = ""
    started: float = 0.0
    suspicious: int = 0
    # Dateien mit Treffern je Baustein ("YARA-X", "Dateityp", "Archiv", "olevba", "PDF", "ClamAV")
    engine_hits: dict = dataclasses.field(default_factory=dict)
    cached: int = 0         # Dateien, deren Ergebnis aus dem Zwischenspeicher kam
    phase: str = "prüfen"   # "sammeln" (Dateien werden gesucht) oder "prüfen"

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        elapsed = time.monotonic() - self.started if self.started else 0
        d["elapsed"] = elapsed
        if self.bytes_done and self.bytes_total > self.bytes_done:
            d["eta"] = elapsed * (self.bytes_total - self.bytes_done) / self.bytes_done
        else:
            d["eta"] = None
        return d


@dataclasses.dataclass
class Entry:
    root: Path
    rel: str
    size: int


class Cancelled(Exception):
    pass


def collect(roots: Iterable[tuple[str, Path]],
            on_found: Callable[[int, str], None] | None = None) -> tuple[list[Entry], list[FileResult]]:
    """Sammelt reguläre Dateien. Symlinks und Sonderdateien werden protokolliert.

    on_found(anzahl, ordner) meldet zwischendurch den Stand (große Sticks brauchen dafür eine Weile).
    """
    entries: list[Entry] = []
    skipped: list[FileResult] = []
    for label, root in roots:
        def onerror(err: OSError, label=label, root=root):
            rel = os.path.relpath(err.filename or str(root), root)
            skipped.append(FileResult(f"{label}/{rel}", status="error",
                                      detail=f"Ordner nicht lesbar: {err.strerror}"))

        for dirpath, dirnames, filenames in os.walk(root, onerror=onerror, followlinks=False):
            if on_found:
                on_found(len(entries), f"{label}/{os.path.relpath(dirpath, root)}")
            for name in dirnames:
                full = os.path.join(dirpath, name)
                if os.path.islink(full):
                    rel = os.path.relpath(full, root)
                    skipped.append(FileResult(f"{label}/{rel}", status="skipped",
                                              detail=f"Symlink → {_readlink(full)} (nicht verfolgt)"))
            for name in filenames:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root)
                try:
                    st = os.lstat(full)
                except OSError as exc:
                    skipped.append(FileResult(f"{label}/{rel}", status="error", detail=exc.strerror or str(exc)))
                    continue
                if stat.S_ISLNK(st.st_mode):
                    skipped.append(FileResult(f"{label}/{rel}", status="skipped",
                                              detail=f"Symlink → {_readlink(full)} (nicht verfolgt)"))
                elif not stat.S_ISREG(st.st_mode):
                    skipped.append(FileResult(f"{label}/{rel}", status="skipped", detail="Sonderdatei"))
                else:
                    entries.append(Entry(root, rel, st.st_size))
    return entries, skipped


def _readlink(path: str) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return "?"


def _open_and_hash(path: Path) -> tuple[int, str, int]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(0, "keine reguläre Datei")
        h = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            h.update(chunk)
        os.lseek(fd, 0, os.SEEK_SET)
        return fd, h.hexdigest(), st.st_size
    except BaseException:
        os.close(fd)
        raise


def make_result(name: str, size: int, digest: str, verdict: Verdict, hits: list[Hit], notes: list[str],
                policy: dict[str, str]) -> FileResult:
    """ClamAV-Ergebnis und Treffer der Tiefenprüfung zu einem Dateiergebnis zusammenführen."""
    hits = list(hits)
    if verdict.status == "infected" and verdict.signature.startswith("Heuristics.Encrypted"):
        # AlertEncryptedArchive: kein Virus, aber nicht prüfbar → Richtlinie "verschlüsselt"
        hits.insert(0, Hit("ClamAV", "encrypted", verdict.signature,
                           f"Verschlüsselt, Inhalt nicht prüfbar ({verdict.signature})"))
        verdict = Verdict("clean")
    hit_dicts = [{**h.to_dict(), "action": policy.get(h.category, "blockieren")} for h in hits]
    action = policy_mod.decide(hit_dicts, policy)
    if verdict.status in ("infected", "error"):
        return FileResult(name, size, digest, verdict.status, verdict.signature, hit_dicts, action, notes)
    if action in ("blockieren", "freigabe"):
        shown = [h["detail"] for h in hit_dicts if h["action"] != "zulassen"]
        detail = "; ".join(dict.fromkeys(shown))
        return FileResult(name, size, digest, "suspicious", detail, hit_dicts, action, notes)
    return FileResult(name, size, digest, "clean", "", hit_dicts, action, notes)


class Scanner:
    def __init__(self, backend: str, client: ClamdClient | None = None, workers: int = 4,
                 clamscan_binary: str = "clamscan", db_dir: Path | None = None,
                 analyzer: Analyzer | None = None, policy: dict[str, str] | None = None,
                 cache: ScanCache | None = None):
        self.backend = backend
        self.client = client
        self.workers = max(1, workers)
        self.clamscan_binary = clamscan_binary
        self.db_dir = db_dir
        self.analyzer = analyzer
        self.policy = policy or policy_mod.defaults()
        self.cache = cache if cache is not None and cache.enabled else None

    def _deep(self, fd: int, name: str, size: int) -> tuple[list[Hit], list[str]]:
        if self.analyzer is None:
            return [], []
        return self.analyzer.analyze(fd, name, size)

    def _cached(self, digest: str, name: str):
        return self.cache.get(ScanCache.key(digest, name)) if self.cache is not None else None

    def _remember(self, digest: str, name: str, verdict: Verdict, hits: list[Hit], notes: list[str]) -> None:
        if self.cache is not None:
            self.cache.put(ScanCache.key(digest, name), verdict, hits, notes)

    def run(self, roots: list[tuple[str, Path]], cancel: threading.Event,
            on_progress: Callable[[Progress], None],
            on_finding: Callable[[FileResult], None]) -> tuple[list[FileResult], Progress]:
        prog = Progress(started=time.monotonic(), phase="sammeln")
        on_progress(prog)
        if self.analyzer is not None:
            self.analyzer.prepare()

        def found(n: int, where: str) -> None:
            if cancel.is_set():
                raise Cancelled()
            prog.total, prog.current = n, where
            on_progress(prog)

        entries, results = collect(roots, found)
        prog.phase = "prüfen"
        prog.current = ""
        label_of = {root: label for label, root in roots}
        prog.total = len(entries)
        prog.bytes_total = sum(e.size for e in entries)
        prog.skipped = sum(1 for r in results if r.status == "skipped")
        prog.errors = sum(1 for r in results if r.status == "error")
        for r in results:
            if r.status == "error":
                on_finding(r)
        on_progress(prog)
        lock = threading.Lock()

        def record(res: FileResult, size: int):
            with lock:
                results.append(res)
                prog.done += 1
                prog.bytes_done += size
                prog.current = res.path
                if res.status == "infected":
                    prog.infected += 1
                elif res.status == "error":
                    prog.errors += 1
                elif res.status == "suspicious":
                    prog.suspicious += 1
                if res.cached:
                    prog.cached += 1
                for engine in {h["engine"] for h in res.hits}:
                    prog.engine_hits[engine] = prog.engine_hits.get(engine, 0) + 1
            if res.status in ("infected", "error", "suspicious"):
                on_finding(res)
            on_progress(prog)

        if self.backend == "clamd":
            self._run_clamd(entries, label_of, cancel, record)
        else:
            self._run_clamscan(entries, label_of, cancel, record)
        if cancel.is_set():
            raise Cancelled()
        return results, prog

    def _run_clamd(self, entries, label_of, cancel, record):
        def work(e: Entry) -> None:
            if cancel.is_set():
                return
            name = f"{label_of[e.root]}/{e.rel}"
            full = e.root / e.rel
            try:
                fd, digest, size = _open_and_hash(full)
            except OSError as exc:
                record(FileResult(name, e.size, status="error", detail=exc.strerror or str(exc)), e.size)
                return
            try:
                hit = self._cached(digest, name)
                if hit is None:
                    try:
                        verdict = self.client.scan_fd(fd)
                    except OSError as exc:
                        verdict = Verdict("error", f"clamd: {exc}")
                    hits, notes = self._deep(fd, name, size)
                    self._remember(digest, name, verdict, hits, notes)
                else:
                    verdict, hits, notes = hit
            finally:
                os.close(fd)
            res = make_result(name, size, digest, verdict, hits, notes, self.policy)
            res.cached = hit is not None
            record(res, size)

        with cf.ThreadPoolExecutor(self.workers, thread_name_prefix="scan") as pool:
            for fut in cf.as_completed([pool.submit(work, e) for e in entries]):
                fut.result()
                if cancel.is_set():
                    pool.shutdown(wait=True, cancel_futures=True)
                    return

    def _run_clamscan(self, entries, label_of, cancel, record):
        by_path = {str(e.root / e.rel): e for e in entries}
        pre: dict[str, tuple[str, list[Hit], list[str]]] = {}
        known: dict[str, tuple[str, Verdict, list[Hit], list[str]]] = {}

        def prepare(p: str, e: Entry) -> None:
            # Hashen und Tiefenprüfung vorab, clamscan prüft danach die ganze Liste
            if cancel.is_set():
                return
            name = f"{label_of[e.root]}/{e.rel}"
            try:
                fd, digest, size = _open_and_hash(Path(p))
            except OSError:
                pre[p] = ("", [], [])
                return
            try:
                hit = self._cached(digest, name)
                if hit is not None:
                    known[p] = (digest, *hit)
                    return
                hits, notes = self._deep(fd, name, size)
            finally:
                os.close(fd)
            pre[p] = (digest, hits, notes)

        with cf.ThreadPoolExecutor(self.workers, thread_name_prefix="prep") as pool:
            for fut in cf.as_completed([pool.submit(prepare, p, e) for p, e in by_path.items()]):
                fut.result()
        if cancel.is_set():
            return
        for path, (digest, verdict, hits, notes) in known.items():
            e = by_path.pop(path)
            res = make_result(f"{label_of[e.root]}/{e.rel}", e.size, digest, verdict, hits, notes, self.policy)
            res.cached = True
            record(res, e.size)
        seen = set()
        for path, verdict in (clamscan_files(by_path, self.clamscan_binary, self.db_dir) if by_path else ()):
            if cancel.is_set():
                return
            e = by_path.get(path)
            if e is None or path in seen:
                continue
            seen.add(path)
            digest, hits, notes = pre.get(path, ("", [], []))
            if digest:
                self._remember(digest, f"{label_of[e.root]}/{e.rel}", verdict, hits, notes)
            record(make_result(f"{label_of[e.root]}/{e.rel}", e.size, digest, verdict, hits, notes, self.policy),
                   e.size)
        for path, e in by_path.items():
            if path not in seen:
                record(FileResult(f"{label_of[e.root]}/{e.rel}", e.size, pre.get(path, ("",))[0],
                                  "error", "von clamscan nicht gemeldet"), e.size)
