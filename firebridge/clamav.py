"""Anbindung an ClamAV.

Bevorzugt wird clamd über seinen Unix-Socket. Die Dateien werden per
FILDES übergeben: der Dienst öffnet die Datei selbst und reicht nur den
Dateideskriptor weiter. clamd braucht dadurch keine Leserechte auf den
Mount und sieht ihn auch gar nicht (privater Mount-Namespace).

Läuft clamd nicht, wird clamscan als Ersatz benutzt. Das ist langsamer,
weil clamscan die Signaturen bei jedem Aufruf neu lädt.
"""

from __future__ import annotations

import array
import dataclasses
import datetime as dt
import email.utils
import os
import socket
import subprocess
from pathlib import Path
from typing import Iterable, Iterator


@dataclasses.dataclass
class Verdict:
    status: str          # "clean", "infected" oder "error"
    signature: str = ""  # Name der Signatur oder Fehlermeldung


@dataclasses.dataclass
class EngineInfo:
    backend: str            # "clamd", "clamscan" oder "" (nicht verfügbar)
    engine: str = ""        # z. B. "ClamAV 1.4.3"
    db_version: str = ""    # daily-Version
    db_time: str = ""       # ISO-Zeit der Signaturen
    available: bool = False
    message: str = ""

    def age_hours(self, now: dt.datetime | None = None) -> float | None:
        if not self.db_time:
            return None
        now = now or dt.datetime.now(dt.timezone.utc)
        return (now - dt.datetime.fromisoformat(self.db_time)).total_seconds() / 3600

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["age_hours"] = self.age_hours()
        return d


def parse_version(text: str) -> tuple[str, str, str]:
    """"ClamAV 1.4.3/27801/Tue Oct 28 07:50:01 2026" → (engine, daily, ISO-Zeit)."""
    text = text.strip().rstrip("\0")
    parts = text.split("/", 2)
    engine = parts[0]
    daily = parts[1] if len(parts) > 1 else ""
    when = ""
    if len(parts) > 2:
        try:
            # ctime-Format; clamd gibt lokale Zeit aus
            parsed = dt.datetime.strptime(parts[2].strip(), "%a %b %d %H:%M:%S %Y")
            when = parsed.astimezone().astimezone(dt.timezone.utc).isoformat()
        except ValueError:
            try:
                when = email.utils.parsedate_to_datetime(parts[2]).isoformat()
            except (TypeError, ValueError):
                when = ""
    return engine, daily, when


def parse_reply(reply: str) -> Verdict:
    """Antwort von clamd, z. B. "fd[10]: Eicar-Signature FOUND"."""
    reply = reply.strip().rstrip("\0")
    _, _, result = reply.rpartition(": ")
    if result == "OK":
        return Verdict("clean")
    if result.endswith(" FOUND"):
        sig = result[: -len(" FOUND")]
        if sig.startswith("Heuristics.Limits.Exceeded"):
            # AlertExceedsMax: Datei war zu groß oder zu tief verschachtelt
            return Verdict("error", f"nicht vollständig geprüft ({sig})")
        return Verdict("infected", sig)
    if result.endswith(" ERROR"):
        return Verdict("error", result[: -len(" ERROR")])
    return Verdict("error", reply or "leere Antwort von clamd")


class ClamdClient:
    def __init__(self, socket_path: Path, timeout: float = 300.0):
        self.socket_path = str(socket_path)
        self.timeout = timeout

    def _connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        return sock

    @staticmethod
    def _recv_all(sock: socket.socket) -> str:
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if data.endswith(b"\0"):
                break
        return b"".join(chunks).decode("utf-8", "replace")

    def command(self, cmd: str) -> str:
        with self._connect() as sock:
            sock.sendall(b"z" + cmd.encode() + b"\0")
            return self._recv_all(sock)

    def ping(self) -> bool:
        try:
            return self.command("PING").strip("\0\n") == "PONG"
        except OSError:
            return False

    def version(self) -> str:
        return self.command("VERSION")

    def scan_fd(self, fd: int) -> Verdict:
        with self._connect() as sock:
            sock.sendall(b"zFILDES\0")
            sock.sendmsg([b"\0"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
            return parse_reply(self._recv_all(sock))


def clamscan_version(binary: str = "clamscan") -> str:
    res = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=30)
    return res.stdout.strip()


def clamscan_files(paths: Iterable[str], binary: str = "clamscan",
                   db_dir: Path | None = None) -> Iterator[tuple[str, Verdict]]:
    """Ersatzweg ohne clamd: ein clamscan-Prozess für eine Dateiliste.

    Liefert (Pfad, Ergebnis) in der Reihenfolge, in der clamscan prüft.
    """
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".lst", delete=False) as lst:
        for p in paths:
            lst.write(p + "\n")
        list_file = lst.name
    cmd = [binary, "--no-summary", "--stdout", "--follow-dir-symlinks=0",
           "--follow-file-symlinks=0", "--alert-encrypted-archive=yes", f"--file-list={list_file}"]
    if db_dir:
        cmd.append(f"--database={db_dir}")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                errors="replace")
        assert proc.stdout
        for line in proc.stdout:
            line = line.rstrip("\n")
            path, sep, _ = line.rpartition(": ")
            if not sep:
                continue
            yield path, parse_reply(line)
        proc.wait()
    finally:
        os.unlink(list_file)


def _db_files(db_dir: Path) -> list[Path]:
    try:
        return [p for p in db_dir.iterdir()
                if p.suffix in (".cvd", ".cld", ".cud", ".hdb", ".hsb", ".ndb", ".ldb", ".yar", ".yara")]
    except OSError:
        return []


def _db_time_from_files(db_dir: Path) -> str:
    """Ersatz, wenn die Version keine Zeit enthält: Änderungszeit von daily.*"""
    files = [p for p in _db_files(db_dir) if p.stem == "daily"] or _db_files(db_dir)
    if not files:
        return ""
    mtime = max(p.stat().st_mtime for p in files)
    return dt.datetime.fromtimestamp(mtime, dt.timezone.utc).isoformat()


def engine_info(client: ClamdClient | None, backend: str, clamscan_binary: str,
                db_dir: Path = Path("/var/lib/clamav")) -> EngineInfo:
    """Fragt ab, welche Engine bereit ist und wie alt die Signaturen sind."""
    if backend in ("auto", "clamd") and client is not None:
        try:
            engine, daily, when = parse_version(client.version())
            return EngineInfo("clamd", engine, daily, when or _db_time_from_files(db_dir), True,
                              "clamd aktiv")
        except OSError as exc:
            if backend == "clamd":
                return EngineInfo("", message=f"clamd nicht erreichbar: {exc}")
    try:
        engine, daily, when = parse_version(clamscan_version(clamscan_binary))
    except (OSError, subprocess.SubprocessError) as exc:
        return EngineInfo("", message=f"Kein ClamAV gefunden: {exc}")
    if not _db_files(db_dir):
        return EngineInfo("clamscan", engine, message=f"Keine Signaturen in {db_dir} (freshclam ausführen)")
    msg = "clamd nicht erreichbar, nutze clamscan (langsamer)" if backend == "auto" else "clamscan"
    return EngineInfo("clamscan", engine, daily, when or _db_time_from_files(db_dir), True, msg)
