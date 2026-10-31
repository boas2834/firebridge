"""Optionale zweite Meinung von VirusTotal (REST API v3).

Vier Stufen, eingestellt in der Oberfläche (Einstellungen → VirusTotal):

  aus      nichts verlässt die Firebridge (Standard)
  manuell  nach dem Scan wird nichts automatisch gefragt; erst auf Knopfdruck
           werden ausgewählte Dateien abgefragt oder hochgeladen
  hash     nur der SHA-256 der interessanten Dateien wird abgefragt
  upload   wie "hash"; zusätzlich lassen sich Dateien, die VirusTotal nicht
           kennt, hochladen – nur auf Knopfdruck, mit Auswahl und Warnhinweis

"Interessant" sind Dateien mit Treffern der Tiefenprüfung (Programme, Skripte,
Makros, PDF-Aktionen, Autostart, YARA, auch zugelassene) und Archive. Saubere
Fotos und Dokumente gehen nie raus, infizierte auch nicht (ClamAV ist da
schon sicher).

Lizenz: Die kostenlose Public API ist nur für nicht-kommerzielle Nutzung
erlaubt. Wer sie einschaltet, muss das in der Oberfläche bestätigen; die
Bestätigung steht mit Uhrzeit in virustotal.json und in jedem Bericht. Für
den Einsatz in der Firma braucht es eine Premium-Lizenz.

Netz: wie bei SMB öffnet der Dienst das nftables-Fenster nur für die Dauer der
Abfrage und nur zu den IPs von www.virustotal.com auf tcp/443. TLS prüft das
Zertifikat gegen den System-CA-Store. Der API-Key liegt in
/var/lib/firebridge/virustotal.key (0600) und erscheint nie im Status, im
Protokoll oder im Bericht.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import http.client
import json
import os
import socket
import ssl
import stat
import time
import urllib.parse
import uuid
from collections import deque
from pathlib import Path
from typing import Callable, Iterable

HOST = "www.virustotal.com"
PORT = 443
API = "/api/v3"
GUI_LINK = "https://www.virustotal.com/gui/file/{}"
DIRECT_UPLOAD_MAX = 32 * 1024 * 1024   # größere Dateien über eine eigene Upload-URL
CHUNK = 1024 * 1024
# SHA-256 der EICAR-Testdatei: VirusTotal kennt sie sicher, gut für "Verbindung testen"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

MODES = ("aus", "manuell", "hash", "upload")
MODE_LABELS = {"aus": "aus", "manuell": "Manuell", "hash": "Hash", "upload": "Upload"}
# Stufen, in denen sich Dateien (nach Auswahl und Warnhinweis) hochladen lassen
UPLOAD_MODES = ("manuell", "upload")
LICENSES = ("public", "premium")
ARCHIVE_SUFFIXES = (".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab", ".iso", ".img")
NONCOMMERCIAL_TEXT = ("Ich bestätige, dass diese Firebridge mit der kostenlosen Public API von VirusTotal "
                      "nur privat bzw. nicht-kommerziell genutzt wird (Nutzungsbedingungen von VirusTotal).")


class VtError(RuntimeError):
    pass


class QuotaExhausted(VtError):
    pass


class VtCancelled(Exception):
    pass


# ---------------------------------------------------------------- Einstellungen

@dataclasses.dataclass
class VtSettings:
    mode: str = "aus"
    # "public" = kostenlose API (nur nicht-kommerziell), "premium" = bezahlte Lizenz, "" = noch nicht gewählt
    license: str = ""
    license_confirmed: str = ""     # Zeitpunkt der Bestätigung (ISO)
    threshold: int = 3              # ab so vielen "malicious"-Meldungen gilt die Datei als gefährlich
    block_on_error: bool = False    # VirusTotal nicht erreichbar → Übertragung sperren

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def validate(data: dict, allow_upload: bool = True) -> VtSettings:
    known = {f.name for f in dataclasses.fields(VtSettings)}
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"Unbekannte VirusTotal-Einstellung: {sorted(unknown)[0]}")
    s = VtSettings(**data)
    if s.mode not in MODES:
        raise ValueError(f"Stufe muss {', '.join(MODES)} sein, nicht {s.mode!r}")
    if s.license not in ("", *LICENSES):
        raise ValueError(f"Lizenz muss public oder premium sein, nicht {s.license!r}")
    if s.mode == "upload" and not allow_upload:
        raise ValueError("Upload ist gesperrt (virustotal.allow_upload = false in firebridge.toml)")
    if s.mode != "aus" and not s.license:
        raise ValueError("Bitte angeben, mit welcher Lizenz VirusTotal genutzt wird")
    if s.mode != "aus" and s.license == "public" and not s.license_confirmed:
        raise ValueError("Die kostenlose Public API ist nur für nicht-kommerzielle Nutzung erlaubt. "
                         "Bitte die Nutzung bestätigen oder eine Premium-Lizenz wählen.")
    s.threshold = int(s.threshold)
    if not 1 <= s.threshold <= 50:
        raise ValueError("Schwelle muss zwischen 1 und 50 Engines liegen")
    s.block_on_error = bool(s.block_on_error)
    return s


@dataclasses.dataclass
class VtLimits:
    """Feste Grenzen aus firebridge.toml ([virustotal])."""
    allow_upload: bool = True
    editable: bool = True
    requests_per_minute: int = 4       # Public API: 4/min
    daily_limit: int = 500             # Public API: 500/Tag
    premium_requests_per_minute: int = 0   # 0 = keine eigene Drossel
    premium_daily_limit: int = 0
    window_minutes: int = 15           # so lange darf das Netzwerk-Fenster höchstens offen sein
    analysis_wait: int = 300           # nach einem Upload so lange auf das Ergebnis warten (s)
    max_upload_mb: int = 650
    timeout: float = 60.0


SETTING_KEYS = {f.name for f in dataclasses.fields(VtSettings)}
LIMIT_KEYS = {f.name for f in dataclasses.fields(VtLimits)}


def split_config(data: dict) -> tuple[dict, VtLimits]:
    """[virustotal] aus firebridge.toml: Startwerte der Einstellungen und feste Grenzen."""
    data = dict(data or {})
    unknown = set(data) - SETTING_KEYS - LIMIT_KEYS
    if unknown:
        raise ValueError(f"Unbekannte Einstellung unter [virustotal]: {sorted(unknown)[0]}")
    limits = VtLimits(**{k: data.pop(k) for k in list(data) if k in LIMIT_KEYS})
    return data, limits


class VtStore:
    """virustotal.json (Einstellungen), virustotal.key (API-Key, 0600) und das Tageskontingent."""

    def __init__(self, state_dir: Path, initial: dict | None = None, limits: VtLimits | None = None):
        self.path = state_dir / "virustotal.json"
        self.key_path = state_dir / "virustotal.key"
        self.quota_path = state_dir / "virustotal-quota.json"
        self.limits = limits or VtLimits()
        self.initial = dict(initial or {})

    def load(self) -> VtSettings:
        data = dict(self.initial)
        try:
            data.update(json.loads(self.path.read_text(encoding="utf-8")))
        except FileNotFoundError:
            pass
        if not self.limits.allow_upload and data.get("mode") == "upload":
            data["mode"] = "hash"
        try:
            return validate(data, self.limits.allow_upload)
        except ValueError:
            # z. B. Stufe in firebridge.toml gesetzt, Lizenz aber nie bestätigt: dann bleibt es aus
            return validate({**data, "mode": "aus"}, self.limits.allow_upload)

    def save(self, settings: VtSettings) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(settings.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    def has_key(self) -> bool:
        return bool(self.key())

    def key(self) -> str:
        try:
            return self.key_path.read_text(encoding="ascii").strip()
        except (FileNotFoundError, UnicodeDecodeError):
            return ""

    def set_key(self, key: str) -> None:
        key = key.strip()
        if not key:
            try:
                self.key_path.unlink()
            except FileNotFoundError:
                pass
            return
        if not all(c.isalnum() for c in key) or not 32 <= len(key) <= 128:
            raise ValueError("Das sieht nicht wie ein VirusTotal-API-Key aus (64 Zeichen, nur Buchstaben und Ziffern)")
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.key_path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(key + "\n")
        os.replace(tmp, self.key_path)

    # -- Kontingent
    def quota(self, license: str) -> tuple[int, int]:
        """(heute verbraucht, Tageslimit; 0 = unbegrenzt)."""
        limit = self.limits.daily_limit if license != "premium" else self.limits.premium_daily_limit
        try:
            data = json.loads(self.quota_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            data = {}
        used = data.get("count", 0) if data.get("date") == dt.date.today().isoformat() else 0
        return int(used), int(limit)

    def count_request(self) -> None:
        today = dt.date.today().isoformat()
        try:
            data = json.loads(self.quota_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            data = {}
        if data.get("date") != today:
            data = {"date": today, "count": 0}
        data["count"] = int(data.get("count", 0)) + 1
        tmp = self.quota_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, self.quota_path)

    def per_minute(self, license: str) -> int:
        return self.limits.requests_per_minute if license != "premium" else self.limits.premium_requests_per_minute


class RateLimiter:
    """Höchstens n Anfragen je 60 s (gleitendes Fenster) und das Tageskontingent."""

    def __init__(self, store: VtStore, license: str, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], bool] | None = None):
        self.store = store
        self.license = license
        self.per_minute = store.per_minute(license)
        self.clock = clock
        self.sleep = sleep or (lambda s: time.sleep(s) or False)
        self.sent: deque[float] = deque()
        self.waiting_until = 0.0

    def wait_time(self) -> float:
        if not self.per_minute:
            return 0.0
        now = self.clock()
        while self.sent and now - self.sent[0] >= 60:
            self.sent.popleft()
        if len(self.sent) < self.per_minute:
            return 0.0
        return 60 - (now - self.sent[0]) + 0.2

    def acquire(self, cancelled: Callable[[], bool] = lambda: False) -> None:
        used, limit = self.store.quota(self.license)
        if limit and used >= limit:
            raise QuotaExhausted(f"Tageskontingent erschöpft ({used} von {limit} Anfragen)")
        while (w := self.wait_time()) > 0:
            self.waiting_until = self.clock() + w
            if self.sleep(min(w, 1.0)) or cancelled():
                raise VtCancelled()
        self.waiting_until = 0.0
        self.sent.append(self.clock())
        self.store.count_request()

    def seconds_for(self, requests: int) -> float:
        """Grobe Restzeit für so viele Anfragen."""
        if not self.per_minute or requests <= 0:
            return 0.0
        return max(0.0, (requests - self.per_minute + len(self.sent)) * 60 / self.per_minute) + self.wait_time()


# ---------------------------------------------------------------- Auswahl und Bewertung

def interesting(f: dict) -> bool:
    """Wird diese Datei bei VirusTotal nachgefragt?"""
    if not f.get("sha256") or f.get("status") in ("infected", "error", "skipped"):
        return False
    if f.get("hits") or f.get("status") == "suspicious":
        return True
    return f.get("path", "").lower().endswith(ARCHIVE_SUFFIXES)


def sendable(f: dict) -> bool:
    """Darf diese Datei auf Wunsch an VirusTotal (Hash oder Upload)? Jede geprüfte Datei außer infizierten."""
    return bool(f.get("sha256")) and f.get("status") in ("clean", "suspicious")


def stats_of(attrs: dict) -> dict:
    s = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
    malicious = int(s.get("malicious", 0))
    suspicious = int(s.get("suspicious", 0))
    total = malicious + suspicious + int(s.get("undetected", 0)) + int(s.get("harmless", 0))
    return {"malicious": malicious, "suspicious": suspicious, "total": total}


def rate(vt: dict, threshold: int) -> str:
    """"hit" (gefährlich), "warn" (einzelne Meldungen), "ok" oder "" (kein Ergebnis)."""
    if vt.get("state") not in ("found", "uploaded") or "malicious" not in vt:
        return ""
    if vt["malicious"] >= threshold:
        return "hit"
    if vt["malicious"] or vt.get("suspicious"):
        return "warn"
    return "ok"


def short(vt: dict | None) -> str:
    """Kurzform für Tabellen, z. B. "3/72 Engines"."""
    if not vt:
        return ""
    st = vt.get("state")
    if st in ("found", "uploaded") and "malicious" in vt:
        return f"{vt['malicious']}/{vt.get('total', 0)} Engines"
    return {"unknown": "unbekannt", "pending": "Analyse läuft", "limit": "nicht geprüft (Limit)",
            "error": "Fehler", "skipped": "nicht geprüft"}.get(st, st or "")


# ---------------------------------------------------------------- HTTPS

class _PinnedHTTPS(http.client.HTTPSConnection):
    """HTTPS zu HOST, aber nur zu den vorab aufgelösten (und in nftables freigegebenen) IPs."""

    def __init__(self, addrs: list[str], timeout: float, context: ssl.SSLContext):
        super().__init__(HOST, PORT, timeout=timeout, context=context)
        self._addrs = addrs

    def connect(self) -> None:
        last: OSError | None = None
        for addr in self._addrs:
            try:
                sock = socket.create_connection((addr, PORT), self.timeout)
                break
            except OSError as exc:
                last = exc
        else:
            raise last or OSError("keine Adresse")
        self.sock = self._context.wrap_socket(sock, server_hostname=HOST)


Response = tuple[int, bytes]
Transport = Callable[[str, str, dict, object, int | None], Response]


def https_transport(addrs: list[str], timeout: float) -> Transport:
    ctx = ssl.create_default_context()

    def send(method: str, path: str, headers: dict, body, length: int | None) -> Response:
        conn = _PinnedHTTPS(addrs, timeout, ctx)
        try:
            hdrs = dict(headers)
            if length is not None:
                hdrs["Content-Length"] = str(length)
            conn.putrequest(method, path)
            for k, v in hdrs.items():
                conn.putheader(k, v)
            conn.endheaders()
            if body is not None:
                for chunk in body:
                    conn.send(chunk)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()
    return send


def _open_source(path: Path) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError(0, "keine reguläre Datei")
    return fd


def file_sha256(path: Path) -> str:
    fd = _open_source(path)
    h = hashlib.sha256()
    try:
        while chunk := os.read(fd, CHUNK):
            h.update(chunk)
    finally:
        os.close(fd)
    return h.hexdigest()


class VtClient:
    """Die drei Aufrufe, die Firebridge braucht. Jeder Aufruf holt sich vorher einen Platz beim RateLimiter."""

    def __init__(self, key: str, transport: Transport, limiter: RateLimiter,
                 cancelled: Callable[[], bool] = lambda: False):
        self.key = key
        self.send = transport
        self.limiter = limiter
        self.cancelled = cancelled

    def _request(self, method: str, path: str, body=None, length: int | None = None,
                 extra: dict | None = None) -> dict | None:
        self.limiter.acquire(self.cancelled)
        headers = {"x-apikey": self.key, "accept": "application/json", "user-agent": "firebridge",
                   **(extra or {})}
        status, data = self.send(method, path, headers, body, length)
        if status == 404:
            return None
        if status in (401, 403):
            raise VtError("VirusTotal lehnt den API-Key ab (ungültig oder ohne Berechtigung)")
        if status == 429:
            raise QuotaExhausted("VirusTotal meldet: Kontingent des API-Keys erschöpft")
        if status >= 400:
            msg = ""
            try:
                msg = json.loads(data).get("error", {}).get("message", "")
            except (ValueError, AttributeError):
                pass
            raise VtError(f"VirusTotal antwortet mit Fehler {status}{': ' + msg if msg else ''}")
        try:
            return json.loads(data or b"{}")
        except ValueError as exc:
            raise VtError("Antwort von VirusTotal nicht lesbar") from exc

    def file_report(self, sha256: str) -> dict | None:
        """Attribute der Datei oder None, wenn VirusTotal sie nicht kennt."""
        res = self._request("GET", f"{API}/files/{sha256}")
        return None if res is None else (res.get("data") or {}).get("attributes") or {}

    def upload(self, path: Path, name: str, size: int, sha256: str) -> str:
        """Datei hochladen, gibt die Analyse-ID zurück. Der Inhalt muss noch zum geprüften Stand passen."""
        if file_sha256(path) != sha256:
            raise VtError("Datei hat sich seit der Prüfung verändert, nicht hochgeladen")
        target = f"{API}/files"
        if size > DIRECT_UPLOAD_MAX:
            res = self._request("GET", f"{API}/files/upload_url") or {}
            url = urllib.parse.urlsplit(str(res.get("data", "")))
            if url.scheme != "https" or url.hostname != HOST:
                raise VtError("Unerwartete Upload-Adresse von VirusTotal, nicht hochgeladen")
            target = url.path + (f"?{url.query}" if url.query else "")
        boundary = uuid.uuid4().hex
        safe = name.replace('"', "_").replace("\r", "_").replace("\n", "_")
        head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{safe}\"\r\n"
                "Content-Type: application/octet-stream\r\n\r\n").encode()
        tail = f"\r\n--{boundary}--\r\n".encode()

        def body() -> Iterable[bytes]:
            yield head
            fd = _open_source(path)
            try:
                while chunk := os.read(fd, CHUNK):
                    if self.cancelled():
                        raise VtCancelled()
                    yield chunk
            finally:
                os.close(fd)
            yield tail

        res = self._request("POST", target, body(), len(head) + size + len(tail),
                            {"content-type": f"multipart/form-data; boundary={boundary}"}) or {}
        aid = (res.get("data") or {}).get("id")
        if not aid:
            raise VtError("VirusTotal hat keine Analyse-ID geliefert")
        return aid

    def analysis(self, analysis_id: str) -> dict:
        """{"status": "queued"|"in-progress"|"completed", "stats": {...}}"""
        res = self._request("GET", f"{API}/analyses/{urllib.parse.quote(analysis_id, safe='')}") or {}
        attrs = (res.get("data") or {}).get("attributes") or {}
        return {"status": attrs.get("status", ""), **stats_of(attrs)}


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def result_from_attrs(attrs: dict, sha256: str, how: str) -> dict:
    return {"state": "found" if how == "hash" else "uploaded", "how": how, "time": now_iso(),
            "link": GUI_LINK.format(sha256), **stats_of(attrs)}


@dataclasses.dataclass
class VtProgress:
    kind: str = "hash"         # "hash" oder "upload"
    total: int = 0
    done: int = 0
    current: str = ""
    waiting: float = 0.0       # Sekunden bis zur nächsten erlaubten Anfrage
    eta: float | None = None
    started: float = 0.0
    phase: str = "verbinden"   # verbinden, abfragen, hochladen, warten (auf Analyse), trennen

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["elapsed"] = time.monotonic() - self.started if self.started else 0
        return d

