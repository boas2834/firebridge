"""Zwischenspeicher für Prüfergebnisse: die letzten N Dateien nach SHA-256.

Steckt derselbe Stick noch einmal, muss jede Datei zwar gelesen und gehasht
werden, ClamAV und Tiefenprüfung entfallen aber für bekannte Inhalte.

Gespeichert wird das rohe Ergebnis (ClamAV-Urteil und Treffer), nicht die
Bewertung: Die Richtlinie wird bei jeder Prüfung neu angewendet. Der
Schlüssel ist Hash plus Dateiname, weil die Dateityp-Prüfung auch die Endung
ansieht ("getarnt als .jpg").

Alle Einträge gelten nur für einen Stand der Prüfmittel (Fingerabdruck aus
ClamAV-Version und Signaturdateien, YARA-Regeln, Einstellungen der
Tiefenprüfung, Firebridge-Version). Ändert sich etwas davon, wird der ganze
Zwischenspeicher verworfen. Ergebnisse mit Hinweisen (Zeitlimit,
Auswertungsfehler) und Fehler werden nie gespeichert.
"""

from __future__ import annotations

import collections
import json
import logging
import os
import threading
from pathlib import Path

from .analysis import Hit
from .clamav import Verdict

log = logging.getLogger(__name__)


class ScanCache:
    def __init__(self, path: Path, size: int = 1000):
        self.path = path
        self.size = max(0, size)
        self.fingerprint = ""
        self._entries: collections.OrderedDict[str, dict] = collections.OrderedDict()
        self._lock = threading.Lock()
        self._loaded = False
        self._dirty = False

    @property
    def enabled(self) -> bool:
        return self.size > 0

    def __len__(self) -> int:
        with self._lock:
            if not self._loaded:
                self._load()
            return len(self._entries)

    @staticmethod
    def key(digest: str, name: str) -> str:
        return f"{digest}:{name.rsplit('/', 1)[-1]}"

    def _load(self) -> None:
        self._loaded = True
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.fingerprint = str(data.get("fingerprint", ""))
            for k, v in data.get("entries", []):
                self._entries[k] = v
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError) as exc:
            log.warning("Zwischenspeicher %s nicht lesbar, fange neu an: %s", self.path, exc)
            self.fingerprint, self._entries = "", collections.OrderedDict()
        while len(self._entries) > self.size:
            self._entries.popitem(last=False)

    def begin(self, fingerprint: str) -> bool:
        """Vor einer Prüfung. True, wenn der Speicher wegen neuer Prüfmittel geleert wurde."""
        with self._lock:
            if not self._loaded:
                self._load()
            if fingerprint == self.fingerprint:
                return False
            had = bool(self._entries)
            self.fingerprint = fingerprint
            self._entries.clear()
            self._dirty = True
            return had

    def get(self, key: str) -> tuple[Verdict, list[Hit], list[str]] | None:
        with self._lock:
            e = self._entries.get(key)
            if e is None:
                return None
            self._entries.move_to_end(key)
            self._dirty = True
        return Verdict(*e["verdict"]), [Hit(**h) for h in e["hits"]], []

    def put(self, key: str, verdict: Verdict, hits: list[Hit], notes: list[str]) -> None:
        if not self.enabled or not self.fingerprint or notes or verdict.status not in ("clean", "infected"):
            return
        with self._lock:
            self._entries[key] = {"verdict": [verdict.status, verdict.signature],
                                  "hits": [h.to_dict() for h in hits]}
            self._entries.move_to_end(key)
            while len(self._entries) > self.size:
                self._entries.popitem(last=False)
            self._dirty = True

    def clear(self) -> None:
        with self._lock:
            self._loaded = True
            self.fingerprint = ""
            self._entries.clear()
            self._dirty = True
        self.save()

    def save(self) -> None:
        with self._lock:
            if not self._dirty:
                return
            data = {"fingerprint": self.fingerprint, "entries": list(self._entries.items())}
            self._dirty = False
        tmp = self.path.with_suffix(".tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False)
            os.replace(tmp, self.path)
        except OSError as exc:
            log.warning("Zwischenspeicher nicht gespeichert: %s", exc)
