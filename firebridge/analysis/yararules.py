"""YARA-X: Regeln übersetzen, laden und Dateien prüfen.

Das tägliche Update (firebridge.update) lädt die Regeln von YARA Forge,
übersetzt sie zusammen mit eigenen Regeln aus /etc/firebridge/yara/*.yar
und legt das Ergebnis unter /var/lib/firebridge/yara/ ab:

  rules.yarc   übersetzte Regeln (lädt der Dienst vor jeder Prüfung neu, falls geändert)
  rules.json   Stand: Quelle, Version, Anzahl, übersprungene Regeln

Regeln, die YARA-X nicht übersetzen kann (manche Regeln sind für das alte
YARA geschrieben), werden einzeln übersprungen und im Stand vermerkt, statt
den ganzen Regelsatz zu verwerfen.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import os
import re
import threading
from pathlib import Path

from .hits import Hit

try:
    import yara_x as _yx
except ImportError:  # pragma: no cover - abhängig vom System
    _yx = None

RULES_FILE = "rules.yarc"
META_FILE = "rules.json"
_RULE_START = re.compile(r"^[ \t]*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)", re.M)
_IMPORT = re.compile(r'^[ \t]*import\s+"[^"]+"', re.M)


def available() -> bool:
    return _yx is not None


def version() -> str:
    if _yx is None:
        return ""
    try:
        from importlib.metadata import version as v
        return v("yara-x")
    except Exception:
        return getattr(_yx, "__version__", "")


def split_rules(text: str) -> tuple[str, list[tuple[str, str]]]:
    """(Import-Zeilen, [(Regelname, Quelltext), …])."""
    imports = "\n".join(m.group(0).strip() for m in _IMPORT.finditer(text))
    starts = list(_RULE_START.finditer(text))
    rules = []
    for i, m in enumerate(starts):
        end = starts[i + 1].start() if i + 1 < len(starts) else len(text)
        rules.append((m.group(1), text[m.start():end]))
    return imports, rules


def compile_sources(sources: list[tuple[str, str]]) -> tuple[object, list[dict]]:
    """sources: [(Namensraum, Quelltext)]. Ergebnis: (Rules, Statistik je Quelle)."""
    if _yx is None:
        raise RuntimeError("YARA-X (Python-Modul yara_x) ist nicht installiert")
    compiler = _yx.Compiler(relaxed_re_syntax=True)
    stats = []
    for namespace, text in sources:
        compiler.new_namespace(namespace)
        imports, rules = split_rules(text)
        st = {"namespace": namespace, "rules": len(rules), "skipped": []}
        # Einzeln übersetzen: fehlerhafte Regeln fallen weg, der Rest bleibt. (Ein Fehler im
        # Gesamttext ließe die Regeln davor halb übersetzt im Compiler zurück.)
        for name, body in rules:
            try:
                compiler.add_source(imports + "\n" + body)
            except _yx.CompileError as exc:
                st["skipped"].append({"rule": name, "error": str(exc).splitlines()[0][:200]})
        st["rules"] -= len(st["skipped"])
        stats.append(st)
    return compiler.build(), stats


def save(rules, meta: dict, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    rules.serialize_into(buf)
    tmp = directory / (RULES_FILE + ".tmp")
    tmp.write_bytes(buf.getvalue())
    os.chmod(tmp, 0o600)
    os.replace(tmp, directory / RULES_FILE)
    mtmp = directory / (META_FILE + ".tmp")
    mtmp.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(mtmp, directory / META_FILE)


class YaraEngine:
    """Hält die übersetzten Regeln; ein YARA-X-Scanner je Thread."""

    def __init__(self, directory: Path, timeout: int = 60, max_bytes: int = 256 * 1024 * 1024):
        self.directory = directory
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.rules = None
        self.meta: dict = {}
        self.message = ""
        self._mtime = None
        self._local = threading.local()
        self._lock = threading.Lock()

    def reload_if_changed(self) -> None:
        path = self.directory / RULES_FILE
        try:
            mtime = path.stat().st_mtime_ns
        except FileNotFoundError:
            self.rules, self.meta = None, {}
            self.message = ("YARA-X fehlt (Python-Modul yara_x)" if _yx is None
                            else "Noch keine YARA-Regeln: sudo systemctl start firebridge-update")
            self._mtime = None
            return
        if mtime == self._mtime:
            return
        with self._lock:
            self._mtime = mtime
            self._local = threading.local()
            try:
                self.meta = json.loads((self.directory / META_FILE).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self.meta = {}
            if _yx is None:
                self.rules = None
                self.message = "YARA-X fehlt (Python-Modul yara_x)"
                return
            try:
                with path.open("rb") as fh:
                    self.rules = _yx.Rules.deserialize_from(fh)
                self.message = ""
            except Exception as exc:
                # z. B. nach einem Update von yara-x: Regeln mit der neuen Version neu übersetzen
                self.rules = None
                self.message = (f"YARA-Regeln nicht ladbar ({exc}). "
                                "Neu übersetzen: sudo firebridge-update --offline")

    @property
    def ready(self) -> bool:
        return self.rules is not None

    def _scanner(self):
        sc = getattr(self._local, "scanner", None)
        if sc is None:
            sc = _yx.Scanner(self.rules)
            sc.set_timeout(self.timeout)
            self._local.scanner = sc
        return sc

    def scan_path(self, path: str, size: int) -> tuple[list[Hit], str]:
        """(Treffer, Hinweis); path z. B. /proc/self/fd/7."""
        if self.rules is None:
            return [], ""
        if size > self.max_bytes:
            return [], f"YARA: übersprungen (größer als {self.max_bytes // (1024 * 1024)} MB)"
        try:
            res = self._scanner().scan_file(path)
        except _yx.TimeoutError:
            return [], f"YARA: Zeitlimit von {self.timeout} s überschritten"
        except Exception as exc:
            return [], f"YARA: {exc}"
        hits = []
        for m in res.matching_rules:
            meta = dict(m.metadata)
            desc = str(meta.get("description", ""))[:160]
            score = meta.get("score")
            detail = f"YARA-Regel {m.identifier}"
            if desc:
                detail += f": {desc}"
            if score not in (None, ""):
                detail += f" (Score {score})"
            hits.append(Hit("YARA-X", "yara", m.identifier, detail))
        return hits, ""

    def info(self) -> dict:
        m = self.meta or {}
        return {
            "available": _yx is not None,
            "ready": self.rules is not None,
            "rules": m.get("rules", 0),
            "compiled": m.get("compiled", ""),
            "source": m.get("source", ""),
            "version": m.get("source_version", ""),
            "skipped": m.get("skipped_count", 0),
            "custom": m.get("custom_rules", 0),
            "yara_x": version(),
            "message": self.message,
        }


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
