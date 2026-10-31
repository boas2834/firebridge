"""Prüfberichte (JSON) und Verlauf.

Jeder Scan erzeugt einen vollständigen Bericht unter reports/<id>.json.
Zusätzlich wird eine Zeile an history.jsonl angehängt, aus der die
Startseite und die Seite „Verlauf“ lesen.

audit.jsonl hält fest, wer etwas freigegeben hat (Dateien, USB-Geräte,
Übertragungen, VirusTotal-Uploads). Die Datei wird nur angehängt, nie umgeschrieben.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
from pathlib import Path

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def report_id(device: dict, when: dt.datetime) -> str:
    vendor = _SAFE.sub("-", device.get("vendor") or device.get("vendor_id") or "Geraet").strip("-")
    serial = _SAFE.sub("", device.get("serial", ""))[-4:] or "0000"
    return f"{when:%Y-%m-%d_%H%M%S}_{vendor[:24]}_{serial}"


class ReportStore:
    def __init__(self, reports_dir: Path, history_file: Path, audit_file: Path | None = None):
        self.reports_dir = reports_dir
        self.history_file = history_file
        self.audit_file = audit_file or history_file.with_name("audit.jsonl")

    def ensure(self) -> None:
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def save(self, report: dict) -> Path:
        self.ensure()
        path = self.reports_dir / f"{report['id']}.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(report, ensure_ascii=False, indent=2))
        os.replace(tmp, path)
        return path

    def append_history(self, entry: dict) -> None:
        _append(self.history_file, entry)

    def history(self, limit: int = 10) -> list[dict]:
        return _tail(self.history_file, limit)

    def append_audit(self, entry: dict) -> None:
        _append(self.audit_file, entry)

    def audit(self, limit: int = 200) -> list[dict]:
        return _tail(self.audit_file, limit)

    def quarantine(self, max_reports: int = 200, limit: int = 1000) -> list[dict]:
        """Gesperrte und freigegebene auffällige Dateien aus den letzten Prüfungen, neueste zuerst.

        Die Dateien selbst bleiben auf dem Datenträger; hier steht nur, was gefunden wurde.
        """
        out: list[dict] = []
        seen: set[str] = set()
        for entry in self.history(max_reports * 3):
            rid = entry.get("id")
            if not rid or rid in seen:
                continue  # Einträge ohne Bericht (BadUSB, abgebrochen) und doppelte (Übertragung)
            seen.add(rid)
            if len(seen) > max_reports:
                break
            try:
                report = self.load(rid)
            except (OSError, ValueError):
                continue
            dev = report.get("device") or {}
            device = dev.get("display_name") or entry.get("device") or "?"
            by = {}
            for rel in report.get("releases") or []:
                for path in rel.get("released") or []:
                    by[path] = rel.get("by", "")
            for f in report.get("files") or []:
                status = f.get("status")
                if status == "infected":
                    state = "infiziert"
                elif status == "suspicious" and f.get("action") == "blockieren":
                    state = "gesperrt"
                elif status == "suspicious" and f.get("action") == "freigabe":
                    state = "freigegeben" if f.get("released") else "nicht freigegeben"
                else:
                    continue
                reason = f.get("detail") or "; ".join(h.get("detail") or h.get("rule") or ""
                                                       for h in f.get("hits") or [] if isinstance(h, dict))
                out.append({"report": rid, "time": report.get("finished") or entry.get("time"),
                            "device": device, "serial": dev.get("serial", ""), "path": f.get("path", ""),
                            "size": f.get("size", 0), "sha256": f.get("sha256", ""), "state": state,
                            "reason": reason, "released": f.get("released", ""),
                            "released_by": by.get(f.get("path"), "")})
                if len(out) >= limit:
                    return out
        return out

    def clear(self) -> tuple[int, int]:
        """Verlauf und alle Prüfberichte löschen (das Freigabe-Protokoll bleibt). Ergebnis: (Einträge, Berichte)."""
        entries = len(self.history(10 ** 9))
        reports = 0
        if self.reports_dir.exists():
            for path in self.reports_dir.glob("*.json"):
                path.unlink(missing_ok=True)
                reports += 1
        if self.history_file.exists():
            tmp = self.history_file.with_suffix(".tmp")
            tmp.write_text("", encoding="utf-8")
            os.replace(tmp, self.history_file)
        return entries, reports

    def load(self, rid: str) -> dict:
        if not rid or _SAFE.search(rid) or rid.startswith("."):
            raise ValueError("ungültige Berichts-ID")
        return json.loads((self.reports_dir / f"{rid}.json").read_text(encoding="utf-8"))


def _append(path: Path, entry: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _tail(path: Path, limit: int) -> list[dict]:
    """Die letzten limit Zeilen einer JSONL-Datei, neueste zuerst."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(out) >= limit:
            break
    return out
