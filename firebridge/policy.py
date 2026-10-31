"""Richtlinie: was mit auffälligen Dateien passiert.

Jede Prüfung (Dateityp, Makros, PDF, Archiv-Inhalt, YARA) meldet Treffer mit
einer Kategorie. Die Richtlinie ordnet jeder Kategorie eine Aktion zu:

  blockieren  die Datei wird nie übertragen
  freigabe    erst übertragbar, wenn sie in der Oberfläche freigegeben wurde
  zulassen    gilt als sauber, der Treffer steht nur im Bericht

Infizierte Dateien (ClamAV) sind davon unabhängig immer gesperrt.
Startwerte stehen in firebridge.toml unter [policy]; Änderungen aus der
Oberfläche landen in /var/lib/firebridge/policy.json.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

ACTIONS = ("blockieren", "freigabe", "zulassen")
ACTION_LABELS = {"blockieren": "blockieren", "freigabe": "Freigabe nötig", "zulassen": "zulassen"}
_RANK = {"zulassen": 0, "freigabe": 1, "blockieren": 2}

# Kategorie → (Beschreibung, Standardaktion); Reihenfolge = Anzeige in der Oberfläche
CATEGORIES: dict[str, tuple[str, str]] = {
    "executable": ("Programme (EXE, DLL, MSI, ELF, JAR, APK …)", "blockieren"),
    "script": ("Skripte (.sh .ps1 .bat .vbs .js .py …)", "freigabe"),
    "autostart": ("Verknüpfungen und Autostart (.lnk, .desktop, autorun.inf …)", "freigabe"),
    "macro": ("Office-Dokumente mit Makros", "freigabe"),
    "pdf_active": ("PDF mit JavaScript oder Auto-Aktionen", "freigabe"),
    "encrypted": ("Verschlüsselte Archive und Dokumente (nicht prüfbar)", "blockieren"),
    "yara": ("Treffer der YARA-Regeln", "blockieren"),
}


def defaults() -> dict[str, str]:
    return {k: v[1] for k, v in CATEGORIES.items()}


def validate(data: dict) -> dict[str, str]:
    """Unbekannte Kategorien oder Aktionen sind ein Fehler, fehlende bekommen den Standard."""
    out = defaults()
    for key, value in (data or {}).items():
        if key not in CATEGORIES:
            raise ValueError(f"Unbekannte Kategorie in der Richtlinie: {key}")
        if value not in ACTIONS:
            raise ValueError(f"Aktion für {key} muss {', '.join(ACTIONS)} sein, nicht {value!r}")
        out[key] = value
    return out


def strongest(actions) -> str:
    """Die strengste Aktion gewinnt (blockieren > freigabe > zulassen)."""
    best = "zulassen"
    for a in actions:
        if _RANK.get(a, 2) > _RANK[best]:
            best = a if a in _RANK else "blockieren"
    return best


def decide(hits: list[dict], policy: dict[str, str]) -> str:
    """Aktion für eine Datei mit diesen Treffern ("" = keine Treffer)."""
    if not hits:
        return ""
    return strongest(policy.get(h.get("category", ""), "blockieren") for h in hits)


def describe() -> list[dict]:
    """Für die Oberfläche: Kategorien mit Beschreibung und Standard."""
    return [{"key": k, "label": label, "default": d} for k, (label, d) in CATEGORIES.items()]


class PolicyStore:
    def __init__(self, path: Path, initial: dict | None = None):
        self.path = path
        self.initial = validate(initial or {})

    def load(self) -> dict[str, str]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return dict(self.initial)
        return validate({**self.initial, **data})

    def save(self, data: dict) -> dict[str, str]:
        policy = validate(data)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)
        return policy
