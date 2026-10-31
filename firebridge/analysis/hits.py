"""Treffer einer Prüfung (Dateityp, Makros, PDF, Archiv, YARA)."""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass
class Hit:
    engine: str      # wer hat es gefunden: "Dateityp", "olevba", "PDF", "Archiv", "YARA-X", "ClamAV"
    category: str    # Schlüssel der Richtlinie (siehe policy.CATEGORIES)
    rule: str        # kurze Kennung, z. B. Name der YARA-Regel
    detail: str      # verständliche Beschreibung für Bericht und Oberfläche

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)
