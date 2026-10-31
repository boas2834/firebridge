"""PDF-Prüfung nach dem Vorbild von pdfid (Didier Stevens).

Zählt die PDF-Namen, mit denen ein Dokument beim Öffnen etwas tun kann:
JavaScript, Programmstart, eingebettete Dateien, Flash/RichMedia, XFA-
Formulare. Getarnte Namen wie /J#61vaScript werden vorher zurückgewandelt.
/OpenAction und /AA allein sind häufig harmlos (z. B. "auf Seite 1 öffnen")
und stehen nur im Detail, wenn noch etwas anderes dazukommt.
"""

from __future__ import annotations

import re
from typing import Callable

from .hits import Hit

CHUNK = 1024 * 1024
OVERLAP = 64
_NAME = re.compile(rb"/[A-Za-z0-9#]{2,40}")
_HEX = re.compile(rb"#([0-9A-Fa-f]{2})")

ACTIVE = {b"/JS": "JavaScript", b"/JavaScript": "JavaScript", b"/Launch": "startet Programme (/Launch)",
          b"/EmbeddedFile": "eingebettete Datei", b"/RichMedia": "RichMedia/Flash", b"/XFA": "XFA-Formular"}
TRIGGERS = {b"/OpenAction": "/OpenAction", b"/AA": "/AA (Auto-Aktion)"}


def is_pdf(head: bytes) -> bool:
    return b"%PDF-" in head[:1024]


def analyze(read: Callable[[int, int], bytes], size: int) -> list[Hit]:
    """read(offset, length) liest aus der Datei; es wird in Stücken von 1 MB gelesen."""
    counts: dict[bytes, int] = {}
    obfuscated = 0
    pos = 0
    while pos < size:
        start = max(0, pos - OVERLAP)
        chunk = read(start, CHUNK + (pos - start))
        if not chunk:
            break
        for m in _NAME.finditer(chunk):
            if start + m.start() < pos:      # schon im vorigen Stück gezählt
                continue
            name = m.group(0)
            if b"#" in name:
                decoded = _HEX.sub(lambda h: bytes([int(h.group(1), 16)]), name)
                if decoded != name and (decoded in ACTIVE or decoded in TRIGGERS):
                    obfuscated += 1   # z. B. /J#61vaScript; #20 in Schriftnamen ist dagegen normal
                name = decoded
            if name in ACTIVE or name in TRIGGERS:
                counts[name] = counts.get(name, 0) + 1
        pos = start + len(chunk)
    found = sorted({ACTIVE[k] for k in counts if k in ACTIVE})
    if not found and not obfuscated:
        return []
    parts = list(found)
    parts += [label for k, label in TRIGGERS.items() if k in counts]
    if obfuscated:
        parts.append(f"{obfuscated} getarnte Schlüsselwörter")
    rule = "pdf-javascript" if "JavaScript" in found else ("pdf-getarnt" if not found else "pdf-aktiv")
    return [Hit("PDF", "pdf_active", rule, "PDF mit " + ", ".join(parts))]
