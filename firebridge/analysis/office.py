"""Makros in Office-Dokumenten mit olevba (oletools).

olevba findet VBA- und Excel-4-Makros (XLM) in alten (.doc/.xls/.ppt) und
neuen Formaten (.docm/.xlsm …, auch .docx mit Makro-Projekt), in RTF und
MHT. Jede Datei mit Makros ist ein Treffer der Kategorie "macro"; ob das
Makro beim Öffnen startet (AutoOpen …) oder verdächtige Aufrufe enthält
(Shell, CreateObject, URLs …), steht im Detail.
"""

from __future__ import annotations

import logging
import warnings

from .hits import Hit

try:
    with warnings.catch_warnings():  # neuere pyparsing-Versionen warnen über die alte API von olevba
        warnings.simplefilter("ignore")
        from oletools import crypto as _crypto
        from oletools.olevba import VBA_Parser as _VBA_Parser
except Exception:  # pragma: no cover - abhängig vom System
    _VBA_Parser = None
    _crypto = None

for _name in ("olevba", "oletools", "olefile"):
    logging.getLogger(_name).setLevel(logging.CRITICAL)

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
TEXT_FORMATS = {"rtf", "doc", "mht", "mhtml", "xml", "xls"}   # Word/Excel speichern auch als RTF/MHT/XML


def available() -> bool:
    return _VBA_Parser is not None


def looks_like_office(name: str, head: bytes, zip_names: list[str] | None) -> bool:
    """Lohnt sich olevba für diese Datei?"""
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if head.startswith(OLE_MAGIC):
        return ext not in ("msi", "msp", "mst")   # Installer sind auch OLE, aber keine Dokumente
    if zip_names is not None:
        return any(n.lower().endswith("vbaproject.bin") for n in zip_names)
    if head.startswith(b"{\\rt"):
        return True
    return ext in TEXT_FORMATS and (b"MIME-Version" in head[:4096] or b"<?mso-application" in head[:4096]
                                    or b"w:wordDocument" in head[:8192])


def analyze(name: str, data: bytes) -> tuple[list[Hit], str]:
    """(Treffer, Hinweis). Hinweis ist z. B. "Dokument beschädigt" (kein Treffer, aber erwähnenswert)."""
    if _VBA_Parser is None:
        return [], ""
    base = name.rsplit("/", 1)[-1]
    if data.startswith(OLE_MAGIC) and _crypto is not None:
        try:
            if _crypto.is_encrypted(data):
                return [Hit("olevba", "encrypted", "office-kennwort",
                            "Kennwortgeschütztes Office-Dokument, Inhalt nicht prüfbar")], ""
        except Exception:
            pass
    parser = None
    try:
        parser = _VBA_Parser(base, data=data)
        detect = getattr(parser, "detect_macros", None) or parser.detect_vba_macros
        if not detect():
            return [], ""
        auto, suspicious, iocs, encoded = [], [], [], False
        for kind, keyword, _desc in parser.analyze_macros():
            if kind == "AutoExec":
                auto.append(keyword)
            elif kind == "Suspicious" and keyword.endswith(" Strings"):
                encoded = True   # "Hex Strings", "Base64 Strings" …: kodierte Zeichenketten
            elif kind == "Suspicious":
                suspicious.append(keyword)
            elif kind == "IOC":
                iocs.append(keyword)
        xlm = bool(getattr(parser, "contains_xlm_macros", False))
        parts = ["Excel-4-Makros (XLM)" if xlm and not getattr(parser, "contains_vba_macros", True)
                 else "VBA-Makros"]
        if auto:
            parts.append("startet beim Öffnen (" + ", ".join(sorted(set(auto))[:3]) + ")")
        if suspicious:
            parts.append("verdächtig: " + ", ".join(sorted(set(suspicious))[:5]))
        if encoded:
            parts.append("kodierte Zeichenketten")
        if iocs:
            parts.append("enthält " + ", ".join(sorted(set(iocs))[:3]))
        rule = "makro-auto" if auto else "makro"
        return [Hit("olevba", "macro", rule, ", ".join(parts))], ""
    except Exception as exc:
        return [], f"olevba: Dokument nicht auswertbar ({exc.__class__.__name__})"
    finally:
        if parser is not None:
            try:
                parser.close()
            except Exception:
                pass
