"""Erkennt Programme, Skripte und Verknüpfungen am Inhalt und am Namen.

Zuerst eigene Regeln (Datei-Header: ELF, PE, Mach-O, Shebang, Windows-
Verknüpfung, Desktop-Datei), dann libmagic (python3-magic) als zweite
Meinung, zuletzt die Endung. Passt der Inhalt nicht zur Endung (ein
Programm namens foto.jpg), steht das im Treffer.
"""

from __future__ import annotations

import re
import struct

from .hits import Hit

try:  # python3-magic (Debian) bzw. python-magic
    import magic as _magic
except ImportError:  # pragma: no cover - abhängig vom System
    _magic = None

EXEC_EXT = {"exe", "dll", "scr", "com", "cpl", "sys", "drv", "ocx", "pif", "msi", "msp", "mst", "appx",
            "msix", "appxbundle", "msixbundle", "appimage", "run", "elf", "so", "deb", "rpm", "apk", "jar",
            "class", "xbap", "gadget", "efi", "ko"}
SCRIPT_EXT = {"sh", "bash", "zsh", "ksh", "csh", "fish", "ps1", "psm1", "psd1", "ps1xml", "psc1", "bat",
              "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsc", "wsh", "hta", "py", "pyw", "pl", "rb", "php",
              "lua", "tcl", "applescript", "scpt", "command", "reg", "msh", "au3", "ahk", "sct"}
AUTOSTART_EXT = {"lnk", "url", "scf", "desktop", "library-ms", "searchconnector-ms", "settingcontent-ms",
                 "appref-ms", "website", "inf"}
AUTOSTART_NAMES = {"autorun.inf", ".autorun", "autorun", "autorun.sh", "autostart.sh"}
MACRO_EXT = {"docm", "dotm", "xlsm", "xltm", "xlam", "xlsb", "pptm", "potm", "ppam", "ppsm", "sldm"}

# Programme, die eine Verknüpfung oder ein Skript typischerweise startet
LAUNCHERS = ("powershell", "pwsh", "cmd.exe", "mshta", "wscript", "cscript", "rundll32", "regsvr32",
             "certutil", "bitsadmin", "msiexec", "schtasks", "curl", "wget", "bash", "sh -c")

LNK_HEADER = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

MAGIC_EXEC_MIME = {"application/x-dosexec", "application/x-executable", "application/x-sharedlib",
                   "application/x-pie-executable", "application/x-mach-binary", "application/x-msi",
                   "application/vnd.microsoft.portable-executable", "application/x-elf",
                   "application/java-archive", "application/x-java-applet", "application/vnd.android.package-archive"}
MAGIC_SCRIPT_MIME = {"text/x-shellscript", "text/x-python", "text/x-script.python", "text/x-perl",
                     "text/x-php", "text/x-msdos-batch", "application/x-msdos-batch", "text/x-ruby",
                     "text/x-lua", "text/x-tcl", "application/javascript", "text/javascript", "application/x-ms-shortcut",
                     "application/hta"}


def ext_of(name: str) -> str:
    base = name.rsplit("/", 1)[-1].lower()
    return base.rsplit(".", 1)[1] if "." in base.lstrip(".") else ""


def magic_available() -> bool:
    return _magic is not None


def _magic_info(head: bytes) -> tuple[str, str]:
    """(MIME-Typ, Beschreibung) oder ("", "") ohne libmagic."""
    if _magic is None or not head:
        return "", ""
    try:
        if hasattr(_magic, "Magic"):  # python-magic
            return (_magic.from_buffer(head, mime=True) or "", _magic.from_buffer(head) or "")
        info = _magic.detect_from_content(head)  # file-magic (python3-file-magic)
        return info.mime_type or "", info.name or ""
    except Exception:
        return "", ""


def _pe_kind(head: bytes) -> str:
    if len(head) < 0x40:
        return "DOS-Programm"
    off = struct.unpack_from("<I", head, 0x3C)[0]
    if off + 24 <= len(head) and head[off:off + 4] == b"PE\0\0":
        characteristics = struct.unpack_from("<H", head, off + 22)[0]
        return "Windows-Bibliothek (DLL)" if characteristics & 0x2000 else "Windows-Programm (PE)"
    return "DOS-/Windows-Programm"


def _lnk_target(data: bytes) -> str:
    """Grobe Suche nach dem gestarteten Programm in einer Verknüpfung."""
    text = (data.decode("utf-16-le", "ignore") + " " + data.decode("latin-1")).lower()
    for name in LAUNCHERS:
        if name in text:
            return name if "." in name or " " in name else name + ".exe"
    m = re.search(r"[a-z]:\\[^\x00-\x1f\"<>|]{3,120}?\.(exe|bat|cmd|ps1|vbs|js|hta|scr)", text)
    return m.group(0) if m else ""


def _first_line(head: bytes, prefix: bytes) -> str:
    for line in head.splitlines():
        line = line.strip()
        if line.lower().startswith(prefix):
            return line.decode("utf-8", "replace")[:120]
    return ""


def detect(name: str, head: bytes) -> list[Hit]:
    """name: Pfad im Bericht, head: die ersten Bytes (64 KB reichen)."""
    ext = ext_of(name)
    base = name.rsplit("/", 1)[-1].lower()
    kind = ""          # was der Inhalt ist
    category = ""
    if head.startswith(b"\x7fELF"):
        kind, category = "Linux-Programm (ELF)", "executable"
    elif head.startswith(b"MZ"):
        kind, category = _pe_kind(head), "executable"
    elif head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        kind, category = "macOS-Programm (Mach-O)", "executable"
    elif head.startswith(b"\xca\xfe\xba\xbe"):
        kind, category = ("Java-Klasse" if ext == "class" else "Programm (Mach-O/Java)"), "executable"
    elif head.startswith(b"#!"):
        kind, category = f"Skript ({head.splitlines()[0][:60].decode('utf-8', 'replace')})", "script"
    elif head.startswith(LNK_HEADER):
        target = _lnk_target(head)
        kind = f"Windows-Verknüpfung, startet {target}" if target else "Windows-Verknüpfung"
        category = "autostart"
    elif head.lstrip().startswith(b"[Desktop Entry]"):
        line = _first_line(head, b"exec=")
        kind, category = (f"Desktop-Starter ({line})" if line else "Desktop-Starter"), "autostart"

    mime, desc = _magic_info(head)
    if not category and mime:
        short = (desc.split(",")[0] or mime)[:80]
        if mime in MAGIC_EXEC_MIME:
            kind, category = (f"Programmdatei (.{ext}, {short})" if ext else f"Programmdatei ({short})"), "executable"
        elif mime in MAGIC_SCRIPT_MIME or re.search(r"\bscript\b|batch file", desc, re.I):
            kind, category = (f"Skript (.{ext}, {short})" if ext else f"Skript ({short})"), "script"

    hits: list[Hit] = []
    if category:
        expected = {"executable": EXEC_EXT, "script": SCRIPT_EXT, "autostart": AUTOSTART_EXT}[category]
        detail = kind
        rule = {"executable": "programm", "script": "skript", "autostart": "verknuepfung"}[category]
        if ext not in expected and base not in AUTOSTART_NAMES:
            detail += f", getarnt als {'.' + ext if ext else 'Datei ohne Endung'}"
            rule += "-getarnt"
        if category == "script":
            detail += _script_extras(ext, head)
        hits.append(Hit("Dateityp", category, rule, detail + _double_ext(base)))
        return hits

    # Nur die Endung (oder der Name) verrät die Art
    if base in AUTOSTART_NAMES:
        line = _first_line(head, b"open=") or _first_line(head, b"shellexecute=")
        hits.append(Hit("Dateityp", "autostart", "autorun", "Autostart-Datei" + (f" ({line})" if line else "")))
    elif ext in EXEC_EXT:
        hits.append(Hit("Dateityp", "executable", "endung", f"Programmdatei (.{ext})"))
    elif ext in SCRIPT_EXT:
        hits.append(Hit("Dateityp", "script", "endung", f"Skript (.{ext})" + _script_extras(ext, head)))
    elif ext in AUTOSTART_EXT:
        hits.append(Hit("Dateityp", "autostart", "endung", f"Verknüpfung/Starter (.{ext})"))
    if hits:
        hits[0].detail += _double_ext(base)
    return hits


def _script_extras(ext: str, head: bytes) -> str:
    text = head.decode("latin-1").lower()
    launcher = next((x for x in LAUNCHERS if x in text), "")
    extra = f", ruft {launcher} auf" if launcher else ""
    if re.search(rb"-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{8,}", head, re.I):
        extra += ", enthält -EncodedCommand"
    return extra


def _double_ext(base: str) -> str:
    if re.search(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|zip|mp[34])\.[a-z0-9]{2,5}$", base):
        return ", doppelte Endung"
    return ""
