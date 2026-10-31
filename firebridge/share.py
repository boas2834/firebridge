"""Einstellungen des Ziel-Shares und Regeln für Namen auf dem Share.

Der Dienst merkt sich beliebig viele Ziele unter /var/lib/firebridge/share.json,
eines davon ist der Standard. Die Passwörter liegen getrennt in share.secret
(nur root lesbar). Solange in der Oberfläche nichts gespeichert wurde, gilt
der Abschnitt [share] in firebridge.toml als einziges Ziel.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import os
import re
import uuid
from pathlib import Path, PurePosixPath


@dataclasses.dataclass
class ShareSettings:
    name: str = ""            # Anzeigename, z. B. "NAS Buchhaltung" (leer = Pfad anzeigen)
    server: str = ""          # Name oder IP des Servers, z. B. "nas01" oder "192.168.1.20"
    share: str = ""           # Freigabename, z. B. "scans"
    folder: str = ""          # Unterordner auf dem Share, z. B. "Eingang/USB" (darf leer sein)
    username: str = ""        # leer = Gastzugang
    domain: str = ""          # Windows-Domäne oder Arbeitsgruppe (optional)
    port: int = 445
    encrypt: bool = True      # SMB3-Verschlüsselung verlangen
    verify: bool = True       # nach dem Kopieren zurücklesen und SHA-256 vergleichen

    @property
    def configured(self) -> bool:
        return bool(self.server and self.share)

    def folder_parts(self) -> list[str]:
        return [p for p in re.split(r"[\\/]+", self.folder) if p]

    def unc(self, host: str | None = None, *parts: str) -> str:
        """\\\\server\\share\\ordner\\... (host ersetzt den Servernamen, z. B. durch die IP)."""
        return "\\".join(["\\\\" + (host or self.server), self.share, *self.folder_parts(), *parts])

    def label(self) -> str:
        return self.name or self.display_target()

    def display_target(self) -> str:
        if not self.configured:
            return ""
        return self.unc() + (f" (Port {self.port})" if self.port != 445 else "")

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


class SettingsError(ValueError):
    pass


_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_SHARE_BAD = re.compile(r'[\\/:*?"<>|\x00-\x1f]')


def validate(s: ShareSettings) -> ShareSettings:
    s.name = s.name.strip()[:60]
    s.server = s.server.strip().lstrip("\\/")
    s.share = s.share.strip().strip("\\/")
    s.folder = "/".join(s.folder_parts())
    s.username = s.username.strip()
    s.domain = s.domain.strip()
    if not s.server:
        raise SettingsError("Server fehlt")
    if not _HOST.match(s.server):
        try:
            ipaddress.ip_address(s.server)
        except ValueError:
            raise SettingsError(f"Ungültiger Servername: {s.server}") from None
    if not s.share or _SHARE_BAD.search(s.share):
        raise SettingsError("Freigabename fehlt oder enthält ungültige Zeichen")
    for part in s.folder_parts():
        if part in (".", "..") or smb_name(part) != part:
            raise SettingsError(f"Ungültiger Ordnername: {part}")
    if "\\" in s.username or "/" in s.username:
        raise SettingsError("Benutzername ohne Domäne eintragen, die Domäne kommt in das eigene Feld")
    if not 1 <= int(s.port) <= 65535:
        raise SettingsError("Port muss zwischen 1 und 65535 liegen")
    s.port = int(s.port)
    return s


def from_dict(data: dict) -> ShareSettings:
    fields = {f.name for f in dataclasses.fields(ShareSettings)}
    unknown = set(data) - fields
    if unknown:
        raise SettingsError(f"Unbekannte Share-Einstellung: {', '.join(sorted(unknown))}")
    return ShareSettings(**data)


class ShareStore:
    """Liest und schreibt die gespeicherten Ziele des Dienstes.

    share.json:   {"active": "<id>", "targets": [{"id": "<id>", "server": …}, …]}
    share.secret: {"<id>": "<passwort>", …}
    Das Format von Etappe 2 (ein einziges Ziel) wird beim Lesen übernommen.
    """

    LEGACY_ID = "standard"

    def __init__(self, path: Path, secret_path: Path, defaults: dict | None = None):
        self.path = path
        self.secret_path = secret_path
        self.defaults = dict(defaults or {})

    # ------------------------------------------------------------ lesen

    def _data(self) -> dict:
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if "targets" not in data:  # ein einzelnes Ziel aus der ersten Fassung
                data = {"active": self.LEGACY_ID, "targets": [{"id": self.LEGACY_ID, **data}]}
            return data
        d = {k: v for k, v in self.defaults.items() if k != "password"}
        if d.get("server"):
            return {"active": self.LEGACY_ID, "targets": [{"id": self.LEGACY_ID, **d}]}
        return {"active": "", "targets": []}

    def _secrets(self) -> dict:
        try:
            text = self.secret_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            if not self.path.exists() and self.defaults.get("password"):
                return {self.LEGACY_ID: str(self.defaults["password"])}
            return {}
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass
        return {self.LEGACY_ID: text}  # Klartext aus der ersten Fassung

    def targets(self) -> list[tuple[str, ShareSettings]]:
        out = []
        for t in self._data()["targets"]:
            t = dict(t)
            tid = t.pop("id")
            out.append((tid, from_dict(t)))
        return out

    def active_id(self) -> str:
        data = self._data()
        ids = [t["id"] for t in data["targets"]]
        if data.get("active") in ids:
            return data["active"]
        return ids[0] if ids else ""

    def load(self, target_id: str | None = None) -> ShareSettings:
        """Ein Ziel (ohne Angabe: der Standard). Ohne gespeicherte Ziele: leere Einstellungen."""
        tid = target_id or self.active_id()
        for i, st in self.targets():
            if i == tid:
                return st
        if target_id:
            raise SettingsError("Dieses Ziel gibt es nicht mehr")
        return ShareSettings()

    def password(self, target_id: str | None = None) -> str:
        return str(self._secrets().get(target_id or self.active_id(), ""))

    def has_password(self, target_id: str | None = None) -> bool:
        return bool(self.password(target_id))

    # ------------------------------------------------------------ schreiben

    def _write(self, data: dict, secrets: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _write_private(self.path, json.dumps(data, ensure_ascii=False, indent=2))
        _write_private(self.secret_path, json.dumps(secrets, ensure_ascii=False))

    def save(self, s: ShareSettings, password: str | None = None, target_id: str | None = None,
             make_default: bool = False) -> str:
        """Ziel anlegen (target_id=None) oder ändern. password=None lässt das Passwort, wie es ist,
        "" löscht es. Gibt die ID zurück."""
        validate(s)
        data, secrets = self._data(), self._secrets()
        targets = data["targets"]
        if target_id:
            idx = next((i for i, t in enumerate(targets) if t["id"] == target_id), None)
            if idx is None:
                raise SettingsError("Dieses Ziel gibt es nicht mehr")
            targets[idx] = {"id": target_id, **s.to_dict()}
        else:
            target_id = uuid.uuid4().hex[:8]
            targets.append({"id": target_id, **s.to_dict()})
        if password is not None:
            if password:
                secrets[target_id] = password
            else:
                secrets.pop(target_id, None)
        if make_default or not data.get("active") or data["active"] not in [t["id"] for t in targets]:
            data["active"] = target_id
        self._write(data, secrets)
        return target_id

    def delete(self, target_id: str) -> None:
        data, secrets = self._data(), self._secrets()
        before = len(data["targets"])
        data["targets"] = [t for t in data["targets"] if t["id"] != target_id]
        if len(data["targets"]) == before:
            raise SettingsError("Dieses Ziel gibt es nicht mehr")
        secrets.pop(target_id, None)
        if data.get("active") == target_id:
            data["active"] = data["targets"][0]["id"] if data["targets"] else ""
        self._write(data, secrets)

    def set_active(self, target_id: str) -> None:
        data = self._data()
        if target_id not in [t["id"] for t in data["targets"]]:
            raise SettingsError("Dieses Ziel gibt es nicht mehr")
        data["active"] = target_id
        self._write(data, self._secrets())

    def public(self) -> dict:
        """Für die Oberfläche: alle Ziele ohne Passwörter."""
        active = self.active_id()
        secrets = self._secrets()
        return {
            "active": active,
            "targets": [{**st.to_dict(), "id": tid, "has_password": bool(secrets.get(tid)),
                         "configured": st.configured, "target": st.display_target(),
                         "label": st.label(), "default": tid == active}
                        for tid, st in self.targets()],
        }


def _write_private(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Namen auf dem Share

_SMB_BAD = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
# 255 ist die Grenze unter Windows; Platz lassen für die Endung ".fbpart" beim Kopieren
MAX_NAME = 240
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
             *(f"LPT{i}" for i in range(1, 10))}


def smb_name(name: str) -> str:
    """Macht aus einem Dateinamen (z. B. von einem ext4-Stick) einen gültigen Windows-Namen."""
    n = _SMB_BAD.sub("_", name).rstrip(" .")
    if not n:
        n = "_"
    if n.split(".")[0].upper() in _RESERVED:
        n = "_" + n
    if len(n) > MAX_NAME:
        stem, dot, ext = n.rpartition(".")
        n = (stem[:MAX_NAME - 1 - len(ext)] + dot + ext) if dot and len(ext) < 20 else n[:MAX_NAME]
    return n


class NameMapper:
    """Ordnet Quellpfaden eindeutige Zielpfade zu.

    Windows unterscheidet keine Groß-/Kleinschreibung: "Bild.JPG" und "bild.jpg"
    von einem ext4-Stick bekommen daher verschiedene Namen ("bild (2).jpg").
    """

    def __init__(self):
        self._dirs: dict[tuple[str, ...], dict[str, str]] = {}

    def _unique(self, parent: tuple[str, ...], name: str, original: str) -> str:
        used = self._dirs.setdefault(parent, {})
        key = original  # gleicher Quellname → gleicher Zielname (für Ordner)
        if ("\0" + key) in used:
            return used["\0" + key]
        candidate, n = name, 1
        stem, dot, ext = name.rpartition(".")
        if not dot or not stem:
            stem, dot, ext = name, "", ""
        while candidate.lower() in used:
            n += 1
            candidate = f"{stem} ({n}){dot}{ext}"
        used[candidate.lower()] = candidate
        used["\0" + key] = candidate
        return candidate

    def map(self, rel: str) -> tuple[str, ...]:
        parts = PurePosixPath(rel).parts
        out: list[str] = []
        for part in parts:
            out.append(self._unique(tuple(out), smb_name(part), part))
        return tuple(out)
