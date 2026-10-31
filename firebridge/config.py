"""Einstellungen des Dienstes.

Werte kommen aus /etc/firebridge/firebridge.toml (falls vorhanden),
sonst gelten die Standardwerte unten.
"""

from __future__ import annotations

import dataclasses
import os
import tomllib
from pathlib import Path

DEFAULT_CONFIG_FILE = Path("/etc/firebridge/firebridge.toml")


@dataclasses.dataclass
class Config:
    station_name: str = "Prüfstation 01"
    # Wurzel für die Read-only-Einbindungen (liegt im privaten Mount-Namespace des Dienstes)
    mount_root: Path = Path("/run/firebridge/mnt")
    # Berichte und Verlauf
    state_dir: Path = Path("/var/lib/firebridge")
    # clamd-Socket (Debian-Standard) und Scan-Backend: "auto", "clamd" oder "clamscan"
    clamd_socket: Path = Path("/run/clamav/clamd.ctl")
    scan_backend: str = "auto"
    clamscan_binary: str = "clamscan"
    clamav_db_dir: Path = Path("/var/lib/clamav")
    scan_workers: int = 4
    clamd_timeout: float = 300.0
    # Ab diesem Alter (Stunden) gelten die Signaturen als veraltet
    signature_warn_hours: int = 36
    # Wartezeit nach dem Einstecken, bis udev alle Partitionen gemeldet hat
    settle_seconds: float = 1.5
    # Seriennummern, die nie geprüft werden (z. B. ein fest steckender Datenstick)
    ignore_serials: list[str] = dataclasses.field(default_factory=list)
    # Netzwerk nur während der Übertragung: "nftables" (Standard) oder "off" (nur zum Testen!)
    firewall: str = "nftables"
    nft_binary: str = "nft"
    # Darf das Ziel-Share in der Oberfläche geändert werden?
    share_editable: bool = True
    # Auch Datenträger mit Ergebnis "unvollständig" übertragen (nur die sauberen Dateien)
    transfer_incomplete: bool = False
    smb_timeout: float = 30.0
    # Startwerte für das Ziel-Share, solange in der Oberfläche nichts gespeichert wurde
    share: dict = dataclasses.field(default_factory=dict)
    # --- Etappe 3: Tiefenprüfung
    # Startwerte der Richtlinie (Kategorie → "blockieren", "freigabe" oder "zulassen")
    policy: dict = dataclasses.field(default_factory=dict)
    policy_editable: bool = True
    # Eigene YARA-Regeln (*.yar), werden mit YARA Forge zusammen übersetzt
    yara_custom_dir: Path = Path("/etc/firebridge/yara")
    # Regelsatz von YARA Forge: "core" (wenig Fehlalarme), "extended" oder "full"
    yara_forge_set: str = "core"
    yara_timeout: int = 60
    yara_max_mb: int = 256
    office_max_mb: int = 100
    # Wie tief verschachtelte ZIP-Archive angesehen werden
    archive_depth: int = 2
    # Update-Dienst (systemd), den "Jetzt aktualisieren" startet
    update_unit: str = "firebridge-update.service"
    freshclam_binary: str = "freshclam"
    # Ergebnisse der letzten N Dateien merken (nach SHA-256), 0 = aus
    scan_cache_size: int = 1000
    # --- Etappe 4: BadUSB
    # Neue USB-Geräte überwachen: USBGuard-Sperre auswerten, Tastaturen festhalten (false nur zum Testen!)
    usb_guard: bool = True
    usbguard_binary: str = "usbguard"
    # So viele Sekunden hat der Bediener, um den Code auf einer neuen Tastatur einzutippen
    hid_probe_seconds: int = 120
    # --- VirusTotal (optional): Startwerte und feste Grenzen, siehe [virustotal] in firebridge.toml
    virustotal: dict = dataclasses.field(default_factory=dict)
    # --- Etappe 5: Zusatzsignaturen für ClamAV (Sanesecurity), siehe [extra_signatures]
    extra_signatures: dict = dataclasses.field(default_factory=dict)

    @property
    def reports_dir(self) -> Path:
        return self.state_dir / "reports"

    @property
    def history_file(self) -> Path:
        return self.state_dir / "history.jsonl"

    @property
    def share_file(self) -> Path:
        return self.state_dir / "share.json"

    @property
    def share_secret_file(self) -> Path:
        return self.state_dir / "share.secret"

    @property
    def policy_file(self) -> Path:
        return self.state_dir / "policy.json"

    @property
    def yara_dir(self) -> Path:
        """Übersetzte YARA-Regeln, schreibt firebridge-update."""
        return self.state_dir / "yara"

    @property
    def update_status_file(self) -> Path:
        return self.state_dir / "update.json"

    @property
    def admin_file(self) -> Path:
        return self.state_dir / "admin.json"

    @property
    def scan_cache_file(self) -> Path:
        return self.state_dir / "scan-cache.json"


def load(path: Path | None = None) -> Config:
    path = path or Path(os.environ.get("FIREBRIDGE_CONFIG", DEFAULT_CONFIG_FILE))
    cfg = Config()
    if not path.exists():
        return cfg
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    fields = {f.name: f for f in dataclasses.fields(Config)}
    for key, value in data.items():
        if key not in fields:
            raise ValueError(f"Unbekannte Einstellung in {path}: {key}")
        default = getattr(cfg, key)
        if isinstance(default, Path):
            value = Path(value)
        setattr(cfg, key, value)
    if cfg.firewall not in ("nftables", "off"):
        raise ValueError(f"firewall muss \"nftables\" oder \"off\" sein, nicht {cfg.firewall!r}")
    if cfg.yara_forge_set not in ("core", "extended", "full"):
        raise ValueError(f"yara_forge_set muss \"core\", \"extended\" oder \"full\" sein, nicht {cfg.yara_forge_set!r}")
    from .virustotal import split_config
    split_config(cfg.virustotal)  # unbekannte Schlüssel unter [virustotal] gleich beim Start melden
    from .extrasigs import settings as extra_settings
    extra_settings(cfg.extra_signatures)
    return cfg
