"""Read-only-Einbindung und Auswerfen.

Jede Partition wird schreibgeschützt eingebunden:
  * das Block-Gerät selbst wird per "blockdev --setro" auf read-only gesetzt,
    damit auch ein Journal-Replay nichts auf den Stick schreibt,
  * Mount-Optionen ro,noexec,nosuid,nodev,noatime,
  * je Dateisystem zusätzliche Optionen gegen Schreibzugriffe (noload, norecovery).

Der Dienst läuft in einem eigenen Mount-Namespace (ProtectSystem=strict in der
systemd-Unit). Die Einbindungen sind deshalb für die Desktop-Sitzung unsichtbar.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Callable, Sequence

from .devices import DeviceInfo, Partition

log = logging.getLogger(__name__)

BASE_OPTIONS = "ro,noexec,nosuid,nodev,noatime"

# Dateisystem (wie blkid es meldet) → (Typ für mount, Zusatzoptionen)
FILESYSTEMS: dict[str, tuple[str, str]] = {
    "vfat": ("vfat", "umask=077,shortname=mixed,utf8"),
    "exfat": ("exfat", "umask=077"),
    "ntfs": ("ntfs3", "umask=077"),
    "ext2": ("ext2", ""),
    "ext3": ("ext3", "noload"),
    "ext4": ("ext4", "noload"),
    "xfs": ("xfs", "norecovery"),
    "btrfs": ("btrfs", "rescue=nologreplay"),
    "iso9660": ("iso9660", ""),
    "udf": ("udf", ""),
    "hfsplus": ("hfsplus", ""),
}

UNSUPPORTED_NOTES = {
    "crypto_LUKS": "verschlüsselt (LUKS), wird nicht geöffnet",
    "BitLocker": "verschlüsselt (BitLocker), wird nicht geöffnet",
    "swap": "Swap-Bereich, nichts zu prüfen",
    "LVM2_member": "LVM, wird nicht aktiviert",
    "": "kein Dateisystem erkannt",
}

Runner = Callable[[Sequence[str]], subprocess.CompletedProcess]


def default_runner(cmd: Sequence[str]) -> subprocess.CompletedProcess:
    return subprocess.run(list(cmd), capture_output=True, text=True, timeout=60)


class MountError(RuntimeError):
    pass


def mount_options(fstype: str) -> tuple[str, str] | None:
    if fstype not in FILESYSTEMS:
        return None
    mtype, extra = FILESYSTEMS[fstype]
    return mtype, BASE_OPTIONS + ("," + extra if extra else "")


class Mounter:
    def __init__(self, mount_root: Path, runner: Runner = default_runner):
        self.mount_root = mount_root
        self.run = runner

    def mount_device(self, dev: DeviceInfo) -> list[Partition]:
        """Bindet alle unterstützten Partitionen ein. Gibt die eingebundenen zurück."""
        self._check(["blockdev", "--setro", dev.devname])
        mounted = []
        for part in dev.partitions:
            opts = mount_options(part.fstype)
            if opts is None:
                part.note = UNSUPPORTED_NOTES.get(part.fstype, f"Dateisystem {part.fstype} nicht unterstützt")
                continue
            target = self.mount_root / dev.sys_name / Path(part.devname).name
            target.mkdir(parents=True, exist_ok=True)
            if part.devname != dev.devname:
                self._check(["blockdev", "--setro", part.devname])
            mtype, options = opts
            res = self.run(["mount", "-t", mtype, "-o", options, part.devname, str(target)])
            if res.returncode != 0:
                part.note = f"Einbinden fehlgeschlagen: {res.stderr.strip() or res.returncode}"
                log.warning("mount %s: %s", part.devname, part.note)
                _rmdir(target)
                continue
            part.mountpoint = str(target)
            part.note = f"read-only ({options})"
            mounted.append(part)
        return mounted

    def unmount_device(self, dev: DeviceInfo, lazy: bool = False) -> list[str]:
        """Hängt alle Partitionen aus. Gibt Fehlermeldungen zurück (leer = ok)."""
        errors = []
        for part in dev.partitions:
            if not part.mountpoint:
                continue
            cmd = ["umount", "-l", part.mountpoint] if lazy else ["umount", part.mountpoint]
            res = self.run(cmd)
            if res.returncode != 0 and not lazy:
                # Zweiter Versuch: lazy, damit nichts hängen bleibt
                res = self.run(["umount", "-l", part.mountpoint])
            if res.returncode != 0:
                errors.append(f"{part.devname}: {res.stderr.strip()}")
            _rmdir(Path(part.mountpoint))
            part.mountpoint = ""
        _rmdir(self.mount_root / dev.sys_name)
        return errors

    def power_off(self, dev: DeviceInfo) -> bool:
        """Schaltet das Gerät ab, damit es gefahrlos abgezogen werden kann."""
        self.run(["blockdev", "--flushbufs", dev.devname])
        res = self.run(["udisksctl", "power-off", "--no-user-interaction", "-b", dev.devname])
        if res.returncode == 0:
            return True
        res = self.run(["eject", dev.devname])
        return res.returncode == 0

    def _check(self, cmd: Sequence[str]) -> None:
        res = self.run(cmd)
        if res.returncode != 0:
            raise MountError(f"{' '.join(cmd)}: {res.stderr.strip()}")


def _rmdir(path: Path) -> None:
    try:
        path.rmdir()
    except OSError:
        pass
