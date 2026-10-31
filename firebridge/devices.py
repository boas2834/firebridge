"""Erkennung von Wechseldatenträgern über udev.

Der Dienst beobachtet Block-Geräte vom Typ "disk". Ein Datenträger wird nur
gemeldet, wenn er
  * an USB oder einem SD-Kartenleser hängt,
  * Medium enthält (Kartenleser ohne Karte melden Größe 0) und
  * kein Systemdatenträger ist. Das ist für den Live-Stick wichtig: der
    Boot-Stick ist selbst ein USB-Stick und darf nie als Prüfling erscheinen.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import threading
from pathlib import Path
from typing import Callable, Iterable

log = logging.getLogger(__name__)

# USB-Schnittstellenklassen (bInterfaceClass), siehe usb.org "Defined Class Codes"
INTERFACE_NAMES = {
    "01": "Audio",
    "02": "Kommunikation/Netzwerk (CDC)",
    "03": "Eingabegerät (HID)",
    "06": "Bild (PTP/MTP)",
    "07": "Drucker",
    "08": "Massenspeicher",
    "09": "Hub",
    "0a": "CDC-Daten",
    "0b": "Smartcard",
    "0e": "Video",
    "e0": "Funk (z. B. RNDIS/Bluetooth)",
    "ef": "Verschiedenes",
    "fe": "Anwendungsspezifisch",
    "ff": "Herstellerspezifisch",
}

# Ein Massenspeicher, der sich zusätzlich so meldet, ist verdächtig (BadUSB, LAN Turtle)
SUSPICIOUS_CLASSES = {"03", "02", "0a", "e0"}


@dataclasses.dataclass
class Partition:
    devname: str
    devnum: str
    fstype: str = ""
    label: str = ""
    uuid: str = ""
    size_bytes: int = 0
    mountpoint: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class DeviceInfo:
    devname: str
    sys_name: str
    devnum: str
    bus: str = "usb"
    vendor: str = ""
    model: str = ""
    serial: str = ""
    vendor_id: str = ""
    product_id: str = ""
    size_bytes: int = 0
    interfaces: list[dict] = dataclasses.field(default_factory=list)
    partitions: list[Partition] = dataclasses.field(default_factory=list)

    @property
    def display_name(self) -> str:
        name = " ".join(p for p in (self.vendor, self.model) if p).strip()
        return name or f"Unbekannt {self.vendor_id}:{self.product_id}".strip()

    @property
    def suspicious_interfaces(self) -> list[dict]:
        return [i for i in self.interfaces if i["class"] in SUSPICIOUS_CLASSES]

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["display_name"] = self.display_name
        d["suspicious_interfaces"] = self.suspicious_interfaces
        return d


# ---------------------------------------------------------------------------
# Reine Hilfsfunktionen (ohne udev, gut testbar)

def read_interface_classes(usb_device_dir: Path) -> list[dict]:
    """Liest die Schnittstellenklassen eines USB-Geräts aus sysfs.

    Schnittstellen liegen als Unterordner "<gerät>:<konfig>.<nr>" vor.
    """
    result = []
    seen = set()
    for entry in sorted(usb_device_dir.glob("*:*")):
        cls_file = entry / "bInterfaceClass"
        if not cls_file.is_file():
            continue
        cls = cls_file.read_text().strip().lower()
        sub = _read(entry / "bInterfaceSubClass").lower()
        proto = _read(entry / "bInterfaceProtocol").lower()
        key = (cls, sub, proto)
        if key in seen:
            continue
        seen.add(key)
        result.append({
            "class": cls,
            "code": f"{cls}/{sub or '??'}/{proto or '??'}",
            "name": INTERFACE_NAMES.get(cls, f"Klasse {cls}"),
        })
    return result


def used_devnums(mountinfo: str, swap_devnums: Iterable[str] = ()) -> set[str]:
    """Gerätenummern ("major:minor"), die eingehängt oder als Swap aktiv sind.

    mountinfo ist der Inhalt von /proc/self/mountinfo; Feld 3 ist major:minor.
    """
    nums = set(swap_devnums)
    for line in mountinfo.splitlines():
        parts = line.split()
        if len(parts) > 2 and ":" in parts[2]:
            nums.add(parts[2])
    return nums


def swap_devnums(swaps: str) -> set[str]:
    nums = set()
    for line in swaps.splitlines()[1:]:
        path = line.split()[0] if line.split() else ""
        if path.startswith("/dev/"):
            try:
                rdev = os.stat(path).st_rdev
                nums.add(f"{os.major(rdev)}:{os.minor(rdev)}")
            except OSError:
                pass
    return nums


def is_system_disk(devnums: Iterable[str], in_use: set[str], has_holders: bool) -> bool:
    """Ein Datenträger gilt als System, wenn er oder eine Partition schon
    benutzt wird (eingehängt, Swap, LVM/dm-crypt)."""
    if has_holders:
        return True
    return any(n in in_use for n in devnums)


def _read(path: Path) -> str:
    try:
        return path.read_text().strip()
    except OSError:
        return ""


def _unescape(value: str) -> str:
    # udev kodiert Sonderzeichen in *_ENC-Werten als \x20 usw.
    try:
        return value.encode("latin-1").decode("unicode_escape").encode("latin-1").decode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return value


# ---------------------------------------------------------------------------
# udev-Anbindung

class DeviceMonitor:
    """Meldet neue und entfernte Wechseldatenträger an Rückruffunktionen."""

    def __init__(self, on_add: Callable[[DeviceInfo], None],
                 on_remove: Callable[[str], None], settle_seconds: float = 1.5,
                 ignore_serials: Iterable[str] = ()):
        import pyudev  # erst hier, damit Tests ohne udev laufen

        self._pyudev = pyudev
        self.context = pyudev.Context()
        self.on_add = on_add
        self.on_remove = on_remove
        self.settle = settle_seconds
        self.ignore_serials = set(ignore_serials)
        self._known: set[str] = set()
        self._lock = threading.Lock()
        self._observer = None

    def start(self) -> None:
        monitor = self._pyudev.Monitor.from_netlink(self.context)
        monitor.filter_by(subsystem="block", device_type="disk")
        self._observer = self._pyudev.MonitorObserver(monitor, callback=self._event, name="udev")
        self._observer.start()
        # Bereits steckende Datenträger (z. B. vor dem Booten eingesteckt)
        for dev in self.context.list_devices(subsystem="block", DEVTYPE="disk"):
            self._consider(dev)

    def stop(self) -> None:
        if self._observer:
            self._observer.stop()

    # -- intern -------------------------------------------------------------

    def _event(self, dev) -> None:
        action = dev.action
        if action == "add":
            threading.Timer(self.settle, self._consider_path, args=(dev.sys_path,)).start()
        elif action == "change":
            # Kartenleser: Karte eingelegt oder entnommen
            if _int(dev.attributes.get("size")) == 0:
                self._forget(dev.device_node)
            else:
                threading.Timer(self.settle, self._consider_path, args=(dev.sys_path,)).start()
        elif action == "remove":
            self._forget(dev.device_node)

    def _forget(self, devname: str | None) -> None:
        if not devname:
            return
        with self._lock:
            if devname not in self._known:
                return
            self._known.discard(devname)
        self.on_remove(devname)

    def _consider_path(self, sys_path: str) -> None:
        try:
            dev = self._pyudev.Devices.from_sys_path(self.context, sys_path)
        except Exception:  # Gerät schon wieder weg
            return
        self._consider(dev)

    def _consider(self, dev) -> None:
        try:
            info = self._build_info(dev)
        except Exception:
            log.exception("Gerät %s konnte nicht gelesen werden", dev.device_node)
            return
        if info is None:
            return
        with self._lock:
            if info.devname in self._known:
                return
            self._known.add(info.devname)
        self.on_add(info)

    def _build_info(self, dev) -> DeviceInfo | None:
        props = dev.properties
        name = dev.sys_name
        bus = props.get("ID_BUS", "")
        if name.startswith("mmcblk") and not name.endswith(("boot0", "boot1", "rpmb")):
            bus = "mmc"
        if bus not in ("usb", "mmc"):
            return None
        size = _int(dev.attributes.get("size")) * 512
        if size == 0:
            return None  # kein Medium
        serial = props.get("ID_SERIAL_SHORT", "")
        if serial and serial in self.ignore_serials:
            log.info("%s ignoriert (Seriennummer in ignore_serials)", dev.device_node)
            return None

        parts = list(self.context.list_devices(subsystem="block", DEVTYPE="partition", parent=dev))
        devnums = [f"{os.major(dev.device_number)}:{os.minor(dev.device_number)}"]
        devnums += [f"{os.major(p.device_number)}:{os.minor(p.device_number)}" for p in parts]
        in_use = used_devnums(_read(Path("/proc/self/mountinfo")),
                              swap_devnums(_read(Path("/proc/swaps"))))
        holders = any(os.listdir(Path(d.sys_path) / "holders")
                      for d in [dev, *parts] if (Path(d.sys_path) / "holders").is_dir())
        if is_system_disk(devnums, in_use, holders):
            log.info("%s ist ein Systemdatenträger und wird nicht angeboten", dev.device_node)
            return None

        info = DeviceInfo(
            devname=dev.device_node,
            sys_name=name,
            devnum=devnums[0],
            bus=bus,
            vendor=_unescape(props.get("ID_VENDOR_ENC", props.get("ID_VENDOR", ""))).strip(),
            model=_unescape(props.get("ID_MODEL_ENC", props.get("ID_MODEL", ""))).strip(),
            serial=serial,
            vendor_id=props.get("ID_VENDOR_ID", ""),
            product_id=props.get("ID_MODEL_ID", ""),
            size_bytes=size,
        )
        usb = dev.find_parent("usb", "usb_device")
        if usb is not None:
            info.interfaces = read_interface_classes(Path(usb.sys_path))
            info.vendor = info.vendor or _read(Path(usb.sys_path) / "manufacturer")
            info.model = info.model or _read(Path(usb.sys_path) / "product")

        targets = parts if parts else [dev]
        for p in targets:
            pp = p.properties
            info.partitions.append(Partition(
                devname=p.device_node,
                devnum=f"{os.major(p.device_number)}:{os.minor(p.device_number)}",
                fstype=pp.get("ID_FS_TYPE", ""),
                label=_unescape(pp.get("ID_FS_LABEL_ENC", pp.get("ID_FS_LABEL", ""))),
                uuid=pp.get("ID_FS_UUID", ""),
                size_bytes=_int(p.attributes.get("size")) * 512,
            ))
        return info


def _int(value) -> int:
    try:
        return int(value.decode() if isinstance(value, bytes) else value)
    except (TypeError, ValueError, AttributeError):
        return 0
