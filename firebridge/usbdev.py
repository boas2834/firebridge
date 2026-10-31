"""USB-Geräte einordnen (Etappe 4: BadUSB).

Grundlage ist die Datei "descriptors" eines USB-Geräts in sysfs. Sie enthält
den Geräte- und alle Konfigurationsdeskriptoren und ist auch dann lesbar, wenn
USBGuard das Gerät gesperrt hat (authorized = 0). Die Unterordner der
Schnittstellen legt der Kernel dann nicht an, deshalb geht es nicht über
bInterfaceClass wie in devices.py.

Einordnung:
  speicher   nur Massenspeicher (08)            → ganz normal prüfen
  hub        nur Hub (09)                        → unauffällig
  badusb     Massenspeicher plus Tastatur/Netz   → gesperrt, nie freigebbar
  netzwerk   Netzwerkadapter (CDC, RNDIS)       → gesperrt, nie freigebbar
  eingabe    Tastatur, Maus, sonstiges HID       → gesperrt, Freigabe mit Tipp-Probe
  sonstiges  alles andere (Webcam, Audio …)      → gesperrt, Freigabe möglich
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

from .devices import INTERFACE_NAMES

DESC_DEVICE = 1
DESC_INTERFACE = 4

KIND_TEXT = {
    "speicher": "Massenspeicher",
    "hub": "USB-Hub",
    "badusb": "Speicher mit Tastatur oder Netzwerk (BadUSB)",
    "netzwerk": "Netzwerkadapter",
    "eingabe": "Eingabegerät",
    "sonstiges": "Sonstiges USB-Gerät",
}

# Diese Arten lassen sich in der Oberfläche nie freigeben
NEVER_ALLOW = {"badusb", "netzwerk"}


@dataclasses.dataclass(frozen=True)
class Interface:
    cls: int
    sub: int
    proto: int

    @property
    def code(self) -> str:
        return f"{self.cls:02x}/{self.sub:02x}/{self.proto:02x}"

    @property
    def name(self) -> str:
        if self.cls == 0x03:
            if self.sub == 0x01 and self.proto == 0x01:
                return "Tastatur (HID)"
            if self.sub == 0x01 and self.proto == 0x02:
                return "Maus (HID)"
        if self.is_network:
            return "Netzwerk (RNDIS)" if self.cls in (0xE0, 0xEF) else "Netzwerk (CDC)"
        return INTERFACE_NAMES.get(f"{self.cls:02x}", f"Klasse {self.cls:02x}")

    @property
    def is_network(self) -> bool:
        if self.cls in (0x02, 0x0A):
            return True
        # RNDIS: E0/01/03 (Wireless Controller) oder EF/04/01 (Misc); Bluetooth E0/01/01 zählt mit
        return (self.cls == 0xE0 and self.sub == 0x01) or (self.cls == 0xEF and self.sub == 0x04)

    def to_dict(self) -> dict:
        return {"class": f"{self.cls:02x}", "code": self.code, "name": self.name}


@dataclasses.dataclass
class UsbInfo:
    """Ein USB-Gerät (nicht Block-Gerät) aus sysfs."""
    port: str                 # sysfs-Name, z. B. "1-2.3" (bei USBGuard "via-port")
    sys_path: str = ""
    vendor_id: str = ""
    product_id: str = ""
    manufacturer: str = ""
    product: str = ""
    serial: str = ""
    device_class: int = 0
    interfaces: list[Interface] = dataclasses.field(default_factory=list)
    authorized: bool | None = None

    @property
    def usb_id(self) -> str:
        return f"{self.vendor_id}:{self.product_id}"

    @property
    def display_name(self) -> str:
        name = " ".join(p for p in (self.manufacturer, self.product) if p).strip()
        return name or f"Unbekannt {self.usb_id}"

    @property
    def kind(self) -> str:
        return classify(self.interfaces, self.device_class)

    @property
    def keyboard_capable(self) -> bool:
        """Kann das Gerät Tasten senden? Alles HID außer einer reinen Boot-Maus."""
        return any(i.cls == 0x03 and not (i.sub == 0x01 and i.proto == 0x02) for i in self.interfaces)

    def to_dict(self) -> dict:
        return {"port": self.port, "usb_id": self.usb_id, "vendor_id": self.vendor_id,
                "product_id": self.product_id, "name": self.display_name, "serial": self.serial,
                "interfaces": [i.to_dict() for i in self.interfaces], "kind": self.kind,
                "kind_text": KIND_TEXT[self.kind], "keyboard": self.keyboard_capable}


def parse_descriptors(data: bytes) -> tuple[dict, list[Interface]]:
    """Gerätedeskriptor (Hersteller-/Produkt-ID, Klasse) und alle Schnittstellen.

    Alternativ-Einstellungen derselben Schnittstelle zählen mit (ein UAS-Stick meldet
    z. B. 08/06/50 und 08/06/62), doppelte Kombinationen nur einmal.
    """
    dev: dict = {}
    if len(data) >= 18 and data[1] == DESC_DEVICE:
        dev = {"device_class": data[4],
               "vendor_id": f"{int.from_bytes(data[8:10], 'little'):04x}",
               "product_id": f"{int.from_bytes(data[10:12], 'little'):04x}"}
    result: list[Interface] = []
    pos = data[0] if dev else 0
    while pos + 2 <= len(data):
        length, kind = data[pos], data[pos + 1]
        if length < 2:
            break  # kaputter Deskriptor, nicht endlos laufen
        if kind == DESC_INTERFACE and length >= 9 and pos + 9 <= len(data):
            itf = Interface(data[pos + 5], data[pos + 6], data[pos + 7])
            if itf not in result:
                result.append(itf)
        pos += length
    return dev, result


def classify(interfaces: list[Interface], device_class: int = 0) -> str:
    classes = {i.cls for i in interfaces}
    if not classes:
        # Keine Schnittstelle lesbar: nicht als harmlos durchgehen lassen
        return "hub" if device_class == 0x09 else "sonstiges"
    storage = 0x08 in classes
    hid = 0x03 in classes
    net = any(i.is_network for i in interfaces)
    if storage and (hid or net):
        return "badusb"
    if net:
        return "netzwerk"
    if hid:
        return "eingabe"
    if classes == {0x08}:
        return "speicher"
    if classes == {0x09}:
        return "hub"
    return "sonstiges"


def _read(path: Path) -> str:
    try:
        return path.read_text(errors="replace").strip()
    except OSError:
        return ""


def read_usb_device(sys_path: str | Path) -> UsbInfo | None:
    """Liest ein USB-Gerät aus sysfs (/sys/bus/usb/devices/<port>). None bei Root-Hubs."""
    p = Path(sys_path)
    if p.name.startswith("usb") or ":" in p.name:
        return None  # Root-Hub bzw. Schnittstelle, kein Gerät
    try:
        raw = (p / "descriptors").read_bytes()
    except OSError:
        return None
    dev, interfaces = parse_descriptors(raw)
    auth = _read(p / "authorized")
    return UsbInfo(
        port=p.name, sys_path=str(p),
        vendor_id=dev.get("vendor_id") or _read(p / "idVendor"),
        product_id=dev.get("product_id") or _read(p / "idProduct"),
        manufacturer=_read(p / "manufacturer"), product=_read(p / "product"), serial=_read(p / "serial"),
        device_class=dev.get("device_class", 0), interfaces=interfaces,
        authorized=None if auth == "" else auth == "1",
    )
