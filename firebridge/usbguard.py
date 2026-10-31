"""USB-Geräte sperren und freigeben (Etappe 4).

Läuft USBGuard, entscheidet er beim Einstecken: Hubs und reine
Massenspeicher sind erlaubt (packaging/usbguard/50-firebridge.conf), alles
andere bleibt gesperrt (authorized = 0), bis die Firebridge es auf Wunsch
des Bedieners mit "usbguard allow-device <id>" freigibt. Die Freigabe gilt
nur, bis das Gerät abgezogen wird.

Fehlt USBGuard, sperrt die Firebridge selbst über sysfs (authorized = 0).
Das ist schwächer: Der Kernel hat das Gerät dann schon kurz zugelassen, bis
die Firebridge reagiert. Deshalb zeigt die Oberfläche das als "eingeschränkt".
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

log = logging.getLogger(__name__)

SYSFS_USB = Path("/sys/bus/usb/devices")
_LINE = re.compile(r"^\s*(\d+):\s+(allow|block|reject)\s+(.*)$")
_PORT = re.compile(r'via-port\s+"([^"]*)"')
_ID = re.compile(r"\bid\s+([0-9a-fA-F*]{4}:[0-9a-fA-F*]{4})")
_NAME = re.compile(r'\bname\s+"([^"]*)"')


class GateError(RuntimeError):
    pass


def parse_list_devices(text: str) -> list[dict]:
    """Ausgabe von "usbguard list-devices" → [{"id", "target", "port", "usb_id", "name"}]."""
    out = []
    for line in text.splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        rest = m.group(3)
        port = _PORT.search(rest)
        uid = _ID.search(rest)
        name = _NAME.search(rest)
        out.append({"id": int(m.group(1)), "target": m.group(2), "port": port.group(1) if port else "",
                    "usb_id": uid.group(1).lower() if uid else "", "name": name.group(1) if name else ""})
    return out


class UsbGate:
    def __init__(self, binary: str = "usbguard", sysfs: Path = SYSFS_USB, runner=subprocess.run,
                 timeout: float = 10.0):
        self.binary = binary
        self.sysfs = sysfs
        self._run_fn = runner
        self.timeout = timeout
        self._lock = threading.Lock()
        self._status: dict | None = None
        self._checked = 0.0

    # ------------------------------------------------------------ Status

    def _run(self, *args: str) -> str:
        try:
            res = self._run_fn([self.binary, *args], capture_output=True, text=True, timeout=self.timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            raise GateError(f"usbguard {args[0]}: {exc}")
        if res.returncode != 0:
            msg = (res.stderr or res.stdout or "").strip().splitlines()
            raise GateError(f"usbguard {args[0]}: {msg[-1] if msg else f'Rückgabewert {res.returncode}'}")
        return res.stdout

    def status(self, refresh: bool = False) -> dict:
        """{"mode": "usbguard" | "sysfs", "active": bool, "message": str}"""
        with self._lock:
            if not refresh and self._status is not None and time.monotonic() - self._checked < 30:
                return dict(self._status)
            if shutil.which(self.binary) is None and "/" not in self.binary:
                st = {"mode": "sysfs", "active": False,
                      "message": "USBGuard ist nicht installiert. Die Firebridge sperrt neue Geräte selbst, "
                                 "aber erst kurz nach dem Einstecken (sudo ./install.sh erneut ausführen)."}
            else:
                try:
                    devices = parse_list_devices(self._run("list-devices"))
                    blocked = sum(1 for d in devices if d["target"] != "allow")
                    st = {"mode": "usbguard", "active": True,
                          "message": f"USBGuard aktiv: {len(devices)} Geräte, {blocked} gesperrt"}
                except GateError as exc:
                    st = {"mode": "sysfs", "active": False,
                          "message": f"USBGuard antwortet nicht ({exc}). Die Firebridge sperrt neue Geräte "
                                     "selbst, aber erst kurz nach dem Einstecken."}
            self._status, self._checked = st, time.monotonic()
            return dict(st)

    @property
    def active(self) -> bool:
        return self.status()["active"]

    # ------------------------------------------------------------ Aktionen

    def authorized(self, port: str) -> bool | None:
        try:
            return (self.sysfs / port / "authorized").read_text().strip() == "1"
        except OSError:
            return None

    def _usbguard_id(self, port: str) -> int:
        for d in parse_list_devices(self._run("list-devices")):
            if d["port"] == port:
                return d["id"]
        raise GateError(f"USBGuard kennt kein Gerät an Port {port}")

    def _write_sysfs(self, port: str, value: str) -> None:
        if not port or "/" in port or port.startswith("."):
            raise GateError(f"ungültiger Port {port!r}")
        try:
            (self.sysfs / port / "authorized").write_text(value)
        except OSError as exc:
            raise GateError(f"{self.sysfs / port / 'authorized'}: {exc.strerror or exc}")

    def allow(self, port: str) -> str:
        """Gerät bis zum Abziehen zulassen. Rückgabe: wie (für das Protokoll)."""
        return self._set(port, True)

    def block(self, port: str) -> str:
        """Gerät sperren (alle Treiber werden gelöst, Tastatur und Speicher verschwinden)."""
        return self._set(port, False)

    def _set(self, port: str, allow: bool) -> str:
        if self.active:
            try:
                dev_id = self._usbguard_id(port)
                self._run("allow-device" if allow else "block-device", str(dev_id))
                return f"USBGuard ({'allow' if allow else 'block'}-device {dev_id})"
            except GateError as exc:
                log.warning("USBGuard: %s, nutze sysfs", exc)
        self._write_sysfs(port, "1" if allow else "0")
        return f"sysfs (authorized = {'1' if allow else '0'})"
