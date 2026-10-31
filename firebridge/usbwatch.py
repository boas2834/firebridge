"""udev-Überwachung für USB-Geräte und Eingabegeräte (Etappe 4).

Ergänzt devices.DeviceMonitor (der nur Block-Geräte sieht): Ein von USBGuard
gesperrtes Gerät bekommt keine Treiber, es erscheint also nie als /dev/sdX.
Deshalb beobachtet der Dienst zusätzlich
  * subsystem "usb", devtype "usb_device": jedes eingesteckte USB-Gerät
  * subsystem "input", Knoten /dev/input/event*: neue Tastaturen
und meldet beides an badusb.Guard.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from .badusb import Guard
from .usbdev import read_usb_device

log = logging.getLogger(__name__)


class UsbMonitor:
    def __init__(self, guard: Guard):
        import pyudev  # erst hier, damit Tests ohne udev laufen

        self._pyudev = pyudev
        self.context = pyudev.Context()
        self.guard = guard
        self._observer = None

    def start(self) -> None:
        monitor = self._pyudev.Monitor.from_netlink(self.context)
        monitor.filter_by(subsystem="usb", device_type="usb_device")
        monitor.filter_by(subsystem="input")
        self._observer = self._pyudev.MonitorObserver(monitor, callback=self._event, name="udev-usb")
        self._observer.start()
        # Was jetzt schon steckt, ist vertraut (eigene Tastatur, Maus, Boot-Stick)
        for dev in self.context.list_devices(subsystem="usb", DEVTYPE="usb_device"):
            info = read_usb_device(dev.sys_path)
            if info is not None:
                self.guard.device_present(info)

    def stop(self) -> None:
        if self._observer:
            self._observer.stop()

    def _event(self, dev) -> None:
        try:
            if dev.subsystem == "usb":
                self._usb(dev)
            elif dev.subsystem == "input":
                self._input(dev)
        except Exception:
            log.exception("udev-Ereignis %s %s", dev.action, dev.sys_path)

    def _usb(self, dev) -> None:
        port = Path(dev.sys_path).name
        if dev.action == "add":
            # Eigener Thread: das Warten unten soll Tastatur-Ereignisse nicht aufhalten
            threading.Thread(target=self._usb_added, args=(dev.sys_path,), name="usb-add", daemon=True).start()
        elif dev.action == "remove":
            self.guard.device_removed(port)

    def _usb_added(self, sys_path: str, wait: float = 1.0) -> None:
        """USBGuard entscheidet erst kurz nach dem Einstecken (bis dahin authorized = 0).
        Kurz warten, damit ein erlaubter Stick nicht als gesperrt gemeldet wird."""
        deadline = time.monotonic() + wait
        while True:
            info = read_usb_device(sys_path)
            if info is None:
                return  # schon wieder abgezogen
            if info.authorized is not False or time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        self.guard.device_added(info)

    def _input(self, dev) -> None:
        node = dev.device_node or ""
        if not Path(node).name.startswith("event"):
            return
        if dev.action == "remove":
            self.guard.on_input_gone(node)
            return
        if dev.action != "add":
            return
        props = dev.properties
        # ID_INPUT_KEYBOARD setzt udev, sobald das Gerät Buchstaben- oder Zifferntasten hat. Reine
        # Zusatztasten (ID_INPUT_KEY, z. B. an Mäusen) können keine Befehle tippen und bleiben frei.
        keyboard = props.get("ID_INPUT_KEYBOARD") == "1"
        usb = dev.find_parent("usb", "usb_device")
        port = Path(usb.sys_path).name if usb is not None else ""
        self.guard.input_added(node, port, keyboard)
