"""firebridged: privilegierter Dienst (läuft als root unter systemd)."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

from dbus_next import BusType, DBusError, Message, MessageType
from dbus_next.aio import MessageBus

from . import BUS_NAME, OBJECT_PATH, __version__
from . import config as config_mod
from .core import Station
from .dbus_service import StationInterface
from .devices import DeviceMonitor
from .firewall import Firewall, FirewallError, NoFirewall
from .mounter import Mounter
from .reports import ReportStore

log = logging.getLogger("firebridged")


def _quiet_dbus_errors(loop: asyncio.AbstractEventLoop, context: dict) -> None:
    # dbus-next 0.2.3 schickt DBusError korrekt als Fehlerantwort, lässt die Ausnahme
    # danach aber weiterlaufen. Das ist kein Fehler des Dienstes, also nicht ins Journal.
    if isinstance(context.get("exception"), DBusError):
        return
    loop.default_exception_handler(context)


async def run(args) -> None:
    cfg = config_mod.load(args.config)
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(_quiet_dbus_errors)
    bus_type = BusType.SESSION if args.session_bus else BusType.SYSTEM
    bus = await MessageBus(bus_type=bus_type).connect()

    reports = ReportStore(cfg.reports_dir, cfg.history_file)
    reports.ensure()
    cfg.mount_root.mkdir(parents=True, exist_ok=True)

    if cfg.firewall == "off":
        firewall = NoFirewall()
        log.warning("Netzwerk-Sperre abgeschaltet (firewall = \"off\"), nur zum Testen verwenden!")
    else:
        firewall = Firewall(cfg.nft_binary)
        try:
            firewall.setup()
        except FirewallError:
            pass  # steht im Status, Übertragung bleibt gesperrt

    def start_update() -> None:
        """firebridge-update.service über systemd starten (aus einem Worker-Thread aufgerufen)."""
        async def call():
            reply = await bus.call(Message(destination="org.freedesktop.systemd1", path="/org/freedesktop/systemd1",
                                           interface="org.freedesktop.systemd1.Manager", member="StartUnit",
                                           signature="ss", body=[cfg.update_unit, "replace"]))
            if reply.message_type == MessageType.ERROR:
                raise RuntimeError(f"{cfg.update_unit} lässt sich nicht starten: "
                                   f"{reply.body[0] if reply.body else reply.error_name}")
        asyncio.run_coroutine_threadsafe(call(), loop).result(timeout=20)

    iface: StationInterface | None = None
    station = Station(cfg, Mounter(cfg.mount_root), reports,
                      emit=lambda kind, data: iface.emit(kind, data) if iface else None,
                      firewall=firewall, start_update=None if args.session_bus else start_update)
    guard = None
    if cfg.usb_guard and not args.no_udev:
        from .badusb import Guard
        from .hidguard import InputGrabber
        from .usbguard import UsbGate
        guard = Guard(UsbGate(cfg.usbguard_binary), InputGrabber,
                      log_line=station.guard_log, notify=station.guard_changed, history=station.guard_history,
                      probe_seconds=cfg.hid_probe_seconds)
        station.guard = guard
    iface = StationInterface(station, loop)
    iface.watch_senders(bus)
    bus.export(OBJECT_PATH, iface)
    await bus.request_name(BUS_NAME)
    log.info("firebridged %s bereit auf dem %s-Bus", __version__, bus_type.name.lower())

    eng = station.engine(refresh=True)
    log.info("Engine: %s %s (daily %s) – %s", eng.backend or "keine", eng.engine, eng.db_version, eng.message)
    station.start_watch()
    ana = station.analyzer.info()
    y = ana["yara"]
    log.info("Tiefenprüfung: YARA-X %s (%s Regeln%s), olevba %s, libmagic %s",
             y["yara_x"] or "fehlt", y["rules"], f", {y['message']}" if y["message"] else "",
             "ok" if ana["olevba"] else "fehlt", "ok" if ana["magic"] else "fehlt")

    monitor = usb_monitor = None
    if guard is not None:
        from .usbwatch import UsbMonitor
        usb_monitor = UsbMonitor(guard)
        usb_monitor.start()
        guard.start()
        log.info("BadUSB-Schutz: %s", guard.gate.status(refresh=True)["message"])
    elif not cfg.usb_guard:
        log.warning("BadUSB-Schutz abgeschaltet (usb_guard = false), nur zum Testen verwenden!")
    if not args.no_udev:
        monitor = DeviceMonitor(station.device_added, station.device_removed,
                                cfg.settle_seconds, cfg.ignore_serials)
        monitor.start()

    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    log.info("Beende, hänge Datenträger aus …")
    if monitor:
        monitor.stop()
    if usb_monitor:
        usb_monitor.stop()
    if guard:
        guard.stop()
    station.shutdown()
    bus.disconnect()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Firebridge-Dienst")
    ap.add_argument("--config", type=Path, help="Pfad zur Konfigurationsdatei")
    ap.add_argument("--session-bus", action="store_true", help="Session-Bus statt System-Bus (Entwicklung)")
    ap.add_argument("--no-udev", action="store_true", help="keine Geräteüberwachung (Entwicklung)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    for noisy in ("smbprotocol", "smbclient", "spnego"):  # protokollieren jedes SMB-Paket
        logging.getLogger(noisy).setLevel(logging.DEBUG if args.verbose else logging.WARNING)
    if os.geteuid() != 0 and not args.session_bus:
        log.warning("Läuft nicht als root: Einbinden und Auswerfen werden fehlschlagen")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
