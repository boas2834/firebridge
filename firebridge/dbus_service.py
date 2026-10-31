"""D-Bus-Schnittstelle des Dienstes.

Alle Daten gehen als JSON-Strings über den Bus. Das hält die Schnittstelle
klein und lässt sich mit busctl leicht von Hand testen:

    busctl call io.github.boas2834.Firebridge1 /io/github/boas2834/Firebridge1 \
        io.github.boas2834.Firebridge1 GetStatus

Wer die Methoden aufrufen darf, regelt die Policy-Datei
packaging/dbus/io.github.boas2834.Firebridge1.conf (Gruppe "firebridge").
"""

import asyncio
import contextvars
import json
import logging
import pwd

from dbus_next import DBusError, Message, MessageType
from dbus_next.service import ServiceInterface, method, signal

from . import INTERFACE, kiosk
from .admin import AdminError, AdminGate
from .core import Station
from .firewall import FirewallError
from .share import SettingsError
from .states import StateError

ERR_STATE = INTERFACE + ".Error.State"
ERR_FAILED = INTERFACE + ".Error.Failed"
ERR_ADMIN = INTERFACE + ".Error.AdminRequired"

log = logging.getLogger(__name__)

# Absender des gerade bearbeiteten Aufrufs. Wird vor dem Verteilen jeder Nachricht gesetzt; dbus_next
# startet async-Methoden als Task, und ein Task nimmt eine Kopie des Kontexts mit. So kennt jede Methode
# ihren eigenen Absender, auch wenn mehrere Aufrufe gleichzeitig laufen.
_SENDER: contextvars.ContextVar[str] = contextvars.ContextVar("firebridge_sender", default="")


def _dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def _loads(text: str) -> dict:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DBusError(ERR_FAILED, f"ungültiges JSON: {exc}")
    if not isinstance(data, dict):
        raise DBusError(ERR_FAILED, "JSON-Objekt erwartet")
    return data


class StationInterface(ServiceInterface):
    def __init__(self, station: Station, loop: asyncio.AbstractEventLoop):
        super().__init__(INTERFACE)
        self.station = station
        self.loop = loop
        self.bus = None
        self.admin = AdminGate(station.cfg.admin_file)

    def watch_senders(self, bus) -> None:
        """Für Freigabe-Protokoll und Admin-Anmeldung: Absender jedes Aufrufs merken (siehe _SENDER) und
        mitbekommen, wenn eine Oberfläche sich abmeldet (dann endet ihre Admin-Anmeldung)."""
        self.bus = bus
        bus.add_message_handler(self._note_sender)
        rule = ("type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',"
                "member='NameOwnerChanged'")
        self.loop.create_task(bus.call(Message(
            destination="org.freedesktop.DBus", path="/org/freedesktop/DBus", interface="org.freedesktop.DBus",
            member="AddMatch", signature="s", body=[rule])))

    def _note_sender(self, msg: Message):
        if msg.message_type == MessageType.METHOD_CALL:
            _SENDER.set(msg.sender or "")
        elif (msg.message_type == MessageType.SIGNAL and msg.member == "NameOwnerChanged"
              and len(msg.body) == 3 and msg.body[0].startswith(":") and not msg.body[2]):
            self.admin.forget(msg.body[0])
        return None  # nicht selbst beantworten, normal weiterverteilen

    async def _who(self) -> tuple[str, int | None, str]:
        """(Absender, uid, Benutzername) des Aufrufers, wie ihn der D-Bus-Daemon kennt (nicht fälschbar)."""
        sender = _SENDER.get()
        if not sender or self.bus is None:
            return sender, None, ""
        try:
            reply = await self.bus.call(Message(
                destination="org.freedesktop.DBus", path="/org/freedesktop/DBus",
                interface="org.freedesktop.DBus", member="GetConnectionUnixUser", signature="s", body=[sender]))
            if reply.message_type == MessageType.ERROR:
                raise RuntimeError(reply.body[0] if reply.body else reply.error_name)
            uid = int(reply.body[0])
        except Exception as exc:  # Protokoll trotzdem schreiben, nur ohne Namen
            log.warning("Aufrufer %s unbekannt: %s", sender, exc)
            return sender, None, ""
        try:
            return sender, uid, pwd.getpwuid(uid).pw_name
        except KeyError:
            return sender, uid, f"uid {uid}"

    async def _actor(self) -> str:
        """Name fürs Protokoll; mit Admin-Anmeldung als „Admin (user)“."""
        sender, uid, name = await self._who()
        if uid != 0 and sender and self.admin.active(sender) > 0:
            return f"Admin ({name})" if name else "Admin"
        return name

    async def _require_admin(self) -> None:
        sender, uid, _ = await self._who()
        if self.bus is None:  # Tests ohne Bus
            return
        try:
            self.admin.require(sender, uid)
        except AdminError as exc:
            raise DBusError(ERR_ADMIN, str(exc))

    def _admin_status(self, sender: str, uid: int | None) -> dict:
        return {"has_password": self.admin.has_password(), "root": uid == 0,
                "active_seconds": int(self.admin.active(sender)) if sender else 0}

    @method()
    async def AdminStatus(self) -> 's':
        sender, uid, _ = await self._who()
        return _dumps(self._admin_status(sender, uid))

    @method()
    async def AdminLogin(self, password: 's') -> 's':
        sender, uid, name = await self._who()
        try:
            await self.loop.run_in_executor(None, self.admin.login, sender, password)
        except AdminError as exc:
            await self.loop.run_in_executor(None, self.station.audit_admin, name, f"Admin-Anmeldung abgelehnt: {exc}")
            raise DBusError(ERR_ADMIN, str(exc))
        await self.loop.run_in_executor(None, self.station.audit_admin, name, "Als Admin angemeldet")
        return _dumps(self._admin_status(sender, uid))

    @method()
    async def AdminLogout(self) -> 's':
        sender, uid, _ = await self._who()
        self.admin.logout(sender)
        return _dumps(self._admin_status(sender, uid))

    @method()
    async def AdminSetPassword(self, password: 's') -> 's':
        """Neues Admin-Passwort. Braucht die Admin-Anmeldung, außer es ist noch keins festgelegt."""
        sender, uid, name = await self._who()
        if self.admin.has_password():
            await self._require_admin()
        first = not self.admin.has_password()
        try:
            await self.loop.run_in_executor(None, self.admin.set_password, password)
        except AdminError as exc:
            raise DBusError(ERR_FAILED, str(exc))
        await self.loop.run_in_executor(None, self.station.audit_admin, name,
                                        "Admin-Passwort festgelegt" if first else "Admin-Passwort geändert")
        if uid != 0:
            self.admin.login(sender, password)  # gleich angemeldet bleiben
        return _dumps(self._admin_status(sender, uid))

    # Wird von Station aus beliebigen Threads aufgerufen
    def emit(self, kind: str, data) -> None:
        payload = data if isinstance(data, str) else _dumps(data)
        fn = {"state": self.StateChanged, "progress": self.ScanProgress, "transfer": self.TransferProgress,
              "virustotal": self.VtProgress, "log": self.LogLine}[kind]
        self.loop.call_soon_threadsafe(fn, payload)

    async def _call(self, fn, *args):
        try:
            return await self.loop.run_in_executor(None, fn, *args)
        except (StateError, SettingsError) as exc:
            raise DBusError(ERR_STATE, str(exc))
        except FirewallError as exc:
            raise DBusError(ERR_FAILED, str(exc))
        except (OSError, ValueError, RuntimeError) as exc:
            raise DBusError(ERR_FAILED, str(exc))

    @method()
    async def GetStatus(self) -> 's':
        return _dumps(await self._call(self.station.status))

    @method()
    async def Scan(self) -> 'b':
        await self._call(self.station.scan)
        return True

    @method()
    async def CancelScan(self) -> 'b':
        await self._call(self.station.cancel)
        return True

    @method()
    async def Eject(self) -> 'b':
        await self._call(self.station.eject)
        return True

    @method()
    async def Transfer(self, target_id: 's', files: 's') -> 'b':
        """target_id = "" überträgt auf das Standardziel; files = "" alle sauberen Dateien,
        sonst eine JSON-Liste der Berichtspfade ("sdb1/Ordner/datei.txt")."""
        selected = None
        if files:
            try:
                selected = json.loads(files)
            except json.JSONDecodeError as exc:
                raise DBusError(ERR_FAILED, f"ungültiges JSON: {exc}")
            if not isinstance(selected, list) or not all(isinstance(f, str) for f in selected):
                raise DBusError(ERR_FAILED, "Liste von Pfaden erwartet")
        await self._call(self.station.transfer, target_id, selected, await self._actor())
        return True

    @method()
    async def CancelTransfer(self) -> 'b':
        await self._call(self.station.cancel_transfer)
        return True

    @method()
    async def GetShare(self) -> 's':
        return _dumps(await self._call(self.station.get_share))

    @method()
    async def SetShare(self, settings: 's') -> 's':
        await self._require_admin()
        return _dumps(await self._call(self.station.set_share, _loads(settings)))

    @method()
    async def DeleteShare(self, target_id: 's') -> 's':
        await self._require_admin()
        return _dumps(await self._call(self.station.delete_share, target_id))

    @method()
    async def SelectShare(self, target_id: 's') -> 's':
        await self._require_admin()
        return _dumps(await self._call(self.station.select_share, target_id))

    @method()
    async def TestShare(self, settings: 's') -> 's':
        """settings = "" testet die gespeicherten Einstellungen."""
        if settings:  # ungespeicherte Daten: öffnet das Netz zu einem beliebigen Server
            await self._require_admin()
        return _dumps(await self._call(self.station.test_share, _loads(settings) if settings else None))

    @method()
    async def Release(self, files: 's') -> 's':
        """JSON-Liste der Berichtspfade, die freigegeben sein sollen (alle anderen auffälligen bleiben gesperrt)."""
        try:
            selected = json.loads(files) if files else []
        except json.JSONDecodeError as exc:
            raise DBusError(ERR_FAILED, f"ungültiges JSON: {exc}")
        if not isinstance(selected, list) or not all(isinstance(f, str) for f in selected):
            raise DBusError(ERR_FAILED, "Liste von Pfaden erwartet")
        await self._require_admin()
        return _dumps(await self._call(self.station.release, selected, await self._actor()))

    @method()
    async def SetPolicy(self, policy: 's') -> 's':
        await self._require_admin()
        return _dumps(await self._call(self.station.set_policy, _loads(policy)))

    @method()
    async def UpdateNow(self) -> 'b':
        """Virensignaturen und YARA-Regeln sofort aktualisieren (startet firebridge-update.service)."""
        await self._call(self.station.update_now)
        return True

    @method()
    async def UsbAllow(self, alert_id: 's') -> 's':
        """Gesperrtes USB-Gerät freigeben; bei Tastaturen beginnt die Tipp-Probe."""
        await self._require_admin()
        return _dumps(await self._call(self.station.usb_allow, alert_id, await self._actor()))

    @method()
    async def UsbDismiss(self, alert_id: 's') -> 's':
        """Alarm bestätigen, das Gerät bleibt gesperrt."""
        return _dumps(await self._call(self.station.usb_dismiss, alert_id))

    @method()
    async def GetVirusTotal(self) -> 's':
        return _dumps(await self._call(self.station.get_virustotal))

    @method()
    async def SetVirusTotal(self, settings: 's') -> 's':
        """Stufe, Lizenz (mit confirm_noncommercial), Schwelle; optional api_key oder clear_key.
        Der Key wird nie zurückgegeben."""
        await self._require_admin()
        return _dumps(await self._call(self.station.set_virustotal, _loads(settings)))

    @method()
    async def TestVirusTotal(self) -> 's':
        return _dumps(await self._call(self.station.vt_test))

    @method()
    async def VirusTotalCheck(self) -> 'b':
        """Noch offene Dateien erneut bei VirusTotal abfragen."""
        await self._call(self.station.vt_check)
        return True

    @method()
    async def VirusTotalUpload(self, files: 's', notice_confirmed: 'b') -> 'b':
        """JSON-Liste der Berichtspfade (nur bei VirusTotal unbekannte). notice_confirmed: der Bediener hat
        bestätigt, dass hochgeladene Dateien von Dritten eingesehen werden können."""
        try:
            selected = json.loads(files) if files else []
        except json.JSONDecodeError as exc:
            raise DBusError(ERR_FAILED, f"ungültiges JSON: {exc}")
        if not isinstance(selected, list) or not all(isinstance(f, str) for f in selected):
            raise DBusError(ERR_FAILED, "Liste von Pfaden erwartet")
        await self._require_admin()
        await self._call(self.station.vt_upload, selected, bool(notice_confirmed), await self._actor())
        return True

    @method()
    async def VirusTotalSend(self, files: 's', upload: 'b', notice_confirmed: 'b') -> 'b':
        """Nur die ausgewählten Dateien (JSON-Liste der Berichtspfade) abfragen; upload = unbekannte davon
        hochladen (nur Stufe Upload, nur mit bestätigtem Hinweis)."""
        try:
            selected = json.loads(files) if files else []
        except json.JSONDecodeError as exc:
            raise DBusError(ERR_FAILED, f"ungültiges JSON: {exc}")
        if not isinstance(selected, list) or not all(isinstance(f, str) for f in selected):
            raise DBusError(ERR_FAILED, "Liste von Pfaden erwartet")
        if upload:
            await self._require_admin()
        await self._call(self.station.vt_send, selected, bool(upload), bool(notice_confirmed),
                         await self._actor() if upload else "")
        return True

    @method()
    async def CancelVirusTotal(self) -> 'b':
        await self._call(self.station.vt_cancel)
        return True

    @method()
    async def GetHistory(self, limit: 'i') -> 's':
        return _dumps(await self._call(self.station.history, max(1, min(limit, 2000))))

    @method()
    async def GetAudit(self, limit: 'i') -> 's':
        """Freigabe-Protokoll, neueste zuerst: wer hat wann Dateien, USB-Geräte, Übertragungen oder
        VirusTotal-Uploads freigegeben."""
        return _dumps(await self._call(self.station.audit_log, max(1, min(limit, 2000))))

    @method()
    async def SetKiosk(self, on: 'b') -> 's':
        """Kioskmodus ein- oder ausschalten (wirkt ab dem nächsten Start). Über die Unit
        firebridge-kiosk@an|aus.service, weil der Dienst /etc nicht beschreiben darf."""
        await self._require_admin()
        st = kiosk.status()
        if not st["available"]:
            raise DBusError(ERR_FAILED, st["reason"])
        if st["on"] != on:
            unit = f"firebridge-kiosk@{'an' if on else 'aus'}.service"
            intro = await self.bus.introspect("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
            mgr = self.bus.get_proxy_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                                            intro).get_interface("org.freedesktop.systemd1.Manager")
            await mgr.call_start_unit(unit, "replace")
            for _ in range(100):           # oneshot: warten, bis die LightDM-Datei da bzw. weg ist
                if kiosk.is_on() == on:
                    break
                await asyncio.sleep(0.2)
            else:
                raise DBusError(ERR_FAILED, f"Kioskmodus ließ sich nicht {'ein' if on else 'aus'}schalten, "
                                f"Details: journalctl -u {unit}")
            await self.loop.run_in_executor(None, self.station.audit_admin, await self._actor(),
                                            "Kioskmodus eingeschaltet" if on else "Kioskmodus ausgeschaltet")
        return _dumps(kiosk.status())

    @method()
    async def AdminCheck(self, purpose: 's') -> 'b':
        """Nur prüfen, ob der Aufrufer Admin ist (z. B. bevor die Oberfläche den Kioskmodus verlässt)."""
        await self._require_admin()
        if purpose == "kiosk":
            await self.loop.run_in_executor(None, self.station.audit_admin, await self._actor(),
                                            "Kioskmodus verlassen")
        return True

    @method()
    async def ClearHistory(self) -> 's':
        """Verlauf und Prüfberichte löschen; das Freigabe-Protokoll bleibt und vermerkt es."""
        await self._require_admin()
        return _dumps(await self._call(self.station.clear_history, await self._actor()))

    @method()
    async def GetQuarantine(self, limit: 'i') -> 's':
        """Infizierte, gesperrte und freigegebene auffällige Dateien aus den letzten Prüfungen."""
        return _dumps(await self._call(self.station.quarantine, max(1, min(limit, 5000))))

    @method()
    async def GetReport(self, report_id: 's') -> 's':
        return _dumps(await self._call(self.station.report, report_id))

    @signal()
    def StateChanged(self, status: 's') -> 's':
        return status

    @signal()
    def ScanProgress(self, progress: 's') -> 's':
        return progress

    @signal()
    def TransferProgress(self, progress: 's') -> 's':
        return progress

    @signal()
    def VtProgress(self, progress: 's') -> 's':
        return progress

    @signal()
    def LogLine(self, line: 's') -> 's':
        return line
