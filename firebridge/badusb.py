"""BadUSB-Abwehr (Etappe 4): Alarme für neue USB-Geräte, Freigabe mit Tipp-Probe.

Ablauf für ein neu eingestecktes Gerät, das kein reiner Speicher und kein Hub ist:

  1. USBGuard hat es gesperrt (ohne USBGuard sperrt es die Firebridge über sysfs).
     Es entsteht ein Alarm, die Oberfläche zeigt ihn als Dialog.
  2. Speicher mit Tastatur/Netzwerk (badusb) und Netzwerkadapter bleiben immer
     gesperrt. Der Bediener kann den Alarm nur bestätigen (dismiss).
  3. Eingabegeräte und sonstige Geräte lassen sich freigeben (allow). Kann das
     Gerät Tasten senden, beginnt die Tipp-Probe: Der HID-Wächter hält jede
     Tastatur des Geräts fest (EVIOCGRAB), die Oberfläche zeigt einen Code.
     Kommt der Code mit menschlichem Tempo, wird die Tastatur losgelassen.
     Tippt das Gerät selbstständig (zu schnell, Tastenkombinationen, Befehle),
     wird es sofort wieder gesperrt und der Alarm zeigt, was es tippen wollte.

Tastaturen, die schon beim Start des Dienstes steckten, gelten als vertraut.
Eine neue Tastatur, deren USB-Gerät noch nicht bekannt ist (das input-Ereignis
kommt manchmal vor dem usb-Ereignis), wird vorsorglich sofort festgehalten.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import secrets
import threading
import time
from typing import Callable

from .hidguard import KeyAnalyzer
from .states import StateError
from .usbdev import KIND_TEXT, NEVER_ALLOW, UsbInfo
from .usbguard import GateError, UsbGate

log = logging.getLogger(__name__)

PROBE_SECONDS = 120
PROBE_TRIES = 3
# Erscheint nach der Freigabe so lange keine Tastatur, war es nur eine Maus o. Ä.
NO_KEYBOARD_SECONDS = 5
CODE_LEN = 4


@dataclasses.dataclass
class Alert:
    id: str
    dev: UsbInfo
    time: str
    state: str = "gesperrt"     # gesperrt | probe | alarm | freigegeben | erledigt
    blocked: bool = True
    message: str = ""
    code: str = ""
    deadline: float = 0.0
    probe_started: float = 0.0
    tries: int = 0
    analyzer: KeyAnalyzer | None = None
    inputs: set[str] = dataclasses.field(default_factory=set)   # festgehaltene /dev/input/eventN
    reasons: list[str] = dataclasses.field(default_factory=list)
    shown_keys: int = 0
    how: str = ""                # wie gesperrt/freigegeben wurde (USBGuard oder sysfs)

    @property
    def open(self) -> bool:
        return self.state in ("gesperrt", "probe", "alarm")

    def to_dict(self, now: float) -> dict:
        d = {"id": self.id, "time": self.time, "state": self.state, "blocked": self.blocked,
             "message": self.message, "device": self.dev.to_dict(), "kind": self.dev.kind,
             "allow_possible": self.state == "gesperrt" and self.dev.kind not in NEVER_ALLOW,
             "reasons": list(self.reasons), "how": self.how, "tries": self.tries,
             "tries_max": PROBE_TRIES}
        if self.state == "probe":
            d["code"] = self.code
            d["seconds_left"] = max(0, int(self.deadline - now))
        if self.analyzer is not None:
            d["keys"] = self.analyzer.summary()
        return d


class Guard:
    def __init__(self, gate: UsbGate, grabber_factory: Callable, log_line: Callable[[str], None],
                 notify: Callable[[], None], history: Callable[[dict], None],
                 clock: Callable[[], float] = time.monotonic, wall: Callable[[], float] = time.time,
                 probe_seconds: int = PROBE_SECONDS):
        self.gate = gate
        self._log = log_line
        self._notify = notify
        self._history = history
        self.clock = clock
        self.wall = wall
        self.probe_seconds = probe_seconds
        self.grabber = grabber_factory(self.on_key, self.on_input_gone)
        self._lock = threading.RLock()
        self.alerts: dict[str, Alert] = {}         # nach Alarm-ID
        self._by_port: dict[str, str] = {}         # Port → Alarm-ID (solange das Gerät steckt)
        self.trusted: set[str] = set()             # Ports vertrauter Geräte
        self._orphans: dict[str, str] = {}         # festgehaltene Eingaben ohne bekanntes Gerät: node → Port
        self._input_port: dict[str, str] = {}      # node → Port
        self._counter = 0
        self._last_key_notify = 0.0
        self._stop = threading.Event()

    # ------------------------------------------------------------ Status

    def status(self) -> dict:
        st = self.gate.status()
        now = self.clock()
        with self._lock:
            alerts = [a.to_dict(now) for a in self.alerts.values() if a.open]
            grabbed = len(self.grabber.grabbed()) if hasattr(self.grabber, "grabbed") else 0
        return {**st, "grabbed": grabbed, "alerts": alerts}

    def start(self, interval: float = 1.0) -> None:
        def loop():
            while not self._stop.wait(interval):
                self.tick()
        threading.Thread(target=loop, name="badusb-tick", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        if hasattr(self.grabber, "close"):
            self.grabber.close()

    # ------------------------------------------------------------ Geräte

    def device_present(self, dev: UsbInfo) -> None:
        """Gerät steckte schon beim Start: vertraut (so sperrt sich niemand die eigene Tastatur aus)."""
        with self._lock:
            self.trusted.add(dev.port)

    def device_added(self, dev: UsbInfo) -> None:
        kind = dev.kind
        if kind in ("speicher", "hub") and dev.authorized is not False:
            return   # erlaubt, wie es sein soll (ein gesperrter Speicher bekommt unten einen Alarm)
        with self._lock:
            if dev.port in self._by_port:
                return  # doppelte Meldung
            self.trusted.discard(dev.port)
            self._counter += 1
            alert = Alert(id=str(self._counter), dev=dev, time=_now_iso())
            self.alerts[alert.id] = alert
            self._by_port[dev.port] = alert.id
            blocked = dev.authorized is False
        ifaces = ", ".join(f"{i.name} ({i.code})" for i in dev.interfaces) or "keine lesbar"
        self._log(f"USB-Gerät eingesteckt: {dev.display_name} {dev.usb_id} an Port {dev.port} "
                  f"→ {KIND_TEXT[kind]}, Schnittstellen: {ifaces}")
        how = "USBGuard"
        if not blocked:
            # USBGuard fehlt oder hat das Gerät zugelassen: selbst sperren
            try:
                how = self.gate.block(dev.port)
                blocked = True
            except GateError as exc:
                self._log(f"FEHLER: Gerät an Port {dev.port} ließ sich nicht sperren: {exc}")
                how = "nicht gesperrt"
        with self._lock:
            alert.blocked = blocked
            alert.how = how
            alert.message = _blocked_message(dev, blocked)
            # Tastaturen, die vor dem usb-Ereignis festgehalten wurden, gehören jetzt zu diesem Alarm
            for node, port in list(self._orphans.items()):
                if port == dev.port:
                    alert.inputs.add(node)
                    del self._orphans[node]
        self._log(f"{'Gesperrt' if blocked else 'NICHT gesperrt'} ({how}): {dev.display_name} – {alert.message}")
        self._history(_history_entry(dev, {"badusb": "BadUSB", "netzwerk": "Netzwerkadapter gesperrt",
                                          "eingabe": "Eingabegerät gesperrt"}.get(kind, "USB-Gerät gesperrt")))
        self._notify()

    def device_removed(self, port: str) -> None:
        with self._lock:
            self.trusted.discard(port)
            aid = self._by_port.pop(port, None)
            alert = self.alerts.pop(aid, None) if aid else None
            nodes = set(alert.inputs) if alert else set()
            nodes |= {n for n, p in self._orphans.items() if p == port}
            for n in nodes:
                self._orphans.pop(n, None)
                self._input_port.pop(n, None)
        for n in nodes:
            self.grabber.release(n)
        if alert is not None:
            if alert.open:
                self._log(f"USB-Gerät abgezogen: {alert.dev.display_name} (Port {port})")
            self._notify()

    def input_added(self, node: str, port: str, keyboard: bool) -> None:
        """Ein Eingabegerät (/dev/input/eventN) ist erschienen. port = USB-Port des Geräts ("" = kein USB)."""
        if not keyboard or not port:
            return
        with self._lock:
            if port in self.trusted:
                return
            aid = self._by_port.get(port)
            alert = self.alerts.get(aid) if aid else None
            if alert is not None and alert.state == "freigegeben" and not alert.inputs:
                # Freigegeben ohne Tasten (z. B. Maus), sendet jetzt doch Tasten: Probe nachholen
                self._begin_probe(alert)
        try:
            self.grabber.grab(node)
        except OSError as exc:
            self._log(f"FEHLER: Tastatur {node} ließ sich nicht festhalten: {exc}")
            if alert is not None:
                self._raise_alarm(alert, [f"Tastatur ließ sich nicht abfangen ({exc.strerror or exc})"])
            return
        with self._lock:
            self._input_port[node] = port
            if alert is None:
                self._orphans[node] = port
            else:
                alert.inputs.add(node)
                if alert.analyzer is None:
                    alert.analyzer = KeyAnalyzer(self.wall())
        self._log(f"Tastatur {node} (Port {port}) wird festgehalten, ihre Tasten erreichen den Rechner nicht")
        self._notify()

    def on_input_gone(self, node: str) -> None:
        with self._lock:
            self._orphans.pop(node, None)
            port = self._input_port.pop(node, None)
            alert = self.alerts.get(self._by_port.get(port, "")) if port else None
            if alert is not None:
                alert.inputs.discard(node)

    # ------------------------------------------------------------ Bediener

    def allow(self, alert_id: str) -> dict:
        with self._lock:
            alert = self.alerts.get(alert_id)
            if alert is None or not alert.open:
                raise StateError("Dieser Alarm ist nicht mehr offen")
            if alert.dev.kind in NEVER_ALLOW:
                raise StateError(f"{KIND_TEXT[alert.dev.kind]} lassen sich nicht freigeben")
            if alert.state != "gesperrt":
                raise StateError("Das Gerät wird schon geprüft")
            dev = alert.dev
            if dev.keyboard_capable:
                self._begin_probe(alert)
        try:
            how = self.gate.allow(dev.port)
        except GateError as exc:
            with self._lock:
                alert.state = "gesperrt"
            raise StateError(f"Freigeben fehlgeschlagen: {exc}")
        with self._lock:
            alert.blocked = False
            alert.how = how
            if not dev.keyboard_capable:
                alert.state = "freigegeben"
                alert.message = "Bis zum Abziehen zugelassen."
        if dev.keyboard_capable:
            self._log(f"Tastatur {dev.display_name} vorläufig zugelassen ({how}), Tipp-Probe läuft")
        else:
            self._log(f"Freigegeben bis zum Abziehen ({how}): {dev.display_name} an Port {dev.port}")
            self._history(_history_entry(dev, "USB-Gerät freigegeben"))
        self._notify()
        return alert.to_dict(self.clock())

    def dismiss(self, alert_id: str) -> dict:
        """Alarm schließen, das Gerät bleibt gesperrt (bzw. wird wieder gesperrt)."""
        with self._lock:
            alert = self.alerts.get(alert_id)
            if alert is None or not alert.open:
                raise StateError("Dieser Alarm ist nicht mehr offen")
            was = alert.state
            dev = alert.dev
        if not alert.blocked:
            try:
                alert.how = self.gate.block(dev.port)
                alert.blocked = True
            except GateError as exc:
                self._log(f"FEHLER beim Sperren: {exc}")
        with self._lock:
            alert.state = "erledigt"
            alert.message = "Gesperrt gelassen."
        self._log(f"Bestätigt: {dev.display_name} bleibt gesperrt" + (" (Tipp-Probe abgebrochen)" if was == "probe" else ""))
        self._notify()
        return alert.to_dict(self.clock())

    # ------------------------------------------------------------ Tipp-Probe

    def _begin_probe(self, alert: Alert) -> None:
        alert.state = "probe"
        alert.code = "".join(secrets.choice("123456789") for _ in range(CODE_LEN))
        alert.probe_started = self.clock()
        alert.deadline = alert.probe_started + self.probe_seconds
        alert.tries = 0
        alert.analyzer = KeyAnalyzer(self.wall())
        alert.message = "Code auf der neuen Tastatur eintippen und Enter drücken."

    def on_key(self, node: str, ts: float, code: int, value: int) -> None:
        with self._lock:
            port = self._input_port.get(node)
            alert = self.alerts.get(self._by_port.get(port, "")) if port else None
            if alert is None or alert.analyzer is None:
                return  # festgehalten ohne Alarm (z. B. vor dem usb-Ereignis): Tasten verwerfen
            if alert.state not in ("probe", "freigegeben", "gesperrt", "alarm"):
                return
            entry = alert.analyzer.feed(ts, code, value)
            reasons = alert.analyzer.reasons()
            state = alert.state
        if reasons:
            if state == "alarm":
                with self._lock:
                    alert.reasons = reasons     # weiter mitschreiben, was das Gerät tippen will
                self._notify_soon()
            else:
                self._raise_alarm(alert, reasons)
            return
        if entry is None or state != "probe":
            if value == 1:
                self._notify_soon()
            return
        if entry == alert.code:
            self._pass_probe(alert)
            return
        with self._lock:
            alert.tries += 1
            tries = alert.tries
        if tries >= PROBE_TRIES:
            self._raise_alarm(alert, [f"{PROBE_TRIES}-mal falscher Code"])
        else:
            with self._lock:
                alert.message = f"Falscher Code, noch {PROBE_TRIES - tries} Versuch(e)."
            self._log(f"Tipp-Probe {alert.dev.display_name}: falscher Code ({tries}/{PROBE_TRIES})")
            self._notify()

    def _notify_soon(self) -> None:
        """Bei schnellem Tippen höchstens zweimal pro Sekunde melden (der Rest kommt mit tick)."""
        now = self.clock()
        if now - self._last_key_notify >= 0.5:
            self._last_key_notify = now
            self._notify()

    def _pass_probe(self, alert: Alert) -> None:
        with self._lock:
            alert.state = "freigegeben"
            alert.message = "Tastatur freigegeben."
            nodes = set(alert.inputs)
            alert.inputs.clear()
            self.trusted.add(alert.dev.port)
            summary = alert.analyzer.summary() if alert.analyzer else {}
        for n in nodes:
            self.grabber.release(n)
            with self._lock:
                self._input_port.pop(n, None)
        self._log(f"Tipp-Probe bestanden: Tastatur {alert.dev.display_name} freigegeben "
                  f"(Abstand {summary.get('median_ms')} ms)")
        self._history(_history_entry(alert.dev, "Tastatur freigegeben"))
        self._notify()

    def _raise_alarm(self, alert: Alert, reasons: list[str]) -> None:
        with self._lock:
            if alert.state == "alarm":
                alert.reasons = reasons
                return
            alert.state = "alarm"
            alert.reasons = reasons
            alert.message = "Das Gerät hat selbstständig getippt und ist wieder gesperrt."
            dev = alert.dev
        try:
            alert.how = self.gate.block(dev.port)
            alert.blocked = True
        except GateError as exc:
            self._log(f"FEHLER beim Sperren: {exc} – Tasten bleiben trotzdem festgehalten")
        text = alert.analyzer.display(120) if alert.analyzer else ""
        self._log(f"ALARM: {dev.display_name} {dev.usb_id} tippt selbstständig: {'; '.join(reasons)}"
                  + (f" – abgefangen: {text}" if text else ""))
        self._history(_history_entry(dev, "BadUSB"))
        self._notify()

    def tick(self) -> None:
        now = self.clock()
        expired, running, mice = [], False, []
        with self._lock:
            for a in self.alerts.values():
                if a.state == "alarm" and a.analyzer is not None and a.analyzer.keys != a.shown_keys:
                    a.shown_keys = a.analyzer.keys   # zuletzt abgefangene Tasten noch anzeigen
                    running = True
                if a.state != "probe":
                    continue
                if not a.inputs and not (a.analyzer and a.analyzer.keys) \
                        and now - a.probe_started >= NO_KEYBOARD_SECONDS:
                    a.state = "freigegeben"
                    a.message = "Bis zum Abziehen zugelassen (keine Tastatur gefunden)."
                    mice.append(a)
                elif now >= a.deadline:
                    expired.append(a)
                else:
                    running = True
        for a in mice:
            self._log(f"Freigegeben bis zum Abziehen ({a.how}): {a.dev.display_name}, ohne Tastatur")
            self._history(_history_entry(a.dev, "USB-Gerät freigegeben"))
            self._notify()
        for a in expired:
            if a.analyzer is not None and a.analyzer.keys:
                self._raise_alarm(a, ["Zeit für die Tipp-Probe abgelaufen, getippt wurde aber etwas anderes"])
            else:
                with self._lock:
                    a.state = "erledigt"
                    a.message = "Keine Eingabe: Die Tasten des Geräts bleiben gesperrt, bis es abgezogen wird."
                self._log(f"Tipp-Probe {a.dev.display_name}: keine Eingabe, Tasten bleiben festgehalten "
                          "(zum neuen Versuch abziehen und wieder einstecken)")
                self._notify()
        if running:
            self._notify()   # Restzeit in der Oberfläche


def _blocked_message(dev: UsbInfo, blocked: bool) -> str:
    kind = dev.kind
    if not blocked:
        return "Das Gerät konnte nicht gesperrt werden. Bitte sofort abziehen."
    if kind == "badusb":
        return ("Ein Speicher, der sich zusätzlich als Tastatur oder Netzwerkkarte meldet, ist typisch für "
                "Angriffs-Sticks. Das Gerät ist komplett gesperrt. Bitte abziehen und der IT übergeben.")
    if kind == "netzwerk":
        return ("Ein USB-Netzwerkadapter könnte den Datenverkehr umleiten. Er bleibt gesperrt. "
                "Bitte abziehen.")
    if kind == "eingabe":
        return ("Neue Tastaturen und Mäuse sind gesperrt, weil sich Angriffs-Sticks als Tastatur ausgeben. "
                "Hast du dieses Gerät selbst angeschlossen, kannst du es freigeben.")
    return "Unbekannte USB-Geräte sind gesperrt. Wenn du es brauchst, kannst du es bis zum Abziehen freigeben."


def _now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _history_entry(dev: UsbInfo, result: str) -> dict:
    return {"id": "", "time": _now_iso(), "device": dev.display_name, "usb_id": dev.usb_id,
            "serial": dev.serial, "files": None, "infected": 0, "suspicious": 0, "result": result,
            "port": dev.port}
