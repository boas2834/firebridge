"""Zustandsmaschine von Firebridge.

Die Klasse Station kennt weder D-Bus noch udev. Sie bekommt Gerätemeldungen
herein, führt die Aktionen aus und meldet Änderungen über emit(kind, data):
  * "state":    vollständiger Status (dict), nach jedem Zustandswechsel
  * "progress": Scan-Fortschritt (dict), höchstens einige Male pro Sekunde
  * "transfer": Fortschritt der Übertragung (dict)
  * "log":      eine Protokollzeile (str)

Netzwerk: Der Dienst hat nur in zwei Fällen ein offenes nftables-Fenster zum
Ziel-Server, nämlich während einer freigegebenen Übertragung (Zustand
UEBERTRAGUNG) und während eines Verbindungstests aus den Einstellungen. Beides
ist nie möglich, solange ein ungeprüfter oder infizierter Datenträger
eingebunden ist.

BadUSB (Etappe 4): Neue USB-Geräte, die kein reiner Speicher sind, meldet
badusb.Guard als Alarm (usb_alerts im Status). Die Alarme laufen neben der
Zustandsmaschine her, eine Prüfung wird dadurch nicht unterbrochen.

VirusTotal (optional): Nach einem Scan ohne Virenfund fragt der Dienst die
SHA-256 der interessanten Dateien bei VirusTotal ab (Zustand VIRUSTOTAL, Fenster
nur zu www.virustotal.com:443). Unbekannte Dateien lassen sich auf Wunsch
hochladen (Auswahl und Warnhinweis in der Oberfläche). Ab der eingestellten
Schwelle gilt eine Datei als gesperrt; VirusTotal hebt nie einen lokalen Treffer auf.

Tiefenprüfung (Etappe 3): Treffer von Dateityp-, Makro-, PDF-, Archiv- und
YARA-Prüfung bewertet die Richtlinie. Auffällige Dateien mit "Freigabe nötig"
lassen sich im Ergebnis freigeben (release); erst dann werden sie mit übertragen.
"""

from __future__ import annotations

import collections
import datetime as dt
import hashlib
import json
import logging
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Callable

from . import __version__
from .build import info as build_info
from .kiosk import status as kiosk_status
from . import policy as policy_mod
from .analysis import Analyzer
from .cache import ScanCache
from .clamav import ClamdClient, EngineInfo, engine_info
from .config import Config
from .devices import DeviceInfo
from .firewall import FirewallError
from .mounter import Mounter, MountError
from .reports import ReportStore, report_id
from .scanner import Cancelled, FileResult, Scanner
from .share import SettingsError, ShareSettings, ShareStore, from_dict, validate
from .smb import SmbSession, explain, resolve
from .states import State, StateError, check_transition
from .transfer import Transfer, TransferCancelled, TransferProgress, plan
from .update import read_status
from . import virustotal as vt_mod
from .virustotal import (QuotaExhausted, RateLimiter, VtCancelled, VtClient, VtError, VtProgress, VtStore,
                         https_transport)

log = logging.getLogger(__name__)

Emit = Callable[[str, object], None]


class Station:
    VT_POLL_SECONDS = 15   # Abstand der Nachfragen, ob die Analyse nach einem Upload fertig ist
    def __init__(self, cfg: Config, mounter: Mounter, reports: ReportStore, emit: Emit,
                 clamd: ClamdClient | None = None, scanner_factory=None,
                 share_store: ShareStore | None = None, firewall=None, smb_factory=None,
                 analyzer: Analyzer | None = None, start_update: Callable[[], None] | None = None,
                 guard=None):
        self.cfg = cfg
        self.mounter = mounter
        self.reports = reports
        self.emit = emit
        self.clamd = clamd if clamd is not None else ClamdClient(cfg.clamd_socket, cfg.clamd_timeout)
        self._scanner_factory = scanner_factory or self._default_scanner
        self._lock = threading.RLock()
        self.state = State.LEERLAUF
        self.device: DeviceInfo | None = None
        self.pending: list[DeviceInfo] = []
        self.progress: dict | None = None
        self.result: dict | None = None
        self.findings: list[dict] = []
        self.message = ""
        self.log_lines: collections.deque[str] = collections.deque(maxlen=200)
        self._cancel = threading.Event()
        self._generation = 0
        self._scan_thread: threading.Thread | None = None
        self._engine: EngineInfo | None = None
        self._engine_checked = 0.0
        self._last_progress_emit = 0.0
        self.share_store = share_store or ShareStore(cfg.share_file, cfg.share_secret_file, cfg.share)
        self.firewall = firewall
        self._smb_factory = smb_factory or (lambda st, pw: SmbSession(st, pw, cfg.smb_timeout))
        self._net_lock = threading.Lock()   # höchstens eine Netzwerkverbindung gleichzeitig
        self.smb_connected = False
        self.transfer_progress: dict | None = None
        self.transfer_result: dict | None = None
        self.analyzer = analyzer or Analyzer(cfg.yara_dir, cfg.yara_timeout, cfg.yara_max_mb,
                                             cfg.office_max_mb, cfg.archive_depth)
        self.policy_store = policy_mod.PolicyStore(cfg.policy_file, cfg.policy)
        self._start_update = start_update   # startet firebridge-update.service (vom Dienst gesetzt)
        self._update_requested = 0.0
        self._watch_stop = threading.Event()
        self.scan_cache = ScanCache(cfg.scan_cache_file, cfg.scan_cache_size)
        self.guard = guard            # badusb.Guard, vom Dienst gesetzt (None = BadUSB-Schutz aus)
        vt_initial, vt_limits = vt_mod.split_config(cfg.virustotal)
        self.vt_store = VtStore(cfg.state_dir, vt_initial, vt_limits)
        self.vt_progress: dict | None = None
        self._vt_resolve = resolve
        # (key, addrs, limiter, cancelled) → VtClient; in Tests durch eine Attrappe ersetzt
        self._vt_factory = lambda key, addrs, limiter, cancelled: VtClient(
            key, https_transport(addrs, vt_limits.timeout), limiter, cancelled)

    # ------------------------------------------------------------------ Status

    def engine(self, refresh: bool = False) -> EngineInfo:
        if refresh or self._engine is None or time.monotonic() - self._engine_checked > 60:
            self._engine = engine_info(self.clamd, self.cfg.scan_backend, self.cfg.clamscan_binary,
                                       self.cfg.clamav_db_dir)
            self._engine_checked = time.monotonic()
        return self._engine

    def status(self) -> dict:
        with self._lock:
            eng = self.engine()
            age = eng.age_hours()
            return {
                "version": __version__,
                "build": build_info(),
                "station_name": self.cfg.station_name,
                "hostname": socket.gethostname(),
                "state": self.state.value,
                "device": self.device.to_dict() if self.device else None,
                "pending_devices": len(self.pending),
                "progress": self.progress,
                "result": self.result,
                "findings": self.findings[:500],
                "message": self.message,
                "engine": eng.to_dict(),
                "signatures_outdated": age is not None and age > self.cfg.signature_warn_hours,
                "signature_warn_hours": self.cfg.signature_warn_hours,
                "smb": self._smb_status(),
                "transfer": self.transfer_progress,
                "transfer_result": self.transfer_result,
                "analysis": self.analyzer.info(),
                "scan_cache": {"entries": len(self.scan_cache), "max": self.scan_cache.size},
                "update": self._update_status(),
                "policy": self._policy(),
                "policy_categories": policy_mod.describe(),
                "policy_editable": self.cfg.policy_editable,
                "usb_guard": self._guard_status(),
                "virustotal": self._vt_status(),
                "kiosk": kiosk_status(),
                "log": list(self.log_lines)[-60:],
                "actions": self._allowed_actions(),
            }

    def _policy(self) -> dict[str, str]:
        try:
            return self.policy_store.load()
        except (OSError, ValueError) as exc:
            log.error("Richtlinie nicht lesbar, nutze Standard: %s", exc)
            return policy_mod.defaults()

    def _guard_status(self) -> dict:
        if self.guard is None:
            return {"mode": "aus", "active": False, "grabbed": 0, "alerts": [],
                    "message": "BadUSB-Schutz ist aus (usb_guard = false in firebridge.toml)"}
        return self.guard.status()

    def _update_status(self) -> dict:
        st = read_status(self.cfg.update_status_file)
        # Gerade angefordert, der Dienst hat update.json aber noch nicht geschrieben
        if not st.get("running") and time.monotonic() - self._update_requested < 15:
            st = {**st, "running": True}
        return st

    def _allowed_actions(self) -> dict:
        s = self.state
        return {
            "scan": s in (State.EINGEBUNDEN, State.ERGEBNIS),
            "cancel": s == State.SCAN,
            "eject": s in (State.EINGEBUNDEN, State.ERGEBNIS, State.FEHLER, State.UEBERTRAGEN),
            "transfer": not self._transfer_block(),
            "cancel_transfer": s == State.UEBERTRAGUNG,
            "test_share": self._network_allowed() and not self._net_lock.locked(),
            "clear_history": s in (State.LEERLAUF, State.AUSGEWORFEN, State.EINGEBUNDEN, State.BLOCKIERT,
                                   State.FEHLER),
            "release": s == State.ERGEBNIS and bool((self.result or {}).get("counts", {}).get("releasable")),
            "update": (self._start_update is not None and s not in (State.SCAN, State.UEBERTRAGUNG, State.VIRUSTOTAL)
                       and not self._update_status().get("running")),
            "vt_check": self._vt_check_possible(),
            "vt_upload": self._vt_upload_possible(),
            "vt_send": self._vt_send_possible(),
            "vt_cancel": s == State.VIRUSTOTAL,
            "vt_test": (self.vt_store.has_key() and self._network_allowed() and not self._net_lock.locked()),
        }

    def _share(self) -> ShareSettings | None:
        try:
            return self.share_store.load()
        except (OSError, ValueError) as exc:
            log.error("Share-Einstellungen nicht lesbar: %s", exc)
            return None

    def _firewall_status(self) -> dict:
        if self.firewall is None:
            return {"ok": False, "open": False, "message": "Netzwerk-Sperre nicht eingerichtet"}
        return self.firewall.status()

    def _smb_status(self) -> dict:
        share = self._share()
        return {
            "configured": bool(share and share.configured),
            "target": share.display_target() if share else "",
            "label": share.label() if share else "",
            "targets": len(self.share_store.targets()) if share else 0,
            "server": share.server if share else "",
            "connected": self.smb_connected,
            "editable": self.cfg.share_editable,
            "firewall": self._firewall_status(),
            "transfer_block": self._transfer_block(),
        }

    def _transferable_verdict(self) -> bool:
        v = (self.result or {}).get("verdict")
        return v in ("sauber", "auffällig") or (v == "unvollständig" and self.cfg.transfer_incomplete)

    def _network_allowed(self) -> bool:
        """Netz nur, wenn kein ungeprüfter oder infizierter Datenträger eingebunden ist."""
        s = self.state
        if s in (State.LEERLAUF, State.AUSGEWORFEN, State.BLOCKIERT, State.UEBERTRAGEN):
            return True
        return s == State.ERGEBNIS and self._transferable_verdict()

    def _transfer_block(self) -> str:
        """Warum gerade nicht übertragen werden kann ("" = es geht)."""
        s = self.state
        if s == State.UEBERTRAGUNG:
            return "Übertragung läuft"
        if s == State.UEBERTRAGEN:
            return "Bereits übertragen"
        if s == State.VIRUSTOTAL:
            return "VirusTotal-Abfrage läuft"
        if s != State.ERGEBNIS:
            return "Erst nach einer Prüfung möglich"
        v = (self.result or {}).get("verdict")
        if v == "infiziert":
            return "Schadsoftware gefunden, Übertragung gesperrt"
        if v == "unvollständig" and not self.cfg.transfer_incomplete:
            return "Nicht alle Dateien konnten geprüft werden, Übertragung gesperrt"
        if not self._transferable_verdict():
            return "Kein verwertbares Prüfergebnis"
        vt = (self.result or {}).get("vt") or {}
        if vt.get("incomplete") and self.vt_store.load().block_on_error:
            return "VirusTotal-Abfrage unvollständig, Übertragung gesperrt (strenge Einstellung)"
        counts = (self.result or {}).get("counts", {})
        if not counts.get("clean") and not counts.get("released"):
            return ("Keine sauberen Dateien zum Übertragen, auffällige erst freigeben" if counts.get("releasable")
                    else "Keine sauberen Dateien zum Übertragen")
        share = self._share()
        if not share or not share.configured:
            return "Kein Ziel-Share eingerichtet (Einstellungen)"
        fw = self._firewall_status()
        if not fw.get("ok"):
            return fw.get("message") or "Netzwerk-Sperre nicht aktiv"
        if self._net_lock.locked():
            return "Verbindungstest läuft"
        return ""

    def history(self, limit: int = 10) -> list[dict]:
        return self.reports.history(limit)

    def clear_history(self, actor: str = "") -> dict:
        """Verlauf, Prüfberichte und damit die Quarantäne-Liste löschen. Das Freigabe-Protokoll bleibt
        und vermerkt, wer gelöscht hat. Nur ohne offenes Ergebnis (dessen Bericht wird noch gebraucht)."""
        with self._lock:
            if self.state not in (State.LEERLAUF, State.AUSGEWORFEN, State.EINGEBUNDEN, State.BLOCKIERT,
                                  State.FEHLER):
                raise StateError("Verlauf löschen geht erst, wenn keine Prüfung oder Übertragung läuft und "
                                 "kein Ergebnis offen ist (Datenträger auswerfen)")
            entries, reports = self.reports.clear()
        self._log(f"Verlauf gelöscht{f' von {actor}' if actor else ''}: {entries} Einträge, {reports} Berichte")
        self._audit(actor, "loeschen", f"Verlauf gelöscht: {entries} Einträge, {reports} Prüfberichte",
                    dev=None, entries=entries, reports=reports)
        self.emit("state", self.status())
        return {"entries": entries, "reports": reports}

    def audit_log(self, limit: int = 200) -> list[dict]:
        return self.reports.audit(limit)

    def quarantine(self, limit: int = 1000) -> list[dict]:
        return self.reports.quarantine(limit=limit)

    def audit_admin(self, actor: str, text: str) -> None:
        self._audit(actor, "admin", text, dev=None)

    def _audit(self, actor: str, action: str, text: str, dev: DeviceInfo | None = None, **extra) -> None:
        """Freigabe-Protokoll: wer hat wann was freigegeben."""
        dev = dev or self.device
        entry = {"time": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
                 "by": actor or "unbekannt", "action": action, "text": text,
                 "device": dev.display_name if dev else "", "serial": dev.serial if dev else "", **extra}
        try:
            self.reports.append_audit(entry)
        except OSError as exc:
            log.error("Freigabe-Protokoll: %s", exc)

    def report(self, rid: str) -> dict:
        return self.reports.load(rid)

    # ------------------------------------------------------------ intern

    def _log(self, text: str) -> None:
        line = f"{dt.datetime.now():%H:%M:%S} {text}"
        self.log_lines.append(line)
        log.info(text)
        self.emit("log", line)

    def _set_state(self, new: State, message: str | None = None) -> None:
        with self._lock:
            check_transition(self.state, new)
            self.state = new
            if message is not None:
                self.message = message
        self.emit("state", self.status())

    # ------------------------------------------------------------ Geräte

    def device_added(self, dev: DeviceInfo) -> None:
        with self._lock:
            if self.state != State.LEERLAUF:
                self.pending.append(dev)
                self._log(f"Weiteres Gerät {dev.devname} wartet, bis {self.device.devname} entfernt ist")
                self.emit("state", self.status())
                return
            self.device = dev
            self.message = ""
            self.progress = None
            self.result = None
            self.findings = []
            self.transfer_progress = None
            self.transfer_result = None
            self._generation += 1
        ifaces = ", ".join(f"{i['name']} ({i['class']})" for i in dev.interfaces) or "unbekannt"
        self._log(f"Gerät erkannt: {dev.display_name} {dev.vendor_id}:{dev.product_id} "
                  f"an {dev.devname}, Schnittstellen: {ifaces}")

        bad = dev.suspicious_interfaces
        if bad:
            names = ", ".join(f"{i['name']} ({i['code']})" for i in bad)
            self._log(f"WARNUNG: Gerät meldet zusätzlich {names}. Es wird nicht eingebunden.")
            self._set_state(State.BLOCKIERT,
                            f"Das Gerät meldet sich zusätzlich als {names}. "
                            "Der Speicher wird nicht eingebunden. Bitte abziehen und der IT übergeben.")
            self.reports.append_history(self._history_entry(None, "BadUSB"))
            return

        self._set_state(State.GERAET_ERKANNT, "Datenträger wird schreibgeschützt eingebunden …")
        try:
            mounted = self.mounter.mount_device(dev)
        except MountError as exc:
            self._log(f"Fehler: {exc}")
            self._set_state(State.FEHLER, f"Schreibschutz konnte nicht gesetzt werden: {exc}")
            return
        for p in dev.partitions:
            if p.mountpoint:
                self._log(f"mount {p.devname} {p.fstype} → {p.note}")
            else:
                self._log(f"{p.devname} nicht eingebunden: {p.note}")
        with self._lock:
            if self.device is not dev:  # in der Zwischenzeit abgezogen
                return
        if not mounted:
            self._set_state(State.FEHLER, "Keine lesbare Partition gefunden. "
                                          "Unterstützt: FAT, exFAT, NTFS, ext2–4, ISO, UDF, XFS, Btrfs, HFS+.")
            return
        self._set_state(State.EINGEBUNDEN, "Bereit zum Prüfen")

    def device_removed(self, devname: str) -> None:
        with self._lock:
            self.pending = [d for d in self.pending if d.devname != devname]
            dev = self.device
            if dev is None or dev.devname != devname:
                self.emit("state", self.status())
                return
            was = self.state
            self._cancel.set()
            self._generation += 1
        if was == State.SCAN:
            self._log("Gerät während der Prüfung abgezogen, Prüfung abgebrochen")
            self.reports.append_history(self._history_entry(self.progress, "abgebrochen"))
        elif was == State.UEBERTRAGUNG:
            self._log("Gerät während der Übertragung abgezogen, Übertragung wird abgebrochen")
        else:
            self._log(f"Gerät {devname} entfernt")
        errors = self.mounter.unmount_device(dev, lazy=True)
        for err in errors:
            self._log(f"umount: {err}")
        with self._lock:
            self.device = None
            self.progress = None
            self.findings = []
            self.result = None
            self.transfer_progress = None
            self.transfer_result = None
            self.state = State.LEERLAUF
            # Nach dem Abschalten meldet udev das Gerät sofort als entfernt
            self.message = (f"{dev.display_name} wurde ausgeworfen und kann abgezogen werden."
                            if was == State.AUSGEWORFEN else "")
            nxt = self.pending.pop(0) if self.pending else None
        self.emit("state", self.status())
        if nxt is not None:
            self.device_added(nxt)

    # ------------------------------------------------------------ Aktionen

    def scan(self) -> None:
        with self._lock:
            if not self._allowed_actions()["scan"]:
                raise StateError(f"Prüfen ist im Zustand {self.state.value} nicht möglich")
            eng = self.engine(refresh=True)
            if not eng.available:
                raise StateError(eng.message or "Keine Viren-Engine verfügbar")
            dev = self.device
            roots = [(Path(p.devname).name, Path(p.mountpoint)) for p in dev.partitions if p.mountpoint]
            self._cancel = threading.Event()
            self.progress = None
            self.findings = []
            self.result = None
            gen = self._generation
            self._set_state(State.SCAN, "Prüfung läuft")
        self._log(f"Prüfung gestartet mit {eng.engine} (daily {eng.db_version}, {eng.message})")
        self._scan_thread = threading.Thread(target=self._scan_worker,
                                             args=(dev, roots, eng, self._cancel, gen),
                                             name="scan-main", daemon=True)
        self._scan_thread.start()

    def cancel(self) -> None:
        with self._lock:
            if self.state != State.SCAN:
                raise StateError("Es läuft keine Prüfung")
            self._cancel.set()
        self._log("Abbruch angefordert")

    def eject(self) -> None:
        with self._lock:
            if not self._allowed_actions()["eject"]:
                raise StateError(f"Auswerfen ist im Zustand {self.state.value} nicht möglich")
            dev = self.device
        errors = self.mounter.unmount_device(dev)
        for err in errors:
            self._log(f"umount: {err}")
        # Vor dem Abschalten setzen: udev meldet das Gerät danach sofort als entfernt
        self._set_state(State.AUSGEWORFEN, "Der Datenträger kann jetzt abgezogen werden.")
        off = self.mounter.power_off(dev)
        self._log(f"Ausgehängt{', Gerät abgeschaltet' if off else ''}: {dev.devname}")

    def shutdown(self) -> None:
        self._watch_stop.set()
        with self._lock:
            self._cancel.set()
            dev = self.device
        if self.firewall is not None:
            try:
                self.firewall.close()
            except FirewallError as exc:
                log.error("Netzwerk-Fenster schließen: %s", exc)
        if dev is not None:
            self.mounter.unmount_device(dev, lazy=True)

    # ------------------------------------------------------------ BadUSB

    def guard_log(self, text: str) -> None:
        self._log(text)

    def guard_changed(self) -> None:
        self.emit("state", self.status())

    def guard_history(self, entry: dict) -> None:
        try:
            self.reports.append_history(entry)
        except OSError as exc:
            log.error("Verlauf: %s", exc)

    def usb_allow(self, alert_id: str, actor: str = "") -> dict:
        if self.guard is None:
            raise StateError("BadUSB-Schutz ist abgeschaltet")
        res = self.guard.allow(alert_id)
        d = res.get("device") or {}
        kind = "Tastatur (Tipp-Probe folgt)" if res.get("state") == "probe" else "USB-Gerät"
        self._audit(actor, "usb", f"{kind} freigegeben: {d.get('display_name') or '?'}", dev=None,
                    usb_device=d.get("display_name", ""), usb_id=f"{d.get('vendor_id', '')}:{d.get('product_id', '')}")
        return res

    def usb_dismiss(self, alert_id: str) -> dict:
        if self.guard is None:
            raise StateError("BadUSB-Schutz ist abgeschaltet")
        return self.guard.dismiss(alert_id)

    # ------------------------------------------------------------ Tiefenprüfung

    def release(self, paths: list[str], actor: str = "") -> dict:
        """Auffällige Dateien mit "Freigabe nötig" freigeben. paths = alle, die freigegeben sein sollen
        (eine vorher freigegebene Datei, die fehlt, wird wieder gesperrt)."""
        with self._lock:
            if self.state != State.ERGEBNIS or not self.result:
                raise StateError("Freigeben geht nur im Ergebnis einer Prüfung")
            report = self.reports.load(self.result["id"])
            releasable = {f["path"]: f for f in report.get("files", [])
                          if f.get("status") == "suspicious" and f.get("action") == "freigabe"}
            wanted = set(paths)
            unknown = wanted - set(releasable)
            if unknown:
                raise StateError(f"Nicht freigebbar (gesperrt oder nicht auffällig): {sorted(unknown)[0]}")
            when = dt.datetime.now().astimezone().isoformat(timespec="seconds")
            granted, revoked = [], []
            for path, f in releasable.items():
                if path in wanted and not f.get("released"):
                    f["released"] = when
                    granted.append(path)
                elif path not in wanted and f.get("released"):
                    f.pop("released")
                    revoked.append(path)
            n = sum(1 for f in releasable.values() if f.get("released"))
            report["counts"]["released"] = n
            if granted or revoked:
                report.setdefault("releases", []).append({"time": when, "by": actor or "unbekannt",
                                                          "released": granted, "revoked": revoked})
                self.reports.save(report)
            self.result["counts"] = dict(report["counts"])
            for f in self.findings:
                if f.get("path") in releasable:
                    f["released"] = releasable[f["path"]].get("released", "")
        who = f" von {actor}" if actor else ""
        for path in granted:
            self._log(f"Freigegeben{who}: {path}")
            self._audit(actor, "datei", f"Datei freigegeben: {path}", report=report["id"], path=path)
        for path in revoked:
            self._log(f"Freigabe zurückgenommen{who}: {path}")
            self._audit(actor, "datei", f"Freigabe zurückgenommen: {path}", report=report["id"], path=path)
        self.emit("state", self.status())
        return {"released": n, "granted": len(granted), "revoked": len(revoked)}

    def set_policy(self, data: dict) -> dict:
        if not self.cfg.policy_editable:
            raise StateError("Die Richtlinie ist fest eingestellt (policy_editable = false)")
        try:
            pol = self.policy_store.save(data)
        except ValueError as exc:
            raise StateError(str(exc))
        self._log("Richtlinie gespeichert: " + ", ".join(f"{k}={v}" for k, v in pol.items()))
        self.emit("state", self.status())
        return pol

    def update_now(self) -> None:
        """Signaturen und YARA-Regeln sofort aktualisieren (startet den Update-Dienst)."""
        with self._lock:
            if not self._allowed_actions()["update"]:
                raise StateError("Update ist gerade nicht möglich" if self._start_update else
                                 "Kein Update-Dienst eingerichtet")
            self._update_requested = time.monotonic()
        self._start_update()
        self._log("Update der Signaturen und YARA-Regeln gestartet")
        self.emit("state", self.status())

    def start_watch(self, interval: float = 5.0) -> None:
        """Beobachtet update.json und die YARA-Regeln, damit die Oberfläche neue Stände sofort sieht."""
        def stamp() -> tuple:
            out = []
            for p in (self.cfg.update_status_file, self.cfg.yara_dir / "rules.yarc"):
                try:
                    out.append(p.stat().st_mtime_ns)
                except OSError:
                    out.append(None)
            return tuple(out)

        def loop():
            last = stamp()
            while not self._watch_stop.wait(interval):
                now = stamp()
                if now != last:
                    last = now
                    with self._lock:
                        scanning = self.state == State.SCAN
                    if not scanning:
                        self.analyzer.prepare()
                    self.engine(refresh=True)
                    self.emit("state", self.status())

        self.analyzer.prepare()
        threading.Thread(target=loop, name="update-watch", daemon=True).start()

    # ------------------------------------------------------------ Ziel-Share

    def get_share(self) -> dict:
        return {**self.share_store.public(), "editable": self.cfg.share_editable}

    def _check_editable(self) -> None:
        if not self.cfg.share_editable:
            raise StateError("Die Ziele sind fest eingestellt (share_editable = false)")
        with self._lock:
            if self.state == State.UEBERTRAGUNG or self._net_lock.locked():
                raise StateError("Während einer Verbindung können die Ziele nicht geändert werden")

    def set_share(self, data: dict) -> dict:
        """Ziel speichern: mit "id" ändern, ohne "id" neu anlegen; "make_default" macht es zum Standard."""
        self._check_editable()
        tid, settings, password, make_default = _parse_share(data)
        tid = self.share_store.save(settings, password, tid, make_default)
        self._log(f"Ziel gespeichert: {settings.label()}")
        self.emit("state", self.status())
        return {**self.get_share(), "saved_id": tid}

    def delete_share(self, target_id: str) -> dict:
        self._check_editable()
        name = self.share_store.load(target_id).label()
        self.share_store.delete(target_id)
        self._log(f"Ziel gelöscht: {name}")
        self.emit("state", self.status())
        return self.get_share()

    def select_share(self, target_id: str) -> dict:
        """Standardziel wählen (geht auch bei share_editable = false)."""
        with self._lock:
            if self.state == State.UEBERTRAGUNG:
                raise StateError("Während einer Übertragung kann das Ziel nicht gewechselt werden")
        self.share_store.set_active(target_id)
        self._log(f"Standardziel: {self.share_store.load().label()}")
        self.emit("state", self.status())
        return self.get_share()

    def test_share(self, data: dict | None = None) -> dict:
        """Verbindungstest: anmelden, Schreibrecht prüfen, wieder trennen."""
        with self._lock:
            if not self._network_allowed():
                raise StateError("Verbindungstest nur ohne ungeprüften Datenträger möglich")
        if data and set(data) - {"id"}:
            tid, settings, password, _ = _parse_share(data)
            if password is None:
                password = self.share_store.password(tid) if tid else ""
        elif data:
            settings, password = self.share_store.load(data["id"]), self.share_store.password(data["id"])
        else:
            settings, password = self.share_store.load(), self.share_store.password()
        if not settings.configured:
            raise StateError("Server und Freigabe eintragen")
        if not self._net_lock.acquire(blocking=False):
            raise StateError("Es besteht schon eine Verbindung")
        steps: list[str] = []
        session = None
        try:
            self._log(f"Verbindungstest zu {settings.display_target()}")
            addrs = self._open_network(settings)
            steps.append(f"Server gefunden: {', '.join(addrs)}")
            session = self._smb_factory(settings, password)
            session.connect(addrs)
            self.smb_connected = True
            steps.append(session.info)
            session.makedirs(())
            session.write_test()
            steps.append("Ordner vorhanden, Schreiben erlaubt")
            ok, msg = True, "Verbindung in Ordnung"
        except (StateError, SettingsError):
            raise
        except Exception as exc:
            ok, msg = False, explain(exc)
        finally:
            self._close_network(session)
            self._net_lock.release()
        steps.append("Verbindung getrennt, Netzwerk wieder gesperrt")
        self._log(f"Verbindungstest: {msg}")
        self.emit("state", self.status())
        return {"ok": ok, "message": msg, "steps": steps, "target": settings.display_target()}

    def _open_network(self, settings: ShareSettings) -> list[str]:
        """nftables-Fenster öffnen: erst DNS, dann nur noch tcp/<port> zu den Server-IPs."""
        fw = self.firewall
        if fw is None or not fw.status().get("ok"):
            raise StateError(self._firewall_status().get("message") or "Netzwerk-Sperre nicht aktiv")
        if not _is_ip(settings.server):
            fw.allow_dns()
        addrs = resolve(settings.server, settings.port)
        fw.allow(addrs, settings.port)
        self._log(f"Netzwerk geöffnet: tcp/{settings.port} zu {', '.join(addrs)}")
        return addrs

    def _close_network(self, session) -> None:
        if session is not None:
            session.close()
        self.smb_connected = False
        if self.firewall is not None:
            try:
                self.firewall.close()
            except FirewallError as exc:
                self._log(f"FEHLER beim Schließen des Netzwerk-Fensters: {exc}")
                return
        self._log("SMB-Verbindung getrennt, Netzwerk wieder gesperrt")

    # ------------------------------------------------------------ Übertragung

    def transfer(self, target_id: str = "", files: list[str] | None = None, actor: str = "") -> None:
        """target_id leer = Standardziel; files = nur diese Berichtspfade (None = alle sauberen)."""
        with self._lock:
            reason = self._transfer_block()
            if reason:
                raise StateError(reason)
            settings = self.share_store.load(target_id or None)
            password = self.share_store.password(target_id or None)
            if not settings.configured:
                raise StateError("Ziel unvollständig: Server und Freigabe fehlen")
            report = self.reports.load(self.result["id"])
            dev = self.device
            roots = {Path(p.devname).name: Path(p.mountpoint) for p in dev.partitions if p.mountpoint}
            items, renamed = plan(report, roots, set(files) if files is not None else None)
            if not items:
                raise StateError("Keine sauberen oder freigegebenen Dateien zum Übertragen" if files is None
                                 else "Keine der ausgewählten Dateien ist zum Übertragen freigegeben")
            selection = files is not None
            if not self._net_lock.acquire(blocking=False):
                raise StateError("Es besteht schon eine Verbindung")
            self._cancel = threading.Event()
            gen = self._generation
            prog = TransferProgress(started=time.monotonic(), target=settings.display_target(),
                                    total=len(items), bytes_total=sum(i.size for i in items))
            self.transfer_progress = prog.to_dict()
            self.transfer_result = None
            self._set_state(State.UEBERTRAGUNG, "Übertragung läuft")
        self._log(f"Übertragung freigegeben{f' von {actor}' if actor else ''}: {len(items)} "
                  f"{'ausgewählte ' if selection else ''}Dateien nach {settings.display_target()}")
        self._audit(actor, "uebertragung", f"Übertragung gestartet: {len(items)} Dateien nach "
                    f"{settings.display_target()}", dev=dev, report=report["id"], files=len(items))
        threading.Thread(target=self._transfer_worker,
                         args=(dev, report, items, renamed, settings, password, prog, self._cancel, gen,
                               selection),
                         name="transfer", daemon=True).start()

    def cancel_transfer(self) -> None:
        with self._lock:
            if self.state != State.UEBERTRAGUNG:
                raise StateError("Es läuft keine Übertragung")
            self._cancel.set()
        self._log("Abbruch der Übertragung angefordert")

    def _on_transfer_progress(self, gen: int, prog: TransferProgress) -> None:
        with self._lock:
            if gen != self._generation:
                return
            self.transfer_progress = prog.to_dict()
        self.emit("transfer", self.transfer_progress)

    def _transfer_worker(self, dev: DeviceInfo, report: dict, items, renamed, settings: ShareSettings,
                         password: str, prog: TransferProgress, cancel: threading.Event, gen: int,
                         selection: bool = False) -> None:
        started = dt.datetime.now().astimezone()
        session = None
        tr = None
        error = ""
        verdict = ""
        try:
            self._on_transfer_progress(gen, prog)
            addrs = self._open_network(settings)
            session = self._smb_factory(settings, password)
            session.connect(addrs)
            self.smb_connected = True
            prog.connection = session.info
            self._log(f"Verbunden: {session.info}")
            tr = Transfer(session, items, settings.verify, cancel,
                          lambda p: self._on_transfer_progress(gen, p), self._log, prog)
            tr.run(report["id"])
            if not prog.failed:
                verdict = "übertragen"
            elif prog.copied:
                verdict = "teilweise übertragen"
            else:
                verdict = "Übertragung fehlgeschlagen"
                error = "Keine Datei konnte fehlerfrei übertragen werden"
            prog.phase = "abschließen"
            self._on_transfer_progress(gen, prog)
        except TransferCancelled:
            verdict = "Übertragung abgebrochen"
        except Exception as exc:
            log.exception("Übertragung fehlgeschlagen")
            verdict = "Übertragung fehlgeschlagen"
            error = explain(exc)
        finished = dt.datetime.now().astimezone()
        section = {
            "verdict": verdict,
            "error": error,
            "started": started.isoformat(timespec="seconds"),
            "finished": finished.isoformat(timespec="seconds"),
            "duration_s": round((finished - started).total_seconds(), 1),
            "target": prog.target,
            "connection": prog.connection,
            "verify": settings.verify,
            "copied": prog.copied,
            "failed": prog.failed,
            "planned": len(items),
            "selection": selection,      # True = nur vom Benutzer ausgewählte Dateien
            "bytes": sum(i.size for i in items),
            "renamed": renamed,
            "files": tr.results if tr else [],
        }
        report = {**report, "transfer": section}
        if tr is not None and tr.folder and verdict in ("übertragen", "teilweise übertragen"):
            try:
                tr.upload_report(report)
                self._log("Prüfbericht auf dem Share abgelegt")
            except Exception as exc:
                section["report_upload"] = explain(exc)
                self._log(f"Prüfbericht konnte nicht abgelegt werden: {explain(exc)}")
        prog.phase = "trennen"
        self._on_transfer_progress(gen, prog)
        try:
            self._close_network(session)
        finally:
            self._net_lock.release()

        try:
            self.reports.save(report)
        except OSError as exc:
            self._log(f"Bericht konnte nicht gespeichert werden: {exc}")
        entry = self._history_entry({"files": prog.copied}, verdict, report["id"], dev)
        self.reports.append_history(entry)
        if error:
            self._log(f"Übertragung fehlgeschlagen: {error}")
        else:
            self._log(f"Übertragung beendet: {prog.copied} von {len(items)} Dateien übertragen"
                      f"{f', {prog.failed} fehlgeschlagen' if prog.failed else ''} → {verdict}")
        with self._lock:
            if gen != self._generation:
                return  # Gerät wurde abgezogen
            self.transfer_progress = prog.to_dict()
            self.transfer_result = {k: v for k, v in section.items() if k not in ("files", "renamed")}
            self.transfer_result["renamed_count"] = len(renamed)
        if verdict == "übertragen":
            msg = (f"{prog.copied} Dateien nach {prog.target} übertragen"
                   f"{' und per SHA-256 gegengeprüft' if settings.verify else ''}.")
        elif verdict == "teilweise übertragen":
            msg = f"{prog.copied} von {len(items)} Dateien übertragen, {prog.failed} fehlgeschlagen."
        else:
            msg = error or "Übertragung abgebrochen."
            if tr is not None and tr.folder and prog.copied:
                msg += f" Bereits kopierte Dateien liegen in {prog.target}."
        with self._lock:
            self.transfer_result["message"] = msg
        if verdict in ("übertragen", "teilweise übertragen"):
            self._set_state(State.UEBERTRAGEN, msg)
        else:
            self._set_state(State.ERGEBNIS, _verdict_message(self.result["verdict"], self.result["counts"]))

    # ------------------------------------------------------------ VirusTotal

    def _vt_status(self) -> dict:
        st = self.vt_store.load()
        lim = self.vt_store.limits
        used, limit = self.vt_store.quota(st.license)
        has_key = self.vt_store.has_key()
        if st.mode == "aus":
            msg = "VirusTotal ist aus"
        elif not has_key:
            msg = "Kein API-Key hinterlegt, VirusTotal wird nicht gefragt"
        elif limit and used >= limit:
            msg = f"Tageskontingent erschöpft ({used} von {limit})"
        else:
            msg = {"manuell": "Manuell: nichts automatisch, Abfrage und Upload nur auf Knopfdruck",
                   "hash": "Nur Hash-Abfrage"}.get(st.mode, "Hash-Abfrage, Upload nach Bestätigung")
        return {**st.to_dict(), "mode_label": vt_mod.MODE_LABELS[st.mode], "has_key": has_key,
                "ready": st.mode != "aus" and has_key, "allow_upload": lim.allow_upload, "editable": lim.editable,
                "quota_used": used, "quota_limit": limit, "per_minute": self.vt_store.per_minute(st.license),
                "max_upload_mb": lim.max_upload_mb, "noncommercial_text": vt_mod.NONCOMMERCIAL_TEXT,
                "progress": self.vt_progress, "message": msg}

    def _vt_ready(self) -> bool:
        st = self.vt_store.load()
        return st.mode != "aus" and self.vt_store.has_key()

    def _vt_auto(self, report: dict) -> bool:
        """Nach dem Scan automatisch fragen? Nie in Stufe manuell, bei Virenfund oder ohne interessante Dateien."""
        if not self._vt_ready() or self.vt_store.load().mode == "manuell" or report.get("verdict") == "infiziert":
            return False
        if self.firewall is None or not self.firewall.status().get("ok"):
            self._log("VirusTotal übersprungen: Netzwerk-Sperre nicht aktiv")
            return False
        return any(vt_mod.interesting(f) for f in report.get("files", []))

    def _vt_check_possible(self) -> bool:
        res = self.result or {}
        vt = res.get("vt") or {}
        return (self.state == State.ERGEBNIS and res.get("verdict") != "infiziert" and self._vt_ready()
                and not self._net_lock.locked() and bool(vt.get("open", 1)))

    def _vt_upload_possible(self) -> bool:
        st = self.vt_store.load()
        return self._vt_send_possible() and st.mode in vt_mod.UPLOAD_MODES and self.vt_store.limits.allow_upload

    def _vt_send_possible(self) -> bool:
        """Einzelne Dateien nach der Prüfung abfragen (Hash, in Stufe manuell/Upload auch hochladen)."""
        res = self.result or {}
        return (self.state == State.ERGEBNIS and res.get("verdict") != "infiziert" and self._vt_ready()
                and not self._net_lock.locked())

    def get_virustotal(self) -> dict:
        return self._vt_status()

    def set_virustotal(self, data: dict) -> dict:
        """Stufe, Lizenz, Schwelle und optional den API-Key speichern. Der Key wird nie zurückgegeben."""
        lim = self.vt_store.limits
        if not lim.editable:
            raise StateError("VirusTotal ist fest eingestellt (virustotal.editable = false)")
        with self._lock:
            if self.state == State.VIRUSTOTAL:
                raise StateError("Während einer VirusTotal-Abfrage nicht möglich")
        data = dict(data)
        key = data.pop("api_key", None)
        clear_key = bool(data.pop("clear_key", False))
        confirm = bool(data.pop("confirm_noncommercial", False))
        for k in ("mode_label", "has_key", "ready", "allow_upload", "editable", "quota_used", "quota_limit",
                  "per_minute", "max_upload_mb", "noncommercial_text", "progress", "message", "license_confirmed"):
            data.pop(k, None)
        old = self.vt_store.load()
        new = {**old.to_dict(), **data}
        if new["license"] != old.license:
            new["license_confirmed"] = ""
        if confirm or (new["license"] == "premium" and not new["license_confirmed"]):
            new["license_confirmed"] = vt_mod.now_iso()
        if new["license"] == "public" and new["mode"] != "aus" and not new["license_confirmed"]:
            raise StateError("Die kostenlose Public API ist nur für nicht-kommerzielle Nutzung erlaubt. "
                             "Bitte die Nutzung bestätigen oder eine Premium-Lizenz wählen.")
        try:
            settings = vt_mod.validate(new, lim.allow_upload)
            if key is not None and key.strip():
                self.vt_store.set_key(key)
            elif clear_key:
                self.vt_store.set_key("")
        except ValueError as exc:
            raise StateError(str(exc))
        self.vt_store.save(settings)
        lic = {"public": "Public API, nicht-kommerzielle Nutzung bestätigt", "premium": "Premium-Lizenz"}.get(
            settings.license, "keine Lizenz gewählt")
        self._log(f"VirusTotal gespeichert: Stufe {settings.mode}, {lic}"
                  f"{f' ({settings.license_confirmed})' if settings.license_confirmed else ''}, "
                  f"Schwelle {settings.threshold}")
        if key is not None and key.strip():
            self._log("VirusTotal: API-Key hinterlegt")
        elif clear_key:
            self._log("VirusTotal: API-Key gelöscht")
        self.emit("state", self.status())
        return self._vt_status()

    def _open_vt_network(self) -> list[str]:
        fw = self.firewall
        if fw is None or not fw.status().get("ok"):
            raise StateError(self._firewall_status().get("message") or "Netzwerk-Sperre nicht aktiv")
        fw.allow_dns()
        addrs = self._vt_resolve(vt_mod.HOST, vt_mod.PORT)
        fw.allow(addrs, vt_mod.PORT)
        self._log(f"Netzwerk geöffnet: tcp/443 zu {vt_mod.HOST} ({', '.join(addrs)})")
        return addrs

    def _close_vt_network(self) -> None:
        if self.firewall is not None:
            try:
                self.firewall.close()
            except FirewallError as exc:
                self._log(f"FEHLER beim Schließen des Netzwerk-Fensters: {exc}")
                return
        self._log("VirusTotal-Verbindung getrennt, Netzwerk wieder gesperrt")

    def vt_test(self) -> dict:
        """API-Key und Verbindung prüfen (eine Hash-Abfrage der EICAR-Testdatei)."""
        with self._lock:
            if not self._network_allowed():
                raise StateError("Verbindungstest nur ohne ungeprüften Datenträger möglich")
        key = self.vt_store.key()
        if not key:
            raise StateError("Erst einen API-Key hinterlegen")
        if not self._net_lock.acquire(blocking=False):
            raise StateError("Es besteht schon eine Verbindung")
        st = self.vt_store.load()
        steps: list[str] = []
        try:
            addrs = self._open_vt_network()
            steps.append(f"{vt_mod.HOST} gefunden: {', '.join(addrs)}")
            limiter = RateLimiter(self.vt_store, st.license)
            client = self._vt_factory(key, addrs, limiter, lambda: False)
            attrs = client.file_report(vt_mod.EICAR_SHA256)
            steps.append("TLS-Zertifikat geprüft, API-Key angenommen")
            if attrs is not None:
                s = vt_mod.stats_of(attrs)
                steps.append(f"Testabfrage EICAR: {s['malicious']} von {s['total']} Engines")
            ok, msg = True, "Verbindung in Ordnung"
        except StateError:
            raise
        except Exception as exc:
            ok, msg = False, _vt_explain(exc)
        finally:
            self._close_vt_network()
            self._net_lock.release()
        steps.append("Verbindung getrennt, Netzwerk wieder gesperrt")
        used, limit = self.vt_store.quota(st.license)
        if limit:
            steps.append(f"Heute {used} von {limit} Anfragen verbraucht")
        self._log(f"VirusTotal-Test: {msg}")
        self.emit("state", self.status())
        return {"ok": ok, "message": msg, "steps": steps}

    def vt_check(self) -> None:
        """Noch offene Dateien (unbekannt, Fehler, Limit, Analyse läuft) erneut abfragen."""
        with self._lock:
            if not self._vt_check_possible():
                raise StateError("VirusTotal-Abfrage ist gerade nicht möglich")
            if self.firewall is None or not self.firewall.status().get("ok"):
                raise StateError(self._firewall_status().get("message") or "Netzwerk-Sperre nicht aktiv")
            self._cancel = threading.Event()
            gen, dev, rid = self._generation, self.device, self.result["id"]
            self._set_state(State.VIRUSTOTAL, "VirusTotal-Abfrage läuft")
        threading.Thread(target=self._vt_worker, args=(rid, dev, "recheck", None, self._cancel, gen),
                         name="virustotal", daemon=True).start()

    def vt_upload(self, paths: list[str], notice_confirmed: bool, actor: str = "") -> None:
        """Ausgewählte Dateien abfragen und, was VirusTotal nicht kennt, hochladen."""
        self.vt_send(paths, True, notice_confirmed, actor)

    def vt_send(self, paths: list[str], upload: bool = False, notice_confirmed: bool = False,
                actor: str = "") -> None:
        """Nur die ausgewählten Dateien bei VirusTotal abfragen (beliebige geprüfte Dateien, auch saubere).
        upload: unbekannte davon hochladen – nur in Stufe Upload und mit bestätigtem Hinweis."""
        with self._lock:
            if not (self._vt_upload_possible() if upload else self._vt_send_possible()):
                raise StateError("Upload zu VirusTotal ist gerade nicht möglich" if upload else
                                 "VirusTotal-Abfrage ist gerade nicht möglich")
            if upload and not notice_confirmed:
                raise StateError("Vor dem Upload den Hinweis bestätigen: hochgeladene Dateien können von "
                                 "Dritten eingesehen werden")
            if not paths:
                raise StateError("Keine Datei ausgewählt")
            report = self.reports.load(self.result["id"])
            files = {f["path"]: f for f in report.get("files", [])}
            for p in paths:
                f = files.get(p)
                if f is None or not vt_mod.sendable(f):
                    raise StateError(f"Nicht an VirusTotal sendbar (infiziert, nicht lesbar oder übersprungen): {p}")
            self._cancel = threading.Event()
            gen, dev, rid = self._generation, self.device, self.result["id"]
            self._set_state(State.VIRUSTOTAL, "Upload zu VirusTotal läuft" if upload else "VirusTotal-Abfrage läuft")
        if upload:
            self._log(f"VirusTotal: {len(paths)} ausgewählte Dateien abfragen, unbekannte hochladen "
                      "(Hinweis zur Weitergabe bestätigt)")
            self._audit(actor, "virustotal", f"Upload zu VirusTotal erlaubt: {len(paths)} Dateien (unbekannte "
                        "werden hochgeladen)", dev=dev, report=rid, paths=list(paths))
        else:
            self._log(f"VirusTotal: {len(paths)} ausgewählte Dateien abfragen (nur SHA-256)")
        threading.Thread(target=self._vt_worker, args=(rid, dev, "select", list(paths), self._cancel, gen),
                         kwargs={"upload": upload}, name="virustotal", daemon=True).start()

    def vt_cancel(self) -> None:
        with self._lock:
            if self.state != State.VIRUSTOTAL:
                raise StateError("Es läuft keine VirusTotal-Abfrage")
            self._cancel.set()
        self._log("VirusTotal: Abbruch angefordert, restliche Dateien bleiben ungeprüft")

    def _vt_emit(self, gen: int, prog: VtProgress, limiter: RateLimiter | None = None, left: int = 0) -> None:
        if limiter is not None:
            prog.waiting = max(0.0, limiter.waiting_until - time.monotonic()) if limiter.waiting_until else 0.0
            prog.eta = limiter.seconds_for(left) if left else prog.waiting or None
        with self._lock:
            if gen != self._generation:
                return
            self.vt_progress = prog.to_dict()
        self.emit("virustotal", self.vt_progress)

    def _vt_worker(self, rid: str, dev: DeviceInfo, kind: str, paths: list[str] | None,
                   cancel: threading.Event, gen: int, final_history: bool = False, upload: bool = False) -> None:
        """kind: "hash" (nach dem Scan), "recheck" (offene erneut) oder "select" (nur paths).
        upload: was VirusTotal nicht kennt, hochladen (nur mit bestätigtem Hinweis)."""
        settings = self.vt_store.load()
        lim = self.vt_store.limits
        report = self.reports.load(rid)
        files = report.get("files", [])
        if kind == "select":
            wanted = set(paths or [])
            todo = [f for f in files if f["path"] in wanted]
        elif kind == "recheck":
            todo = [f for f in files if vt_mod.interesting(f)
                    and (f.get("vt") or {}).get("state") not in ("found", "uploaded")]
        else:
            todo = [f for f in files if vt_mod.interesting(f)]
        roots = {Path(p.devname).name: Path(p.mountpoint) for p in dev.partitions if p.mountpoint}
        prog = VtProgress(kind="upload" if upload else "hash", total=len(todo), started=time.monotonic())
        limiter = RateLimiter(self.vt_store, settings.license,
                              sleep=lambda s: (self._vt_emit(gen, prog, limiter, prog.total - prog.done),
                                               cancel.wait(s))[1])
        deadline = time.monotonic() + lim.window_minutes * 60
        run = {"kind": kind, "time": vt_mod.now_iso(), "files": len(todo), "license": settings.license,
               "license_confirmed": settings.license_confirmed, "error": ""}
        if upload:
            run["notice_confirmed"] = True
            run["upload"] = True
        if kind == "select":
            run["selected"] = len(todo)
        self._log(f"VirusTotal: {len(todo)} Dateien {'abfragen, unbekannte hochladen' if upload else 'abfragen'} "
                  f"(höchstens {limiter.per_minute or 'beliebig viele'} Anfragen pro Minute)")
        pending: list[dict] = []
        handled: set[str] = set()
        error = ""
        locked = self._net_lock.acquire(blocking=False)
        try:
            if not locked:
                raise StateError("Es besteht schon eine Verbindung")
            self._vt_emit(gen, prog)
            addrs = self._open_vt_network()
            client = self._vt_factory(self.vt_store.key(), addrs, limiter, cancel.is_set)
            for f in todo:
                if cancel.is_set():
                    raise VtCancelled()
                if time.monotonic() > deadline:
                    error = f"Zeitlimit von {lim.window_minutes} Minuten erreicht"
                    break
                prog.current = f["path"]
                prog.phase = "abfragen"
                self._vt_emit(gen, prog, limiter, prog.total - prog.done)
                try:
                    # Erst den Hash fragen (spart den Upload, wenn VirusTotal die Datei kennt); ist schon
                    # bekannt, dass sie unbekannt ist, gleich hochladen
                    attrs = None
                    if not (upload and (f.get("vt") or {}).get("state") == "unknown"):
                        attrs = client.file_report(f["sha256"])
                        if attrs is None:
                            f["vt"] = {"state": "unknown", "how": "hash", "time": vt_mod.now_iso()}
                        else:
                            f["vt"] = vt_mod.result_from_attrs(attrs, f["sha256"], "hash")
                        self._log(f"VirusTotal: {vt_mod.short(f['vt'])} → {f['path']}")
                    if attrs is None and upload:
                        if int(f.get("size", 0)) > lim.max_upload_mb * 1024 * 1024:
                            raise VtError(f"Zu groß für den Upload (über {lim.max_upload_mb} MB)")
                        label, _, rel = f["path"].partition("/")
                        root = roots.get(label)
                        if root is None or not rel or ".." in Path(rel).parts:
                            raise VtError("Datei nicht mehr erreichbar")
                        prog.phase = "hochladen"
                        self._vt_emit(gen, prog, limiter, prog.total - prog.done)
                        aid = client.upload(root / rel, Path(rel).name, int(f.get("size", 0)), f["sha256"])
                        f["vt"] = {"state": "pending", "how": "upload", "analysis": aid, "time": vt_mod.now_iso(),
                                   "link": vt_mod.GUI_LINK.format(f["sha256"])}
                        pending.append(f)
                        self._log(f"VirusTotal: hochgeladen {f['path']}")
                except QuotaExhausted:
                    raise
                except VtError as exc:
                    if "API-Key" in str(exc):
                        raise
                    f["vt"] = {"state": "error", "time": vt_mod.now_iso(), "message": str(exc)}
                    self._log(f"VirusTotal: Fehler bei {f['path']}: {exc}")
                handled.add(f["path"])
                prog.done += 1
            # Nach dem Upload auf die Analysen warten (zählt auch gegen das Kontingent)
            wait_end = time.monotonic() + lim.analysis_wait
            while pending and not error and time.monotonic() < min(wait_end, deadline):
                prog.phase = "warten"
                prog.current = f"Analyse von {len(pending)} {'Datei' if len(pending) == 1 else 'Dateien'} läuft"
                self._vt_emit(gen, prog, limiter)
                if cancel.wait(self.VT_POLL_SECONDS):
                    raise VtCancelled()
                for f in list(pending):
                    res = client.analysis(f["vt"]["analysis"])
                    if res.get("status") == "completed":
                        f["vt"].update({"state": "uploaded", "time": vt_mod.now_iso(),
                                        **{k: res[k] for k in ("malicious", "suspicious", "total")}})
                        pending.remove(f)
                        self._log(f"VirusTotal: Analyse fertig, {vt_mod.short(f['vt'])} → {f['path']}")
            if pending and not error:
                error = "Analyse bei VirusTotal noch nicht fertig, später „Erneut abfragen“"
        except VtCancelled:
            error = "abgebrochen"
        except QuotaExhausted as exc:
            error = str(exc)
            for f in todo:
                if f["path"] not in handled:
                    f["vt"] = {"state": "limit", "time": vt_mod.now_iso(), "message": str(exc)}
        except Exception as exc:
            if not isinstance(exc, (StateError, VtError, OSError)):
                log.exception("VirusTotal fehlgeschlagen")
            error = _vt_explain(exc)
        finally:
            if locked:
                prog.phase = "trennen"
                self._vt_emit(gen, prog)
                self._close_vt_network()
                self._net_lock.release()
        # Nicht mehr drangekommen (Abbruch, Zeitlimit, Fehler): ohne Ergebnis als "nicht geprüft" markieren,
        # ein früheres Ergebnis bleibt stehen (beim Upload bleibt die Datei "unbekannt" und hochladbar)
        for f in todo:
            if f["path"] not in handled and "vt" not in f:
                f["vt"] = {"state": "skipped", "time": vt_mod.now_iso(), "message": error or "nicht geprüft"}
        run["error"] = error
        self._vt_finish(report, settings, run, gen, dev, final_history)

    def _vt_finish(self, report: dict, settings, run: dict, gen: int, dev: DeviceInfo, final_history: bool) -> None:
        hits = _apply_vt(report, settings.threshold)
        summary = _vt_summary(report, settings.threshold)
        sec = report.setdefault("virustotal", {})
        sec.update({"mode": settings.mode, "license": settings.license,
                    "license_confirmed": settings.license_confirmed, "threshold": settings.threshold,
                    "block_on_error": settings.block_on_error, **summary})
        sec.setdefault("runs", []).append({**run, **{k: summary[k] for k in ("found", "unknown", "hits", "warn")}})
        try:
            self.reports.save(report)
        except OSError as exc:
            self._log(f"Bericht konnte nicht gespeichert werden: {exc}")
        counts, verdict = report["counts"], report["verdict"]
        if final_history:
            self.reports.append_history(self._history_entry(counts, verdict, report["id"], dev))
        for path in hits:
            self._log(f"VirusTotal: GESPERRT (über der Schwelle von {settings.threshold} Engines) → {path}")
        self._log(f"VirusTotal fertig: {summary['found']} bekannt, {summary['unknown']} unbekannt, "
                  f"{summary['hits']} gefährlich, {summary['warn']} mit einzelnen Meldungen"
                  f"{', ' + run['error'] if run['error'] else ''}")
        with self._lock:
            if gen != self._generation:
                return
            self.vt_progress = None
            self.result = {**(self.result or {}), "verdict": verdict, "counts": dict(counts),
                           "vt": {**summary, "error": run["error"]}}
            self.findings = [f for f in report.get("files", [])
                             if f.get("status") in ("infected", "suspicious", "error") or f.get("vt")][:500]
        self._set_state(State.ERGEBNIS, _verdict_message(verdict, counts))

    # ------------------------------------------------------------ Scan

    def _default_scanner(self, eng: EngineInfo) -> Scanner:
        return Scanner(eng.backend, self.clamd, self.cfg.scan_workers,
                       self.cfg.clamscan_binary, self.cfg.clamav_db_dir, self.analyzer, self._policy(),
                       self._prepare_cache(eng))

    def scan_fingerprint(self, eng: EngineInfo) -> str:
        """Stand der Prüfmittel. Ändert er sich, gilt kein gespeichertes Ergebnis mehr."""
        self.analyzer.prepare()   # neue YARA-Regeln zuerst laden, sonst passt der Abdruck nicht
        db = []
        try:
            for p in sorted(self.cfg.clamav_db_dir.iterdir()):
                # freshclam.dat und mirrors.dat ändern sich bei jedem Lauf, auch ohne neue Signaturen
                if p.suffix not in (".dat", ".tmp") and p.is_file():
                    st = p.stat()
                    db.append([p.name, st.st_size, st.st_mtime_ns])
        except OSError:
            pass
        data = {"firebridge": __version__, "backend": eng.backend, "engine": eng.engine,
                "daily": eng.db_version, "db_time": eng.db_time, "db": db,
                "analysis": self.analyzer.fingerprint()}
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def _prepare_cache(self, eng: EngineInfo) -> ScanCache | None:
        if not self.scan_cache.enabled:
            return None
        if self.scan_cache.begin(self.scan_fingerprint(eng)):
            self._log("Neue Signaturen oder Regeln: gespeicherte Prüfergebnisse verworfen")
        return self.scan_cache

    def _on_progress(self, gen: int, prog) -> None:
        now = time.monotonic()
        if now - self._last_progress_emit < 0.25 and (prog.done < prog.total or prog.phase == "sammeln"):
            return
        self._last_progress_emit = now
        with self._lock:
            if gen != self._generation:
                return
            self.progress = prog.to_dict()
        self.emit("progress", self.progress)

    def _on_finding(self, gen: int, res: FileResult) -> None:
        with self._lock:
            if gen != self._generation:
                return
            self.findings.append(res.to_dict())
        if res.status == "infected":
            self._log(f"FUND {res.detail} → {res.path}")
        elif res.status == "suspicious":
            how = "gesperrt" if res.action == "blockieren" else "Freigabe nötig"
            self._log(f"AUFFÄLLIG ({how}) {res.detail} → {res.path}")
        else:
            self._log(f"Fehler {res.detail} → {res.path}")

    def _scan_worker(self, dev: DeviceInfo, roots, eng: EngineInfo, cancel: threading.Event,
                     gen: int) -> None:
        started = dt.datetime.now().astimezone()
        scanner = self._scanner_factory(eng)
        policy = getattr(scanner, "policy", None) or self._policy()
        try:
            try:
                results, prog = scanner.run(roots, cancel,
                                            lambda p: self._on_progress(gen, p),
                                            lambda r: self._on_finding(gen, r))
            finally:
                if getattr(scanner, "cache", None) is not None:
                    scanner.cache.save()
        except Cancelled:
            with self._lock:
                if gen != self._generation:
                    return  # Gerät wurde abgezogen, device_removed räumt auf
                self.progress = None
                self.findings = []
            self._log("Prüfung abgebrochen")
            self.reports.append_history(self._history_entry(None, "abgebrochen"))
            self._set_state(State.EINGEBUNDEN, "Prüfung abgebrochen")
            return
        except Exception as exc:  # unerwartet: nicht als "sauber" werten
            log.exception("Scan fehlgeschlagen")
            with self._lock:
                if gen != self._generation:
                    return
            self._log(f"Prüfung fehlgeschlagen: {exc}")
            self._set_state(State.EINGEBUNDEN, f"Prüfung fehlgeschlagen: {exc}")
            return

        finished = dt.datetime.now().astimezone()
        counts = {
            "files": prog.total,
            "clean": sum(1 for r in results if r.status == "clean"),
            "infected": sum(1 for r in results if r.status == "infected"),
            "errors": sum(1 for r in results if r.status == "error"),
            "skipped": sum(1 for r in results if r.status == "skipped"),
            "suspicious": sum(1 for r in results if r.status == "suspicious"),
            "blocked": sum(1 for r in results if r.status == "suspicious" and r.action == "blockieren"),
            "releasable": sum(1 for r in results if r.status == "suspicious" and r.action == "freigabe"),
            "released": 0,
            "cached": sum(1 for r in results if getattr(r, "cached", False)),
            "bytes": prog.bytes_total,
        }
        if counts["infected"]:
            verdict = "infiziert"
        elif counts["errors"]:
            verdict = "unvollständig"
        elif counts["suspicious"]:
            verdict = "auffällig"
        else:
            verdict = "sauber"
        rid = report_id(dev.to_dict(), started)
        report = {
            "id": rid,
            "station": self.cfg.station_name,
            "host": socket.gethostname(),
            "software": f"firebridge {__version__}",
            "started": started.isoformat(timespec="seconds"),
            "finished": finished.isoformat(timespec="seconds"),
            "duration_s": round((finished - started).total_seconds(), 1),
            "device": dev.to_dict(),
            "engine": eng.to_dict(),
            "analysis": self.analyzer.info(),
            "policy": policy,
            "verdict": verdict,
            "counts": counts,
            "files": [r.to_dict() for r in sorted(results, key=lambda r: r.path)],
        }
        try:
            path = self.reports.save(report)
            self._log(f"Bericht gespeichert: {path}")
        except OSError as exc:
            self._log(f"Bericht konnte nicht gespeichert werden: {exc}")
        with self._lock:
            if gen != self._generation:
                self.reports.append_history(self._history_entry(counts, verdict, rid, dev))
                return
            self.progress = prog.to_dict()
            self.result = {"id": rid, "verdict": verdict, "counts": counts,
                           "started": report["started"], "finished": report["finished"],
                           "duration_s": report["duration_s"]}
        if counts["cached"]:
            self._log(f"{counts['cached']} von {counts['files']} Dateien schon bekannt, "
                      "Ergebnis aus dem Zwischenspeicher übernommen")
        self._log(f"Prüfung beendet: {counts['files']} Dateien, {counts['infected']} infiziert, "
                  f"{counts['suspicious']} auffällig, {counts['errors']} Fehler → {verdict}")
        if self._vt_auto(report):
            self._set_state(State.VIRUSTOTAL, "VirusTotal-Abfrage läuft")
            self._vt_worker(rid, dev, "hash", None, cancel, gen, final_history=True)
            return
        self.reports.append_history(self._history_entry(counts, verdict, rid, dev))
        self._set_state(State.ERGEBNIS, _verdict_message(verdict, counts))

    def _history_entry(self, counts, result: str, rid: str = "", dev: DeviceInfo | None = None) -> dict:
        dev = dev or self.device
        files = None
        if isinstance(counts, dict):
            files = counts.get("files", counts.get("total"))
        return {
            "id": rid,
            "time": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
            "device": dev.display_name if dev else "?",
            "usb_id": f"{dev.vendor_id}:{dev.product_id}" if dev else "",
            "serial": dev.serial if dev else "",
            "files": files,
            "infected": counts.get("infected", 0) if isinstance(counts, dict) else 0,
            "suspicious": counts.get("suspicious", 0) if isinstance(counts, dict) else 0,
            "result": result,
        }


def _vt_explain(exc: BaseException) -> str:
    if isinstance(exc, (VtError, StateError)):
        return str(exc)
    if isinstance(exc, (ssl.SSLError, ssl.CertificateError)):
        return f"TLS-Fehler, Zertifikat von {vt_mod.HOST} nicht vertrauenswürdig: {exc}"
    return explain(exc).replace("Server antwortet nicht", "VirusTotal antwortet nicht")


def _apply_vt(report: dict, threshold: int) -> list[str]:
    """VirusTotal-Ergebnisse in Status, Zählung und Gesamtergebnis übernehmen. Gibt neu gesperrte Pfade zurück.

    Ab der Schwelle wird die Datei wie ein lokaler Treffer gesperrt (blockieren, nicht freigebbar). Darunter
    gibt es nur einen Hinweis. Eine lokale Erkennung wird nie aufgehoben."""
    newly = []
    for f in report.get("files", []):
        v = f.get("vt")
        if not v:
            continue
        r = vt_mod.rate(v, threshold)
        v["rating"] = r
        detail = f"VirusTotal: {v.get('malicious')} von {v.get('total')} Engines melden Schadsoftware"
        if r == "hit" and not any(h.get("engine") == "VirusTotal" for h in f.get("hits", [])):
            f.setdefault("hits", []).append({"engine": "VirusTotal", "category": "virustotal", "rule": "schwelle",
                                             "action": "blockieren", "detail": detail})
            f["detail"] = f"{f['detail']}; {detail}" if f.get("status") == "suspicious" and f.get("detail") else detail
            f["status"] = "suspicious"
            f["action"] = "blockieren"
            f.pop("released", None)
            newly.append(f["path"])
        elif r == "warn":
            note = (f"VirusTotal: {v.get('malicious')} von {v.get('total')} Engines melden etwas "
                    f"(unter der Schwelle von {threshold})")
            notes = [n for n in f.get("notes", []) if not n.startswith("VirusTotal:")]
            f["notes"] = notes + [note]
    files = report.get("files", [])
    c = report["counts"]
    c["clean"] = sum(1 for f in files if f.get("status") == "clean")
    c["suspicious"] = sum(1 for f in files if f.get("status") == "suspicious")
    c["blocked"] = sum(1 for f in files if f.get("status") == "suspicious" and f.get("action") == "blockieren")
    c["releasable"] = sum(1 for f in files if f.get("status") == "suspicious" and f.get("action") == "freigabe")
    c["released"] = sum(1 for f in files if f.get("status") == "suspicious" and f.get("action") == "freigabe"
                        and f.get("released"))
    if c.get("infected"):
        report["verdict"] = "infiziert"
    elif c.get("errors"):
        report["verdict"] = "unvollständig"
    elif c["suspicious"]:
        report["verdict"] = "auffällig"
    else:
        report["verdict"] = "sauber"
    return newly


def _vt_summary(report: dict, threshold: int) -> dict:
    states = [(f.get("vt") or {}).get("state") for f in report.get("files", []) if f.get("vt")]
    rates = [vt_mod.rate(f["vt"], threshold) for f in report.get("files", []) if f.get("vt")]
    out = {
        "checked": len(states),
        "found": sum(1 for s in states if s in ("found", "uploaded")),
        "unknown": sum(1 for s in states if s == "unknown"),
        "uploaded": sum(1 for s in states if s == "uploaded"),
        "pending": sum(1 for s in states if s == "pending"),
        "errors": sum(1 for s in states if s in ("error", "limit", "skipped")),
        "hits": rates.count("hit"),
        "warn": rates.count("warn"),
    }
    # noch etwas offen, das sich erneut abfragen ließe
    out["open"] = out["errors"] + out["pending"] + out["unknown"]
    # "unvollständig" für block_on_error: Fehler, Limit, Zeitlimit oder Analyse noch nicht fertig
    out["incomplete"] = out["errors"] + out["pending"]
    return out


def _is_ip(text: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _parse_share(data: dict) -> tuple[str | None, ShareSettings, str | None, bool]:
    """Daten aus der GUI: ID (leer = neues Ziel), Einstellungen, Passwort (None = unverändert,
    "" = löschen) und ob das Ziel Standard werden soll."""
    data = dict(data)
    tid = data.pop("id", None) or None
    password = data.pop("password", None)
    if data.pop("clear_password", False):
        password = ""
    make_default = bool(data.pop("make_default", False))
    for key in ("has_password", "configured", "target", "editable", "label", "default"):
        data.pop(key, None)
    return tid, validate(from_dict(data)), password, make_default


def _verdict_message(verdict: str, counts: dict) -> str:
    if verdict == "infiziert":
        n = counts["infected"]
        return f"{n} {'Datei' if n == 1 else 'Dateien'} mit Schadsoftware gefunden. Der Datenträger ist gesperrt."
    if verdict == "unvollständig":
        return (f"Keine Schadsoftware gefunden, aber {counts['errors']} Dateien konnten nicht geprüft werden.")
    if verdict == "auffällig":
        n, blocked, rel = counts["suspicious"], counts.get("blocked", 0), counts.get("releasable", 0)
        parts = []
        if blocked:
            parts.append(f"{blocked} gesperrt")
        if rel:
            parts.append(f"{rel} {'braucht' if rel == 1 else 'brauchen'} eine Freigabe")
        return (f"Keine Schadsoftware gefunden, aber {n} {'Datei ist' if n == 1 else 'Dateien sind'} auffällig "
                f"({', '.join(parts)}). {counts['clean']} saubere Dateien können übertragen werden.")
    return f"Keine Schadsoftware gefunden. {counts['clean']} Dateien geprüft."
