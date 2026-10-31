"""Oberfläche der Firebridge (läuft ohne Rechte als normaler Benutzer).

Start:   firebridge-gui           (spricht über den System-Bus mit dem Dienst)
Demo:    firebridge-gui --demo    (Beispieldaten, kein Dienst nötig)
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import math
import sys
import time

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import (QColor, QFont, QGuiApplication, QIcon, QIntValidator, QKeySequence, QPainter,
                           QPainterPath, QPen, QPixmap, QShortcut)
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QFrame,
                               QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLayout, QLineEdit, QListWidget,
                               QListWidgetItem, QMainWindow,
                               QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QRadioButton,
                               QScrollArea, QSizePolicy, QSpinBox, QTreeWidget, QTreeWidgetItem,
                               QTreeWidgetItemIterator,
                               QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout,
                               QWidget)

from .. import policy as policy_mod
from .. import virustotal as vt_mod
from ..transfer import transferable
from .client import Backend, DBusBackend, DemoBackend
from . import zoom
from .style import C, FONT_FAMILIES, MONO_FAMILIES, TONES, stylesheet

# ---------------------------------------------------------------------------
# Formatierung


def fmt_bytes(n: int | None) -> str:
    if not n:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            text = f"{n:.0f}" if unit == "B" or n >= 100 else f"{n:.1f}"
            return f"{text.replace('.', ',')} {unit}"
        n /= 1000
    return ""


def fmt_int(n: int | None) -> str:
    return "—" if n is None else f"{n:,}".replace(",", " ")


def fmt_when(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        t = dt.datetime.fromisoformat(iso).astimezone()
    except ValueError:
        return iso
    today = dt.datetime.now().astimezone().date()
    if t.date() == today:
        return f"heute {t:%H:%M}"
    if t.date() == today - dt.timedelta(days=1):
        return f"gestern {t:%H:%M}"
    return f"{t:%d.%m.} {t:%H:%M}"


def fmt_duration(sec: float | None) -> str:
    if sec is None:
        return "—"
    sec = int(sec)
    return f"{sec // 60}:{sec % 60:02d}"


def mono() -> QFont:
    f = QFont()
    f.setFamilies(MONO_FAMILIES)
    return f


# ---------------------------------------------------------------------------
# Bausteine


def label(text: str = "", role: str | None = None, wrap: bool = False) -> QLabel:
    w = QLabel(text)
    if role:
        w.setProperty("role", role)
    w.setWordWrap(wrap)
    w.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return w


def repolish(w: QWidget) -> None:
    w.style().unpolish(w)
    w.style().polish(w)
    for child in w.findChildren(QWidget):
        child.style().unpolish(child)
        child.style().polish(child)


def set_tone(w: QWidget, tone: str) -> None:
    if w.property("tone") != tone:
        w.setProperty("tone", tone)
        repolish(w)


class Card(QFrame):
    def __init__(self, title: str | None = None):
        super().__init__()
        self.setProperty("role", "card")
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(16, 14, 16, 14)
        self.lay.setSpacing(4)
        if title:
            self.lay.addWidget(label(title.upper(), "lbl"))


class StatCard(Card):
    def __init__(self, title: str):
        super().__init__(title)
        self.big = label("—", "big")
        self.small = label("", "small", wrap=True)
        self.lay.addWidget(self.big)
        self.lay.addWidget(self.small)
        self.lay.addStretch()

    def set(self, big: str, small: str = "", color: str | None = None) -> None:
        self.big.setText(big)
        self.small.setText(small)
        self.big.setStyleSheet(f"color: {color};" if color else "")


class FilterCard(StatCard):
    """Kachel, die beim Anklicken die Tabelle darunter filtert (selected = aktiver Filter)."""

    clicked = Signal()

    def __init__(self, title: str):
        super().__init__(title)
        self.setCursor(Qt.PointingHandCursor)
        self.setProperty("selected", False)
        self.setToolTip("Klicken: Tabelle auf diese Dateien filtern, nochmal klicken: wieder alle Funde")

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)

    def select(self, on: bool) -> None:
        if self.property("selected") != on:
            self.setProperty("selected", on)
            repolish(self)


class Pill(QLabel):
    def __init__(self, text: str = "", tone: str = "info"):
        super().__init__(text)
        self.setProperty("role", "pill")
        self.setProperty("tone", tone)
        self.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)

    def set(self, text: str, tone: str) -> None:
        self.setText(text)
        set_tone(self, tone)


class Dot(QLabel):
    def __init__(self, tone: str = "off"):
        super().__init__()
        self.setFixedSize(9, 9)
        self.set(tone)

    def set(self, tone: str) -> None:
        color = TONES.get(tone, TONES["off"])[0]
        if tone == "ok":
            color = "#4cc282"  # auf dunklem Grund heller
        elif tone == "bad":
            color = "#f2867e"
        elif tone == "warn":
            color = "#e6b04d"
        self.setStyleSheet(f"background: {color}; border-radius: 4px;")


class Spinner(QWidget):
    """Dreh-Animation: zeigt, dass die Firebridge gerade arbeitet."""

    def __init__(self, size: int = 22, color: str | None = None):
        super().__init__()
        self.setFixedSize(size, size)
        self.color = QColor(color or C["accent"])
        self.angle = 0
        self.timer = QTimer(self)
        self.timer.setInterval(30)
        self.timer.timeout.connect(self._step)
        self.hide()

    def _step(self) -> None:
        self.angle = (self.angle + 12) % 360
        self.update()

    def start(self) -> None:
        if not self.timer.isActive():
            self.timer.start()
        self.show()

    def stop(self) -> None:
        self.timer.stop()
        self.hide()

    def set_running(self, on: bool) -> None:
        self.start() if on else self.stop()

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w = max(2.0, self.width() / 8)
        r = QRectF(w / 2, w / 2, self.width() - w, self.height() - w)
        faint = QColor(self.color)
        faint.setAlpha(45)
        p.setPen(QPen(faint, w))
        p.drawEllipse(r)
        pen = QPen(self.color, w)
        pen.setCapStyle(Qt.RoundCap)
        p.setPen(pen)
        p.drawArc(r, -self.angle * 16, 100 * 16)
        p.end()


class BusyRow(QWidget):
    """Spinner mit Text, z. B. "Prüfung wird gestartet …"."""

    def __init__(self):
        super().__init__()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)
        self.spinner = Spinner(20)
        self.text = label("", "hint")
        lay.addWidget(self.spinner)
        lay.addWidget(self.text, 1)
        self.hide()

    def busy(self, text: str) -> None:
        self.text.setText(text)
        self.spinner.start()
        self.show()

    def idle(self) -> None:
        self.spinner.stop()
        self.hide()


class StatusRow(QWidget):
    def __init__(self, text: str):
        super().__init__()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 2, 0, 2)
        lay.setSpacing(8)
        self.dot = Dot()
        self.text = QLabel(text)
        lay.addWidget(self.dot, 0, Qt.AlignVCenter)
        lay.addWidget(self.text, 1)

    def set(self, tone: str, text: str) -> None:
        self.dot.set(tone)
        self.text.setText(text)


class Banner(QFrame):
    def __init__(self):
        super().__init__()
        self.setProperty("role", "banner")
        self.setProperty("tone", "info")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(2)
        self.title = label("", "bannerTitle", wrap=True)
        self.body = label("", None, wrap=True)
        lay.addWidget(self.title)
        lay.addWidget(self.body)
        self.hide()

    def show_msg(self, tone: str, title: str, body: str = "") -> None:
        set_tone(self, tone)
        self.title.setText(title)
        self.body.setText(body)
        self.body.setVisible(bool(body))
        self.show()


def button(text: str, kind: str | None = None, xl: bool = False) -> QPushButton:
    b = QPushButton(text)
    if kind:
        b.setProperty("kind", kind)
    if xl:
        b.setProperty("size", "xl")
    b.setCursor(Qt.PointingHandCursor)
    return b


def pixmap_ratio() -> int:
    """Symbole scharf zeichnen, auch wenn die Oberfläche vergrößert ist."""
    app = QGuiApplication.instance()
    return max(2, math.ceil(app.devicePixelRatio() if app else 1))


def fit_to_screen(w: QWidget, width: int, height: int) -> None:
    """Fenstergröße wünschen, aber nie größer als der Bildschirm (wichtig bei großer Skalierung)."""
    screen = w.screen() or QGuiApplication.primaryScreen()
    if screen is not None:
        avail = screen.availableGeometry()
        width = min(width, int(avail.width() * 0.95))
        height = min(height, int(avail.height() * 0.92))
    w.resize(width, height)


def scrollable(page: QWidget) -> QScrollArea:
    """Seite in einen Rollbereich setzen: passt sie bei großer Schrift nicht ganz, wird gerollt statt gequetscht."""
    sc = QScrollArea()
    sc.setWidgetResizable(True)
    sc.setFrameShape(QFrame.NoFrame)
    sc.setWidget(page)
    return sc


def usb_pixmap(color: str, size: int = 40) -> QPixmap:
    ratio = pixmap_ratio()
    pm = QPixmap(size * ratio, size * ratio)
    pm.setDevicePixelRatio(ratio)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    pen = QPen(QColor(color), 1.8)
    p.setPen(pen)
    s = size / 24
    p.drawRoundedRect(QRectF(7 * s, 2 * s, 10 * s, 7 * s), 1 * s, 1 * s)
    p.drawRoundedRect(QRectF(5 * s, 9 * s, 14 * s, 13 * s), 2 * s, 2 * s)
    p.drawLine(QPointF(10 * s, 5 * s), QPointF(11 * s, 5 * s))
    p.drawLine(QPointF(13 * s, 5 * s), QPointF(14 * s, 5 * s))
    p.end()
    return pm


def warn_pixmap(color: str, size: int = 40) -> QPixmap:
    ratio = pixmap_ratio()
    pm = QPixmap(size * ratio, size * ratio)
    pm.setDevicePixelRatio(ratio)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(QPen(QColor(color), 2))
    path = QPainterPath()
    path.moveTo(size / 2, 4)
    path.lineTo(size - 3, size - 5)
    path.lineTo(3, size - 5)
    path.closeSubpath()
    p.drawPath(path)
    p.drawLine(QPointF(size / 2, 15), QPointF(size / 2, size - 16))
    p.drawPoint(QPointF(size / 2, size - 11))
    p.end()
    return pm


def make_table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels([h.upper() for h in headers])
    t.verticalHeader().hide()
    t.setShowGrid(False)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setFocusPolicy(Qt.NoFocus)
    t.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    t.horizontalHeader().setHighlightSections(False)
    t.verticalHeader().setDefaultSectionSize(32)
    return t


def cell(text: str, color: str | None = None, mono_font: bool = False, bold: bool = False) -> QTableWidgetItem:
    it = QTableWidgetItem(text)
    if color:
        it.setForeground(QColor(color))
    f = mono() if mono_font else QFont()
    f.setBold(bold)
    it.setFont(f)
    return it


RESULT_TONES = {"sauber": "ok", "infiziert": "bad", "BadUSB": "bad", "unvollständig": "warn", "auffällig": "warn",
                "abgebrochen": "off", "übertragen": "ok", "teilweise übertragen": "warn",
                "Übertragung fehlgeschlagen": "bad", "Übertragung abgebrochen": "off",
                "Netzwerkadapter gesperrt": "bad", "Eingabegerät gesperrt": "warn", "USB-Gerät gesperrt": "warn",
                "Tastatur freigegeben": "info", "USB-Gerät freigegeben": "info"}


def page_widget() -> tuple[QWidget, QVBoxLayout]:
    w = QWidget()
    w.setObjectName("page")
    lay = QVBoxLayout(w)
    lay.setContentsMargins(26, 22, 26, 22)
    lay.setSpacing(16)
    return w, lay


# ---------------------------------------------------------------------------
# Seiten


class DeviceCard(Card):
    """Großer Gerätekasten auf der Startseite."""

    def __init__(self):
        super().__init__()
        self.lay.setContentsMargins(18, 16, 18, 16)
        row = QHBoxLayout()
        row.setSpacing(18)
        self.lay.addLayout(row)

        self.icon_box = QFrame()
        self.icon_box.setProperty("role", "iconBox")
        self.icon_box.setFixedSize(68, 68)
        ib = QVBoxLayout(self.icon_box)
        ib.setContentsMargins(0, 0, 0, 0)
        self.icon = QLabel()
        self.icon.setAlignment(Qt.AlignCenter)
        ib.addWidget(self.icon)
        row.addWidget(self.icon_box, 0, Qt.AlignTop)

        col = QVBoxLayout()
        col.setSpacing(4)
        self.caption = label("ANGESCHLOSSENES GERÄT", "lbl")
        self.name = label("Kein Datenträger", "name", wrap=True)
        self.hint = label("", "hint", wrap=True)
        col.addWidget(self.caption)
        col.addWidget(self.name)
        col.addWidget(self.hint)
        self.kv = QGridLayout()
        self.kv.setHorizontalSpacing(16)
        self.kv.setVerticalSpacing(2)
        self.kv_labels: dict[str, QLabel] = {}
        for i, key in enumerate(("Dateisystem", "Größe", "USB-ID", "Schnittstellen")):
            self.kv.addWidget(label(key, "kvKey"), i, 0, Qt.AlignTop)
            val = label("", "kvVal", wrap=True)
            val.setFont(mono())
            self.kv.addWidget(val, i, 1)
            self.kv_labels[key] = val
        self.kv.setColumnStretch(1, 1)
        self.kv_box = QWidget()
        self.kv_box.setLayout(self.kv)
        col.addWidget(self.kv_box)
        row.addLayout(col, 1)

        self.pill = Pill("kein Gerät", "off")
        row.addWidget(self.pill, 0, Qt.AlignTop)

    def update_from(self, st: dict) -> None:
        dev = st.get("device")
        state = st.get("state", "")
        bad = state == "BLOCKIERT"
        set_tone(self, "bad" if bad else "")
        set_tone(self.icon_box, "bad" if bad else "")
        self.icon.setPixmap(warn_pixmap(C["bad"]) if bad else usb_pixmap(C["accent"] if dev else C["off"]))
        if not dev:
            self.caption.setText("ANGESCHLOSSENES GERÄT")
            self.name.setText("Kein Datenträger angeschlossen")
            self.hint.setText("Stick oder Speicherkarte einstecken. Der Datenträger wird automatisch "
                              "schreibgeschützt eingebunden, aber erst auf Knopfdruck geprüft.")
            self.hint.show()
            self.kv_box.hide()
            self.pill.set("bereit für Gerät", "off")
            return
        self.caption.setText("GERÄT GESPERRT" if bad else "ANGESCHLOSSENES GERÄT")
        size = fmt_bytes(dev.get("size_bytes"))
        self.name.setText(f"{dev.get('display_name')} · {size}")
        parts = dev.get("partitions") or []
        fs = []
        for p in parts:
            t = (p.get("fstype") or "?").replace("vfat", "FAT32").replace("exfat", "exFAT").replace("ntfs", "NTFS")
            lbl = f" „{p['label']}“" if p.get("label") else ""
            mode = "read-only" if p.get("mountpoint") else (p.get("note") or "nicht eingebunden")
            fs.append(f"{t}{lbl} · {mode}")
        self.kv_labels["Dateisystem"].setText("\n".join(fs) or "nicht eingebunden")
        self.kv_labels["Größe"].setText(f"{size} · {len(parts)} Partition{'en' if len(parts) != 1 else ''}")
        serial = dev.get("serial") or "—"
        if len(serial) > 12:
            serial = f"{serial[:4]}…{serial[-4:]}"
        self.kv_labels["USB-ID"].setText(f"{dev.get('vendor_id') or '?'}:{dev.get('product_id') or '?'} · "
                                         f"Serien-Nr. {serial} · {dev.get('devname')}")
        ifaces = dev.get("interfaces") or []
        text = ", ".join(f"{i['name']} ({i['class']})" for i in ifaces) or "unbekannt"
        if not dev.get("suspicious_interfaces"):
            text += " — keine Tastatur/Netzwerk"
        self.kv_labels["Schnittstellen"].setText(text)
        self.kv_labels["Schnittstellen"].setStyleSheet(f"color: {C['bad']}; font-weight: 600;" if bad else "")
        self.kv_box.show()
        msg = st.get("message", "")
        self.hint.setText(msg if state in ("BLOCKIERT", "FEHLER", "AUSGEWORFEN", "UEBERTRAGEN") else "")
        self.hint.setVisible(bool(self.hint.text()))
        self.hint.setStyleSheet(f"color: {C['bad']}; font-weight: 600;" if bad else "")

        result = st.get("result") or {}
        pill = {
            "GERAET_ERKANNT": ("wird eingebunden", "info"),
            "EINGEBUNDEN": ("bereit", "info"),
            "SCAN": ("wird geprüft", "warn"),
            "UEBERTRAGUNG": ("wird übertragen", "warn"),
            "UEBERTRAGEN": ("übertragen", "ok"),
            "BLOCKIERT": ("BadUSB-Verdacht", "bad"),
            "FEHLER": ("nicht lesbar", "warn"),
            "AUSGEWORFEN": ("ausgeworfen", "ok"),
        }.get(state)
        if state == "ERGEBNIS":
            v = result.get("verdict", "")
            pill = (f"geprüft: {v}", RESULT_TONES.get(v, "info"))
        self.pill.set(*(pill or ("", "off")))


class StartPage(QWidget):
    def __init__(self, win: "MainWindow"):
        super().__init__()
        self.win = win
        self.setObjectName("page")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 22)
        lay.setSpacing(16)
        lay.addWidget(label("Start", "h1"))
        self.banner = Banner()
        lay.addWidget(self.banner)
        self.device = DeviceCard()
        lay.addWidget(self.device)

        act = QHBoxLayout()
        act.setSpacing(10)
        self.btn_scan = button("▶  Prüfen", "primary", xl=True)
        self.btn_transfer = button("⇪  Auf Share übertragen", xl=True)
        self.btn_transfer.setEnabled(False)
        self.btn_eject = button("⏏  Auswerfen", xl=True)
        self.btn_result = button("Ergebnis anzeigen", xl=True)
        for b in (self.btn_scan, self.btn_transfer, self.btn_eject, self.btn_result):
            act.addWidget(b)
        act.addStretch()
        lay.addLayout(act)
        self.busy = BusyRow()
        lay.addWidget(self.busy)
        self._starting = False
        self._start_timeout = QTimer(self)
        self._start_timeout.setSingleShot(True)
        self._start_timeout.timeout.connect(self.clear_starting)
        self.btn_scan.clicked.connect(self._scan_clicked)
        self.btn_transfer.clicked.connect(win.confirm_transfer)
        self.btn_eject.clicked.connect(win.backend.eject)
        self.btn_result.clicked.connect(win.show_state_page)

        row = QHBoxLayout()
        row.setSpacing(16)
        self.c_sig = StatCard("ClamAV-Signaturen")
        self.c_yara = StatCard("YARA-Regeln")
        self.c_share = StatCard("Ziel-Share")
        self.c_share.big.setFont(mono())
        self.c_share.big.setWordWrap(True)
        self.c_share.set("nicht eingerichtet", "")
        for c in (self.c_sig, self.c_yara, self.c_share):
            row.addWidget(c, 1)
        lay.addLayout(row)
        upd = QHBoxLayout()
        upd.setSpacing(10)
        self.update_spinner = Spinner(18)
        self.update_text = label("", "small", wrap=True)
        self.btn_update = button("↻  Jetzt aktualisieren")
        self.btn_update.setStyleSheet("padding: 6px 12px;")
        self.btn_update.clicked.connect(self._update_clicked)
        upd.addWidget(self.update_spinner)
        upd.addWidget(self.update_text, 1)
        upd.addWidget(self.btn_update)
        lay.addLayout(upd)

        hist = Card("Letzte Prüfungen")
        self.table = make_table(["Zeit", "Gerät", "Dateien", "Ergebnis", "Bericht"])
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.Stretch)
        for i in (2, 3, 4):
            h.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        self.table.setMinimumHeight(150)
        self.table.cellDoubleClicked.connect(self._open_report)
        hist.lay.addWidget(self.table)
        lay.addWidget(hist, 1)
        self._history: list[dict] = []
        self.device.update_from({})
        self.btn_result.hide()

    def _open_report(self, row: int, _col: int) -> None:
        if 0 <= row < len(self._history) and self._history[row].get("id"):
            self.win.backend.get_report(self._history[row]["id"])

    def _scan_clicked(self) -> None:
        # Sofort zeigen, dass etwas passiert: der Dienst fragt erst die Engine ab
        self._starting = True
        self.btn_scan.setEnabled(False)
        self.btn_scan.setText("Startet …")
        self.busy.busy("Prüfung wird gestartet …")
        self._start_timeout.start(20000)
        self.win.backend.scan()

    def _update_clicked(self) -> None:
        self.btn_update.setEnabled(False)
        self.update_spinner.start()
        self.update_text.setText("Update wird gestartet …")
        self.win.backend.update_now()

    def clear_starting(self) -> None:
        if self._starting:
            self._starting = False
            self.update_from(self.win.status)

    def update_from(self, st: dict) -> None:
        state = st.get("state")
        acts = st.get("actions") or {}
        self.device.update_from(st)
        if self._starting and state in ("EINGEBUNDEN", "ERGEBNIS"):
            return  # Scan wurde angefordert, Antwort des Dienstes steht noch aus
        self._starting = False
        self._start_timeout.stop()
        busy = {"GERAET_ERKANNT": "Datenträger wird schreibgeschützt eingebunden …",
                "SCAN": "Prüfung läuft …", "UEBERTRAGUNG": "Übertragung läuft …",
                "VIRUSTOTAL": "VirusTotal-Abfrage läuft …"}.get(state)
        self.busy.busy(busy) if busy else self.busy.idle()
        self.btn_scan.setEnabled(bool(acts.get("scan")))
        self.btn_scan.setText("▶  Erneut prüfen" if state == "ERGEBNIS" else "▶  Prüfen")
        self.btn_eject.setEnabled(bool(acts.get("eject")))
        self.btn_transfer.setEnabled(bool(acts.get("transfer")))
        if self.btn_transfer.property("kind") != ("go" if acts.get("transfer") else None):
            self.btn_transfer.setProperty("kind", "go" if acts.get("transfer") else None)
            repolish(self.btn_transfer)
        smb = st.get("smb") or {}
        self.btn_transfer.setToolTip(smb.get("transfer_block") or "Saubere Dateien auf das Ziel-Share kopieren")
        self.btn_result.setVisible(state in ("ERGEBNIS", "UEBERTRAGEN", "UEBERTRAGUNG", "VIRUSTOTAL"))
        self.btn_result.setText({"UEBERTRAGUNG": "Übertragung anzeigen", "VIRUSTOTAL": "VirusTotal anzeigen",
                                 "UEBERTRAGEN": "Übertragung anzeigen"}.get(state, "Ergebnis anzeigen"))
        fw = smb.get("firewall") or {}
        if not smb.get("configured"):
            self.c_share.set("nicht eingerichtet", "Unter Einstellungen Server und Freigabe eintragen.", C["muted"])
        else:
            title = smb.get("label") or smb.get("target", "")
            more = smb.get("targets", 1) - 1
            where = smb.get("target", "") + "\n" if smb.get("label") != smb.get("target") else ""
            where += f"Standard von {more + 1} Zielen · " if more > 0 else ""
            if smb.get("connected"):
                self.c_share.set(title, where + "verbunden · Übertragung läuft", C["warn"])
            elif not fw.get("ok"):
                self.c_share.set(title, where + fw.get("message", ""), C["bad"])
            else:
                self.c_share.set(title, where + "getrennt · wird erst nach Prüfung und Freigabe verbunden")
        self.c_share.big.setStyleSheet(self.c_share.big.styleSheet() + "font-size: 15px;")

        eng = st.get("engine") or {}
        age = eng.get("age_hours")
        if not eng.get("available"):
            self.c_sig.set("nicht verfügbar", eng.get("message", ""), C["bad"])
        else:
            color = C["bad"] if st.get("signatures_outdated") else None
            extra = f" · älter als {st.get('signature_warn_hours')} h!" if st.get("signatures_outdated") else ""
            daily = f"daily {eng.get('db_version')} · " if eng.get("db_version") else ""
            backend = eng.get("backend")
            how = " · clamd" if backend == "clamd" else f" · {eng.get('message', '')}"
            self.c_sig.set(fmt_when(eng.get("db_time")), f"{daily}{eng.get('engine', '')}{how}{extra}", color)
            if backend != "clamd" and not color:
                self.c_sig.big.setStyleSheet(f"color: {C['warn']};")
        if age is None and eng.get("available"):
            self.c_sig.small.setText(self.c_sig.small.text() + " · Alter unbekannt")
        self._update_analysis(st, acts)

        if st.get("signatures_outdated"):
            self.banner.show_msg("warn", "Virensignaturen sind veraltet",
                                 "Das letzte Update ist mehr als "
                                 f"{st.get('signature_warn_hours')} Stunden her. "
                                 "Bitte Netzwerk prüfen und unten auf „Jetzt aktualisieren“ klicken.")
        elif state == "UEBERTRAGEN":
            tr = st.get("transfer_result") or {}
            self.banner.show_msg(RESULT_TONES.get(tr.get("verdict"), "ok"),
                                 "Übertragung abgeschlossen" if tr.get("verdict") == "übertragen"
                                 else "Übertragung teilweise fehlgeschlagen",
                                 (st.get("message") or "") + " Die Verbindung ist wieder getrennt.")
        elif state == "AUSGEWORFEN" or (state == "LEERLAUF" and st.get("message")):
            self.banner.show_msg("ok", "Datenträger ausgeworfen",
                                 st.get("message") or "Er kann jetzt abgezogen werden.")
        elif st.get("pending_devices"):
            self.banner.show_msg("info", "Weiterer Datenträger wartet",
                                 "Es wird immer nur ein Datenträger geprüft. "
                                 "Der nächste kommt dran, sobald dieser abgezogen ist.")
        else:
            self.banner.hide()

    def _update_analysis(self, st: dict, acts: dict) -> None:
        ana = st.get("analysis") or {}
        y = ana.get("yara") or {}
        if y.get("ready"):
            src = y.get("source", "") + (f" {y['version']}" if y.get("version") else "")
            small = f"{src} · {fmt_when(y.get('compiled'))}"
            if y.get("skipped"):
                small += f" · {fmt_int(y['skipped'])} nicht übersetzbar"
            self.c_yara.set(fmt_int(y.get("rules")), small)
        elif not y.get("available"):
            self.c_yara.set("fehlt", "YARA-X ist nicht installiert (sudo ./install.sh erneut ausführen)", C["bad"])
        else:
            self.c_yara.set("keine", y.get("message") or "Noch keine Regeln geladen", C["warn"])
        missing = [n for n, ok in (("olevba", ana.get("olevba")), ("libmagic", ana.get("magic"))) if not ok]
        if missing and ana:
            self.c_yara.small.setText(self.c_yara.small.text() + f" · fehlt: {', '.join(missing)}")

        up = st.get("update") or {}
        running = bool(up.get("running"))
        self.update_text.setStyleSheet("")
        self.update_spinner.set_running(running)
        if running:
            text = "Update läuft: Signaturen und YARA-Regeln werden geladen …"
        elif up.get("finished"):
            failed = [f"{x['name']}: {x['message']}" for x in up.get("steps", []) if not x.get("ok")]
            text = f"Letztes Update {fmt_when(up['finished'])}: " + ("in Ordnung" if not failed else
                                                                     "Fehler · " + " · ".join(failed[:2]))
            self.update_text.setStyleSheet(f"color: {C['bad']};" if failed else "")
        else:
            text = "Tägliches Update um 03:00 (firebridge-update.timer). Noch kein Update gelaufen."
        self.update_text.setText(text)
        self.btn_update.setEnabled(bool(acts.get("update")))
        self.btn_update.setToolTip("" if acts.get("update") else
                                   "Nicht während einer Prüfung oder Übertragung" if not running else "Läuft schon")

    def set_history(self, rows: list[dict]) -> None:
        self._history = rows
        t = self.table
        t.setRowCount(len(rows))
        for r, e in enumerate(rows):
            res = e.get("result", "")
            tone = RESULT_TONES.get(res, "info")
            text = res
            if res == "infiziert" and e.get("infected"):
                text = f"{e['infected']} infiziert"
            elif res == "auffällig" and e.get("suspicious"):
                text = f"{e['suspicious']} auffällig"
            t.setItem(r, 0, cell(fmt_when(e.get("time")), mono_font=True))
            t.setItem(r, 1, cell(f"{e.get('device', '?')}  ({e.get('usb_id', '')})"))
            t.setItem(r, 2, cell(fmt_int(e.get("files")), mono_font=True))
            t.setItem(r, 3, cell(text, TONES[tone][0], bold=True))
            t.setItem(r, 4, cell("öffnen (Doppelklick)" if e.get("id") else "—", C["accent"] if e.get("id") else C["muted"]))
        if not rows:
            t.setRowCount(1)
            t.setItem(0, 1, cell("Noch keine Prüfungen", C["muted"]))


class ScanPage(QWidget):
    def __init__(self, win: "MainWindow"):
        super().__init__()
        self.win = win
        self.setObjectName("page")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 22)
        lay.setSpacing(16)
        head = QHBoxLayout()
        head.setSpacing(12)
        self.spinner = Spinner(26)
        self.title = label("Prüfung läuft", "h1")
        head.addWidget(self.spinner)
        head.addWidget(self.title, 1)
        lay.addLayout(head)

        card = Card()
        top = QHBoxLayout()
        left = QVBoxLayout()
        left.addWidget(label("FORTSCHRITT", "lbl"))
        self.count = label("0 / 0 Dateien", "big")
        left.addWidget(self.count)
        right = QVBoxLayout()
        right.addWidget(label("RESTZEIT", "lbl"), 0, Qt.AlignRight)
        self.eta = label("—", "big")
        right.addWidget(self.eta, 0, Qt.AlignRight)
        top.addLayout(left, 1)
        top.addLayout(right)
        card.lay.addLayout(top)
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setRange(0, 1000)
        card.lay.addSpacing(6)
        card.lay.addWidget(self.bar)
        self.current = label("", "small")
        self.current.setFont(mono())
        card.lay.addWidget(self.current)
        lay.addWidget(card)

        checks = QHBoxLayout()
        checks.setSpacing(10)
        self.k_clam = StatCard("ClamAV")
        self.k_yara = StatCard("YARA-X")
        self.k_type = StatCard("Skripte & Programme")
        self.k_doc = StatCard("Makros & PDF")
        self.k_err = StatCard("Nicht lesbar")
        for k in (self.k_clam, self.k_yara, self.k_type, self.k_doc, self.k_err):
            k.big.setStyleSheet("font-size: 17px;")
            checks.addWidget(k, 1)
        lay.addLayout(checks)

        lay.addWidget(label("PROTOKOLL", "lbl"))
        self.log = QPlainTextEdit()
        self.log.setObjectName("log")
        self.log.setReadOnly(True)
        self.log.setFont(mono())
        self.log.setMaximumBlockCount(500)
        lay.addWidget(self.log, 1)

        act = QHBoxLayout()
        self.btn_cancel = button("Abbrechen")
        self.btn_cancel.clicked.connect(win.backend.cancel)
        act.addWidget(self.btn_cancel)
        act.addStretch()
        lay.addLayout(act)

    def update_from(self, st: dict) -> None:
        dev = st.get("device") or {}
        self.title.setText(f"Prüfung läuft · {dev.get('display_name', '')}")
        self.spinner.set_running(st.get("state") == "SCAN")
        self.set_progress(st.get("progress") or {"phase": "sammeln"})

    def set_progress(self, p: dict) -> None:
        total, done = p.get("total", 0), p.get("done", 0)
        if p.get("phase") == "sammeln":
            # vor dem eigentlichen Scan: Dateien zählen (dauert bei großen Sticks)
            self.count.setText("Dateien werden gesucht …")
            self.bar.setRange(0, 0)
            self.eta.setText("—")
            self.current.setText(f"{fmt_int(total)} Dateien gefunden   ·   {p.get('current', '')}")
            return
        self.bar.setRange(0, 1000)
        self.count.setText(f"{fmt_int(done)} / {fmt_int(total)} Dateien")
        bt, bd = p.get("bytes_total") or 0, p.get("bytes_done") or 0
        frac = bd / bt if bt else (done / total if total else 0)
        self.bar.setValue(int(frac * 1000))
        self.eta.setText("≈ " + fmt_duration(p["eta"]) if p.get("eta") is not None else "—")
        self.current.setText(f"{p.get('current', '')}   ·   {fmt_bytes(bd)} von {fmt_bytes(bt)}")
        inf = p.get("infected", 0)
        self.k_clam.set(f"{fmt_int(done)} geprüft", f"{inf} Fund{'e' if inf != 1 else ''}",
                        C["bad"] if inf else C["ok"])
        eh = p.get("engine_hits") or {}

        def hits(card: StatCard, n: int, what: str) -> None:
            card.set(f"{fmt_int(n)} Treffer", what, C["warn"] if n else C["ok"])

        ana = (self.win.status.get("analysis") or {})
        y = ana.get("yara") or {}
        if ana and not y.get("ready"):
            self.k_yara.set("aus", y.get("message") or "keine Regeln", C["muted"])
        else:
            hits(self.k_yara, eh.get("YARA-X", 0), f"{fmt_int(y.get('rules'))} Regeln" if y else "")
        hits(self.k_type, eh.get("Dateityp", 0) + eh.get("Archiv", 0), "auch in ZIP-Archiven")
        hits(self.k_doc, eh.get("olevba", 0) + eh.get("PDF", 0), "olevba · PDF-Aktionen")
        err = p.get("errors", 0)
        self.k_err.set(fmt_int(err), f"{fmt_int(p.get('skipped', 0))} Symlinks/Sonderdateien übersprungen",
                       C["warn"] if err else C["ok"])

    def set_log(self, lines: list[str]) -> None:
        self.log.setPlainText("\n".join(lines))
        self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())

    def add_log(self, line: str) -> None:
        self.log.appendPlainText(line)


class ResultPage(QWidget):
    def __init__(self, win: "MainWindow"):
        super().__init__()
        self.win = win
        self.setObjectName("page")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 22)
        lay.setSpacing(16)
        self.title = label("Ergebnis", "h1")
        lay.addWidget(self.title)
        self.banner = Banner()
        lay.addWidget(self.banner)
        self.transfer_banner = Banner()
        lay.addWidget(self.transfer_banner)

        row = QHBoxLayout()
        row.setSpacing(16)
        self.c_all = FilterCard("Alle")
        self.c_clean = FilterCard("Sauber")
        self.c_susp = FilterCard("Auffällig")
        self.c_inf = FilterCard("Infiziert")
        self.c_err = FilterCard("Nicht geprüft")
        self.c_size = StatCard("Größe")
        # Klick auf eine Kachel filtert die Tabelle, ein zweiter Klick zeigt wieder die Funde
        self.filters = {"alle": self.c_all, "sauber": self.c_clean, "auffällig": self.c_susp,
                        "infiziert": self.c_inf, "nicht geprüft": self.c_err}
        for key, c in self.filters.items():
            c.clicked.connect(lambda key=key: self.set_filter(key))
        for c in (self.c_all, self.c_clean, self.c_susp, self.c_inf, self.c_err, self.c_size):
            row.addWidget(c, 1)
        lay.addLayout(row)

        card = Card("Funde")
        self.list_title = card.lay.itemAt(0).widget()
        self.table = make_table(["Datei", "Grund", "Stufe", "VirusTotal"])
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.Stretch)
        h.setSectionResizeMode(1, QHeaderView.Stretch)
        h.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.cellDoubleClicked.connect(self._open_vt)
        card.lay.addWidget(self.table)
        rel = QHBoxLayout()
        self.release_hint = label("", "small", wrap=True)
        self.btn_release = button("Auffällige freigeben …")
        rel.addWidget(self.release_hint, 1)
        rel.addWidget(self.btn_release)
        card.lay.addLayout(rel)
        vtl = QHBoxLayout()
        self.vt_hint = label("", "small", wrap=True)
        self.vt_hint.setTextFormat(Qt.RichText)
        self.btn_vt_check = button("Erneut abfragen")
        self.btn_vt_upload = button("Dateien an VirusTotal …")
        self.btn_vt_upload.setToolTip("Einzelne Dateien auswählen und abfragen (in den Stufen Manuell und Upload auch hochladen)")
        for b in (self.btn_vt_check, self.btn_vt_upload):
            b.setStyleSheet("padding: 6px 12px;")
        vtl.addWidget(self.vt_hint, 1)
        vtl.addWidget(self.btn_vt_check)
        vtl.addWidget(self.btn_vt_upload)
        card.lay.addLayout(vtl)
        lay.addWidget(card, 1)

        act = QHBoxLayout()
        act.setSpacing(10)
        self.btn_eject = button("⏏  Auswerfen", "primary", xl=True)
        self.btn_transfer = button("⇪  Auf Share übertragen", "go", xl=True)
        self.btn_transfer.setEnabled(False)
        self.btn_report = button("Bericht anzeigen")
        self.btn_again = button("Erneut prüfen")
        self.btn_home = button("Zur Startseite")
        for b in (self.btn_eject, self.btn_transfer, self.btn_report, self.btn_again, self.btn_home):
            act.addWidget(b)
        act.addStretch()
        lay.addLayout(act)
        self.btn_eject.clicked.connect(win.backend.eject)
        self.btn_transfer.clicked.connect(win.confirm_transfer)
        self.btn_again.clicked.connect(win.backend.scan)
        self.btn_home.clicked.connect(lambda: win.show_page("start"))
        self.btn_report.clicked.connect(self._report)
        self.btn_release.clicked.connect(win.open_release)
        self.btn_vt_upload.clicked.connect(win.open_vt_upload)
        self.btn_vt_check.clicked.connect(win.backend.vt_check)
        self._rid = ""
        self._rows: list[dict] = []
        self._filter = ""                    # "" = Funde (auffällig, infiziert, nicht lesbar)
        self._files: list[dict] | None = None   # alle Dateien aus dem Bericht, für die Filter
        self._files_key = None
        self._loading = False
        self._st: dict = {}
        win.backend.transferFiles.connect(self._report_loaded)

    def set_filter(self, key: str) -> None:
        self._filter = "" if key == self._filter else key
        self._fill_table()

    def _report_loaded(self, report: dict) -> None:
        if report.get("id") not in (self._rid, "demo") or not self._loading:
            return
        self._loading = False
        self._files = report.get("files") or []
        self._fill_table()

    def _report(self) -> None:
        if self._rid:
            self.win.backend.get_report(self._rid)

    def _open_vt(self, row: int, col: int) -> None:
        if col == 3 and 0 <= row < len(self._rows):
            open_vt_link(self._rows[row].get("vt"))

    def _update_vt(self, st: dict, res: dict, acts: dict) -> None:
        vtc = st.get("virustotal") or {}
        vs = res.get("vt")
        ready = vtc.get("ready")
        self.btn_vt_check.setVisible(bool(ready) and res.get("verdict") != "infiziert")
        self.btn_vt_check.setEnabled(bool(acts.get("vt_check")))
        self.btn_vt_upload.setVisible(bool(ready) and res.get("verdict") != "infiziert")
        self.btn_vt_upload.setEnabled(bool(acts.get("vt_send")))
        if not ready:
            self.vt_hint.setText("VirusTotal: aus" if vtc.get("mode") == "aus" or not vtc else
                                 f"VirusTotal: {html.escape(vtc.get('message', ''))}")
        elif res.get("verdict") == "infiziert":
            self.vt_hint.setText("VirusTotal: nicht gefragt, ClamAV hat schon Schadsoftware gefunden.")
        elif not vs:
            self.vt_hint.setText("VirusTotal: noch nicht abgefragt.")
            self.btn_vt_check.setText("Jetzt abfragen")
        else:
            self.btn_vt_check.setText("Erneut abfragen")
            parts = [f"{fmt_int(vs.get('checked'))} Dateien abgefragt", f"{fmt_int(vs.get('found'))} bekannt"]
            if vs.get("hits"):
                parts.append(f"<b style='color:{C['bad']}'>{fmt_int(vs['hits'])} gefährlich (gesperrt)</b>")
            if vs.get("warn"):
                parts.append(f"<span style='color:{C['warn']}'>{fmt_int(vs['warn'])} mit einzelnen Meldungen</span>")
            if vs.get("unknown"):
                parts.append(f"{fmt_int(vs['unknown'])} unbekannt")
            if vs.get("incomplete"):
                parts.append(f"<span style='color:{C['warn']}'>{fmt_int(vs['incomplete'])} nicht geprüft</span>")
            text = "VirusTotal: " + " · ".join(parts)
            if vs.get("error"):
                text += f"<br><small>{html.escape(vs['error'])}</small>"
            self.vt_hint.setText(text)
        self.vt_hint.setVisible(bool(vtc))

    def update_from(self, st: dict) -> None:
        dev = st.get("device") or {}
        res = st.get("result") or {}
        counts = res.get("counts") or {}
        self._rid = res.get("id", "")
        self.title.setText(f"Ergebnis · {dev.get('display_name', '')}")
        v = res.get("verdict", "")
        tone = RESULT_TONES.get(v, "info")
        n_susp = counts.get("suspicious", 0)
        titles = {"infiziert": "Schadsoftware gefunden",
                  "unvollständig": "Prüfung unvollständig",
                  "auffällig": f"{fmt_int(n_susp)} {'Datei' if n_susp == 1 else 'Dateien'} auffällig, "
                               "keine Viren gefunden",
                  "sauber": "Keine Schadsoftware gefunden"}
        body = st.get("message", "")
        if v == "infiziert":
            body += " Bitte den Datenträger auswerfen und der IT übergeben."
        elif counts.get("released"):
            n = counts["released"]
            body += (" 1 auffällige Datei ist freigegeben und wird mit übertragen." if n == 1 else
                     f" {fmt_int(n)} auffällige Dateien sind freigegeben und werden mit übertragen.")
        body += f" Dauer {fmt_duration(res.get('duration_s'))} min."
        self.banner.show_msg(tone, titles.get(v, v), body)
        self.c_all.set(fmt_int(counts.get("files")), "alle Dateien anzeigen")
        self.c_clean.set(fmt_int(counts.get("clean")), "", C["ok"])
        sub = []
        if counts.get("blocked"):
            sub.append(f"{fmt_int(counts['blocked'])} gesperrt")
        if counts.get("releasable"):
            sub.append(f"{fmt_int(counts.get('released', 0))} von {fmt_int(counts['releasable'])} freigegeben")
        self.c_susp.set(fmt_int(n_susp), " · ".join(sub), C["warn"] if n_susp else None)
        self.c_inf.set(fmt_int(counts.get("infected")), "", C["bad"] if counts.get("infected") else None)
        n_err = (counts.get("errors") or 0) + (counts.get("skipped") or 0)
        self.c_err.set(fmt_int(n_err), f"{fmt_int(counts.get('errors'))} nicht lesbar · "
                                       f"{fmt_int(counts.get('skipped'))} übersprungen (Symlinks)",
                       C["warn"] if counts.get("errors") else None)
        self.c_size.set(fmt_bytes(counts.get("bytes")), f"{fmt_int(counts.get('files'))} Dateien")
        acts = st.get("actions") or {}
        self.btn_eject.setEnabled(bool(acts.get("eject")))
        can_release = bool(counts.get("releasable")) and v != "infiziert"
        self.btn_release.setVisible(can_release)
        self.release_hint.setVisible(can_release)
        self.btn_release.setEnabled(bool(acts.get("release")))
        self.release_hint.setText(
            f"{fmt_int(counts.get('releasable'))} auffällige {'Datei darf' if counts.get('releasable') == 1 else 'Dateien dürfen'} "
            "laut Richtlinie nach einer Freigabe mit übertragen werden. Gesperrte bleiben immer auf dem Stick.")
        smb = st.get("smb") or {}
        self.btn_transfer.setEnabled(bool(acts.get("transfer")))
        self.btn_transfer.setVisible(v != "infiziert")
        self.btn_transfer.setToolTip(smb.get("transfer_block") or f"Saubere Dateien nach {smb.get('target')} kopieren")
        # sauber: Übertragen ist der nächste Schritt, sonst Auswerfen
        self.btn_transfer.setProperty("kind", "go" if acts.get("transfer") else None)
        self.btn_eject.setProperty("kind", None if acts.get("transfer") else "primary")
        repolish(self.btn_transfer)
        repolish(self.btn_eject)
        tr = st.get("transfer_result") or {}
        if tr and st.get("state") == "ERGEBNIS":
            self.transfer_banner.show_msg(RESULT_TONES.get(tr.get("verdict"), "warn"), tr.get("verdict", ""),
                                          tr.get("message", ""))
        elif v in ("sauber", "auffällig") and smb.get("transfer_block") and not acts.get("transfer"):
            self.transfer_banner.show_msg("info", "Übertragung nicht möglich", smb.get("transfer_block"))
        else:
            self.transfer_banner.hide()

        self._update_vt(st, res, acts)
        # Neue Prüfung, Freigabe oder VirusTotal-Ergebnis: die geladene Dateiliste ist veraltet
        key = (res.get("id"), json.dumps(counts, sort_keys=True), json.dumps(res.get("vt"), sort_keys=True))
        if key != self._files_key:
            self._files_key = key
            self._files = None
            self._loading = False
            if res.get("id") != (self._st.get("result") or {}).get("id"):
                self._filter = ""
        self._st = st
        self._fill_table()

    MAX_ROWS = 5000

    def _fill_table(self) -> None:
        st = self._st
        res = st.get("result") or {}
        f_key = self._filter
        for key, c in self.filters.items():
            c.select(key == f_key)
        titles = {"": "Funde", "alle": "Alle Dateien", "sauber": "Saubere Dateien", "auffällig": "Auffällige Dateien",
                  "infiziert": "Infizierte Dateien", "nicht geprüft": "Nicht geprüfte Dateien"}
        title = titles[f_key]
        t = self.table
        t.setColumnHidden(3, not (st.get("virustotal") or {}).get("ready") and not res.get("vt"))
        if f_key in ("alle", "sauber"):
            # saubere Dateien stehen nicht in den Funden, dafür den Bericht laden
            if self._files is None:
                if not self._loading and self._rid:
                    self._loading = True
                    self.win.backend.load_transfer_files(self._rid)
                self.list_title.setText(title.upper() + " · LADE …")
                return
            source = self._files
        else:
            source = st.get("findings") or []
        want = {"": ("infected", "suspicious", "error"), "alle": None, "sauber": ("clean",),
                "auffällig": ("suspicious",), "infiziert": ("infected",), "nicht geprüft": ("error", "skipped")}[f_key]
        rows = [f for f in source if want is None or f.get("status") in want]
        order = {"infected": 0, "suspicious": 1, "error": 2, "skipped": 3}
        rows.sort(key=lambda f: (order.get(f.get("status"), 4), f.get("path", "")))
        total = len(rows)
        rows = rows[:self.MAX_ROWS]
        self.list_title.setText(f"{title} ({fmt_int(total)})".upper() if f_key else title.upper())
        if total > len(rows):
            self.list_title.setText(f"{title.upper()} · ERSTE {fmt_int(len(rows))} VON {fmt_int(total)} "
                                    "(ALLE IM BERICHT)")
        t.setUpdatesEnabled(False)
        t.clearContents()
        t.setRowCount(max(1, len(rows)))
        if not rows:
            t.setItem(0, 0, cell("Keine Funde" if not f_key else "Keine Dateien", C["muted"]))
            for c in (1, 2, 3):
                t.setItem(0, c, cell(""))
        self._rows = rows
        for r, f in enumerate(self._rows):
            text, color = finding_stage(f)
            t.setItem(r, 0, cell(f.get("path", ""), mono_font=True))
            detail = "; ".join([f.get("detail", "")] + [n for n in f.get("notes", []) if n.startswith("VirusTotal")])
            reason = cell(detail.strip("; "))
            reason.setToolTip(detail.strip("; "))
            t.setItem(r, 1, reason)
            t.setItem(r, 2, cell(text, color, bold=True))
            t.setItem(r, 3, vt_cell(f.get("vt")))
        t.setUpdatesEnabled(True)


def finding_stage(f: dict) -> tuple[str, str]:
    """Stufe eines Fundes für Tabellen: (Text, Farbe)."""
    st = f.get("status")
    if st == "infected":
        return "infiziert", C["bad"]
    if st == "suspicious":
        if f.get("action") == "blockieren":
            return "gesperrt", C["bad"]
        return ("freigegeben", C["ok"]) if f.get("released") else ("Freigabe nötig", C["warn"])
    if st == "error":
        return "nicht lesbar", C["warn"]
    if st == "skipped":
        return "übersprungen", C["muted"]
    return "sauber", C["ok"]


def vt_cell(v: dict | None) -> QTableWidgetItem:
    """Zelle "VirusTotal": z. B. "3/72 Engines", Farbe nach Schwelle, Link im Tooltip."""
    if not v:
        return cell("—", C["muted"])
    r = v.get("rating") or vt_mod.rate(v, v.get("threshold", 3))
    color = {"hit": C["bad"], "warn": C["warn"], "ok": C["ok"]}.get(r, C["muted"])
    if v.get("state") in ("error", "limit", "skipped"):
        color = C["warn"]
    it = cell(vt_mod.short(v), color, bold=r in ("hit", "warn"))
    tip = []
    if v.get("how") == "upload":
        tip.append("hochgeladen")
    if v.get("message"):
        tip.append(v["message"])
    if v.get("link"):
        tip.append(f"{v['link']} (Doppelklick öffnet den Bericht bei VirusTotal)")
    it.setToolTip("\n".join(tip))
    return it


# Kioskmodus (firebridge-gui --kiosk): Vollbild, Schließen und Browser gesperrt
KIOSK = False


def open_vt_link(v: dict | None) -> None:
    if KIOSK:
        return  # ein Browser wäre ein Weg aus dem Kiosk
    if v and str(v.get("link", "")).startswith("https://www.virustotal.com/"):
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        QDesktopServices.openUrl(QUrl(v["link"]))


PHASES = [("verbinden", "Verbinden"), ("kopieren", "Kopieren + SHA-256"), ("abschließen", "Bericht ablegen"),
          ("trennen", "Trennen")]


class TransferPage(QWidget):
    """Laufende und abgeschlossene Übertragung."""

    def __init__(self, win: "MainWindow"):
        super().__init__()
        self.win = win
        self.setObjectName("page")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 22)
        lay.setSpacing(16)
        head = QHBoxLayout()
        head.setSpacing(12)
        self.spinner = Spinner(26)
        self.title = label("Übertragung", "h1")
        head.addWidget(self.spinner)
        head.addWidget(self.title, 1)
        lay.addLayout(head)
        self.banner = Banner()
        lay.addWidget(self.banner)

        steps = QHBoxLayout()
        steps.setSpacing(8)
        self.steps: list[Pill] = []
        for i, (_, text) in enumerate(PHASES):
            p = Pill(f"{i + 1}  {text}", "off")
            self.steps.append(p)
            steps.addWidget(p)
        steps.addStretch()
        lay.addLayout(steps)

        card = Card()
        top = QHBoxLayout()
        left = QVBoxLayout()
        left.addWidget(label("FORTSCHRITT", "lbl"))
        self.count = label("0 / 0 Dateien", "big")
        left.addWidget(self.count)
        right = QVBoxLayout()
        right.addWidget(label("RESTZEIT", "lbl"), 0, Qt.AlignRight)
        self.eta = label("—", "big")
        right.addWidget(self.eta, 0, Qt.AlignRight)
        top.addLayout(left, 1)
        top.addLayout(right)
        card.lay.addLayout(top)
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setRange(0, 1000)
        card.lay.addSpacing(6)
        card.lay.addWidget(self.bar)
        self.current = label("", "small")
        self.current.setFont(mono())
        card.lay.addWidget(self.current)
        lay.addWidget(card)

        row = QHBoxLayout()
        row.setSpacing(10)
        self.k_copied = StatCard("Kopiert und geprüft")
        self.k_failed = StatCard("Fehlgeschlagen")
        self.k_conn = StatCard("Verbindung")
        self.k_net = StatCard("Netzwerk")
        for k in (self.k_copied, self.k_failed, self.k_conn, self.k_net):
            k.big.setStyleSheet("font-size: 17px;")
            row.addWidget(k, 1)
        lay.addLayout(row)

        lay.addWidget(label("PROTOKOLL", "lbl"))
        self.log = QPlainTextEdit()
        self.log.setObjectName("log")
        self.log.setReadOnly(True)
        self.log.setFont(mono())
        self.log.setMaximumBlockCount(500)
        lay.addWidget(self.log, 1)

        act = QHBoxLayout()
        act.setSpacing(10)
        self.btn_cancel = button("Abbrechen")
        self.btn_eject = button("⏏  Auswerfen", "primary", xl=True)
        self.btn_report = button("Bericht anzeigen")
        self.btn_home = button("Zur Startseite")
        for b in (self.btn_cancel, self.btn_eject, self.btn_report, self.btn_home):
            act.addWidget(b)
        act.addStretch()
        lay.addLayout(act)
        self.btn_cancel.clicked.connect(win.backend.cancel_transfer)
        self.btn_eject.clicked.connect(win.backend.eject)
        self.btn_home.clicked.connect(lambda: win.show_page("start"))
        self.btn_report.clicked.connect(self._report)
        self._rid = ""

    def _report(self) -> None:
        if self._rid:
            self.win.backend.get_report(self._rid)

    def update_from(self, st: dict) -> None:
        state = st.get("state")
        dev = st.get("device") or {}
        self._rid = (st.get("result") or {}).get("id", "")
        running = state == "UEBERTRAGUNG"
        self.spinner.set_running(running)
        self.title.setText(f"{'Übertragung läuft' if running else 'Übertragung'} · {dev.get('display_name', '')}")
        self.btn_cancel.setVisible(running)
        self.btn_eject.setVisible(not running)
        self.btn_report.setVisible(not running)
        self.btn_home.setVisible(not running)
        self.btn_eject.setEnabled(bool((st.get("actions") or {}).get("eject")))
        fw = (st.get("smb") or {}).get("firewall") or {}
        if fw.get("open"):
            self.k_net.set("offen", fw.get("message", "") or "nur zum Ziel-Server", C["warn"])
        else:
            self.k_net.set("gesperrt", "nftables: Prüfdienst hat kein Netz", C["ok"])
        tr = st.get("transfer_result") or {}
        if state == "UEBERTRAGEN" and tr:
            v = tr.get("verdict", "")
            title = "Übertragung abgeschlossen" if v == "übertragen" else "Übertragung teilweise fehlgeschlagen"
            body = tr.get("message", "")
            if tr.get("renamed_count"):
                body += (f" {tr['renamed_count']} Dateinamen wurden für Windows angepasst "
                         "(siehe Bericht).")
            body += " Die Verbindung ist getrennt."
            self.banner.show_msg(RESULT_TONES.get(v, "ok"), title, body)
        else:
            self.banner.hide()
        if st.get("transfer"):
            self.set_progress(st["transfer"])

    def set_progress(self, p: dict) -> None:
        total, done = p.get("total", 0), p.get("done", 0)
        connecting = p.get("phase") == "verbinden"
        self.count.setText("Verbinde mit dem Server …" if connecting else f"{fmt_int(done)} / {fmt_int(total)} Dateien")
        bt, bd = p.get("bytes_total") or 0, p.get("bytes_done") or 0
        frac = bd / bt if bt else (done / total if total else 0)
        self.bar.setRange(0, 0 if connecting else 1000)
        self.bar.setValue(int(frac * 1000))
        self.eta.setText("≈ " + fmt_duration(p["eta"]) if p.get("eta") is not None else "—")
        cur = f"{p.get('current', '')}   ·   " if p.get("phase") == "kopieren" else ""
        self.current.setText(f"{cur}{fmt_bytes(bd)} von {fmt_bytes(bt)}\nZiel: {p.get('target', '')}")
        self.k_copied.set(fmt_int(p.get("copied", 0)), "SHA-256 auf dem Share bestätigt", C["ok"])
        failed = p.get("failed", 0)
        self.k_failed.set(fmt_int(failed), "Dateien, die nicht übertragen wurden", C["warn"] if failed else None)
        conn = p.get("connection", "")
        parts = [c.strip() for c in conn.split(",")]
        self.k_conn.set(parts[0] or "—", ", ".join(parts[1:]))
        phase = p.get("phase", "")
        keys = [k for k, _ in PHASES]
        idx = keys.index(phase) if phase in keys else 0
        finished = self.win.status.get("state") == "UEBERTRAGEN"
        for i, pill in enumerate(self.steps):
            pill.set(pill.text(), "ok" if i < idx or finished else ("warn" if i == idx else "off"))

    def set_log(self, lines: list[str]) -> None:
        self.log.setPlainText("\n".join(lines))
        self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())

    def add_log(self, line: str) -> None:
        self.log.appendPlainText(line)


class SettingsPage(QWidget):
    """Gespeicherte Ziele verwalten und Verbindung testen."""

    def __init__(self, win: "MainWindow"):
        super().__init__()
        self.win = win
        self.setObjectName("page")
        self._cfg: dict = {}
        self._current: dict = {}      # gerade bearbeitetes Ziel ({} = neues Ziel)
        self._select_after: str | None = None
        # Das Formular ist höher als kleine Bildschirme, daher scrollbar
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        inner = QWidget()
        inner.setObjectName("page")
        scroll.setWidget(inner)
        outer.addWidget(scroll)
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(26, 22, 26, 22)
        lay.setSpacing(16)
        lay.addWidget(label("Einstellungen", "h1"))
        self.banner = Banner()
        lay.addWidget(self.banner)
        self._build_admin(lay)
        self._build_kiosk(lay)
        self._build_zoom(lay)

        row = QHBoxLayout()
        row.setSpacing(16)
        lay.addLayout(row, 1)

        # -- Liste der Ziele
        lcard = Card("Gespeicherte Ziele")
        lcard.setFixedWidth(310)
        self.list = QListWidget()
        self.list.setObjectName("targets")
        self.list.setWordWrap(True)
        self.list.currentRowChanged.connect(self._row_changed)
        lcard.lay.addWidget(self.list, 1)
        self.empty = label("Noch kein Ziel gespeichert. Rechts eintragen und speichern.", "small", wrap=True)
        lcard.lay.addWidget(self.empty)
        lact = QHBoxLayout()
        lact.setSpacing(6)
        self.btn_new = button("+ Neu")
        self.btn_default = button("★ Standard")
        for b in (self.btn_new, self.btn_default):
            b.setStyleSheet("padding: 8px 10px;")
        self.btn_default.setToolTip("Dieses Ziel wird beim Übertragen vorgeschlagen")
        self.btn_delete = button("Löschen")
        self.btn_delete.setStyleSheet("padding: 8px 10px;")
        for b in (self.btn_new, self.btn_default, self.btn_delete):
            lact.addWidget(b)
        lcard.lay.addLayout(lact)
        row.addWidget(lcard)

        # -- Formular
        card = Card("Ziel")
        self.form_title = card.lay.itemAt(0).widget()
        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(8)
        self.f_name = QLineEdit()
        self.f_name.setPlaceholderText("optional, z. B. NAS Buchhaltung")
        self.f_server = QLineEdit()
        self.f_server.setPlaceholderText("nas01 oder 192.168.1.20")
        self.f_share = QLineEdit()
        self.f_share.setPlaceholderText("z. B. scans")
        self.f_folder = QLineEdit()
        self.f_folder.setPlaceholderText("optional, z. B. Eingang/USB")
        self.f_domain = QLineEdit()
        self.f_domain.setPlaceholderText("optional, z. B. FIRMA oder WORKGROUP")
        self.f_user = QLineEdit()
        self.f_user.setPlaceholderText("leer = Gastzugang")
        self.f_pass = QLineEdit()
        self.f_pass.setEchoMode(QLineEdit.Password)
        self.f_port = QLineEdit("445")
        self.f_port.setValidator(QIntValidator(1, 65535, self))
        self.f_port.setMaximumWidth(110)
        self.f_encrypt = QCheckBox("SMB3-Verschlüsselung verlangen (empfohlen)")
        self.f_verify = QCheckBox("Nach dem Kopieren zurücklesen und SHA-256 vergleichen (empfohlen)")
        self.f_clear = QCheckBox("Gespeichertes Passwort löschen")
        rows = [("Name", self.f_name), ("Server", self.f_server), ("Freigabe", self.f_share),
                ("Unterordner", self.f_folder), ("Domäne", self.f_domain), ("Benutzer", self.f_user),
                ("Passwort", self.f_pass), ("Port", self.f_port)]
        for i, (key, w) in enumerate(rows):
            grid.addWidget(label(key, "kvKey"), i, 0)
            grid.addWidget(w, i, 1)
        grid.addWidget(self.f_clear, len(rows), 1)
        grid.addWidget(self.f_encrypt, len(rows) + 1, 1)
        grid.addWidget(self.f_verify, len(rows) + 2, 1)
        grid.setColumnStretch(1, 1)
        card.lay.addLayout(grid)
        card.lay.addSpacing(6)
        self.preview = label("", "small", wrap=True)
        self.preview.setFont(mono())
        self.preview.setTextFormat(Qt.RichText)
        card.lay.addWidget(self.preview)
        self.locked = label("Die Ziele sind fest in /etc/firebridge/firebridge.toml eingestellt "
                            "(share_editable = false). Den Standard kannst du trotzdem wählen.", "small", wrap=True)
        card.lay.addWidget(self.locked)
        act = QHBoxLayout()
        act.setSpacing(10)
        self.btn_save = button("Speichern", "primary")
        self.btn_test = button("Verbindung testen")
        self.test_spinner = Spinner(20)
        act.addWidget(self.btn_save)
        act.addWidget(self.btn_test)
        act.addWidget(self.test_spinner)
        self.test_hint = label("", "small", wrap=True)
        act.addWidget(self.test_hint, 1)
        card.lay.addSpacing(6)
        card.lay.addLayout(act)
        card.lay.addStretch()
        row.addWidget(card, 1)

        prow = QHBoxLayout()
        prow.setSpacing(16)
        pcard = Card("Richtlinie für auffällige Dateien")
        pgrid = QGridLayout()
        pgrid.setHorizontalSpacing(14)
        pgrid.setVerticalSpacing(6)
        self.policy_boxes: dict[str, QComboBox] = {}
        for i, cat in enumerate(policy_mod.describe()):
            box = QComboBox()
            for action in policy_mod.ACTIONS:
                box.addItem(policy_mod.ACTION_LABELS[action], action)
            box.currentIndexChanged.connect(self._policy_changed)
            pgrid.addWidget(label(cat["label"], None, wrap=True), i, 0)
            pgrid.addWidget(box, i, 1)
            self.policy_boxes[cat["key"]] = box
        pgrid.setColumnStretch(0, 1)
        pcard.lay.addLayout(pgrid)
        pcard.lay.addSpacing(6)
        self.policy_hint = label("„Freigabe nötig“: im Ergebnis über „Auffällige freigeben …“ einzeln freigeben. "
                                 "Infizierte Dateien sind immer gesperrt. Gilt ab der nächsten Prüfung.",
                                 "small", wrap=True)
        pcard.lay.addWidget(self.policy_hint)
        pact = QHBoxLayout()
        self.btn_policy = button("Richtlinie speichern", "primary")
        self.btn_policy.setEnabled(False)
        self.btn_policy_reset = button("Standard")
        self.btn_policy.clicked.connect(self._save_policy)
        self.btn_policy_reset.clicked.connect(self._reset_policy)
        pact.addWidget(self.btn_policy)
        pact.addWidget(self.btn_policy_reset)
        pact.addStretch()
        pcard.lay.addLayout(pact)
        prow.addWidget(pcard, 3)

        self.ana_card = Card("Tiefenprüfung und Updates")
        self.ana_text = label("", None, wrap=True)
        self.ana_text.setTextFormat(Qt.RichText)
        self.ana_card.lay.addWidget(self.ana_text)
        self.ana_card.lay.addStretch()
        prow.addWidget(self.ana_card, 2)
        lay.addLayout(prow)
        self._policy_dirty = False
        self._policy_filling = False
        self._policy_editable = True

        self._build_vt(lay)

        self.fw_card = Card("Netzwerk-Sperre")
        self.fw_state = label("", "name")
        self.fw_text = label("Der Prüfdienst hat grundsätzlich kein Netz. Nur während einer freigegebenen "
                             "Übertragung oder eines Verbindungstests öffnet er per nftables tcp/445 zur IP "
                             "des Ziel-Servers und schließt danach wieder. Für VirusTotal genauso, nur tcp/443 "
                             "zu www.virustotal.com.", "small", wrap=True)
        self.fw_card.lay.addWidget(self.fw_state)
        self.fw_card.lay.addWidget(self.fw_text)
        lay.addWidget(self.fw_card)

        for w in (self.f_server, self.f_share, self.f_folder):
            w.textChanged.connect(self._update_preview)
        self.btn_save.clicked.connect(self._save)
        self.btn_test.clicked.connect(self._test)
        self.btn_new.clicked.connect(self._new)
        self.btn_default.clicked.connect(self._make_default)
        self.btn_delete.clicked.connect(self._delete)
        win.backend.shareConfig.connect(self.fill)
        win.backend.shareTested.connect(self.show_test)
        win.backend.vtConfig.connect(self._vt_config)
        win.backend.vtTested.connect(self._vt_tested)
        self._load_form({})

    # -- VirusTotal

    def _build_admin(self, lay: QVBoxLayout) -> None:
        card = Card("Admin")
        row = QHBoxLayout()
        row.setSpacing(12)
        self.admin_state = label("", None, wrap=True)
        self.btn_admin_pw = button("Passwort ändern …")
        self.btn_admin_pw.clicked.connect(self._admin_pw)
        row.addWidget(self.admin_state, 1)
        row.addWidget(self.btn_admin_pw)
        card.lay.addLayout(row)
        card.lay.addWidget(label("Geschützt sind: Einstellungen speichern, Verbindung mit ungespeicherten Daten "
                                 "testen, auffällige Dateien und USB-Geräte freigeben, VirusTotal-Upload, "
                                 "Verlauf löschen und Kioskmodus. Prüfen, Übertragen und Auswerfen geht ohne Passwort. "
                                 "Passwort vergessen: sudo firebridge-admin-passwort", "small", wrap=True))
        lay.addWidget(card)

    def _build_kiosk(self, lay: QVBoxLayout) -> None:
        card = Card("Kioskmodus")
        row = QHBoxLayout()
        row.setSpacing(12)
        self.kiosk_state = label("", None, wrap=True)
        self.btn_kiosk = button("Kiosk einschalten …")
        self.btn_kiosk.clicked.connect(self._kiosk_toggle)
        row.addWidget(self.kiosk_state, 1)
        row.addWidget(self.btn_kiosk)
        card.lay.addLayout(row)
        card.lay.addWidget(label("Im Kiosk startet die Station direkt in die Firebridge: Vollbild, ohne Desktop, "
                                 "Startmenü und Browser. Verlassen nur mit dem Admin-Passwort. Ein- und "
                                 "Ausschalten wirkt ab dem nächsten Start; ausgeschaltet ist die Anmeldung "
                                 "wieder wie vorher.", "small", wrap=True))
        lay.addWidget(card)
        self._kiosk: dict = {}
        self._kiosk_busy_until = 0.0
        self.win.backend.kioskChanged.connect(self._kiosk_changed)

    def _kiosk_show(self, k: dict) -> None:
        self._kiosk = k
        on = bool(k.get("on"))
        if not k:
            self.kiosk_state.setText("Unbekannt (Dienst nicht verbunden).")
        elif not k.get("available") and not on:
            self.kiosk_state.setText(k.get("reason") or "Nicht verfügbar.")
        elif on:
            now = " Diese Sitzung läuft im Kiosk." if self.win.kiosk else ""
            self.kiosk_state.setText(f"<b>Eingeschaltet:</b> die Station startet in den Kiosk.{now}")
        else:
            self.kiosk_state.setText("Ausgeschaltet: die Station startet mit der normalen Anmeldung." +
                                     (" Diese Sitzung läuft noch im Kiosk bis zum Neustart." if self.win.kiosk
                                      else ""))
        self.btn_kiosk.setText("Kiosk ausschalten …" if on else "Kiosk einschalten …")
        self.btn_kiosk.setEnabled(bool(k) and (on or bool(k.get("available"))))

    def _kiosk_toggle(self) -> None:
        on = not self._kiosk.get("on")
        text = ("Ab dem nächsten Start meldet sich die Station automatisch an und zeigt nur die Firebridge im "
                "Vollbild. Verlassen geht nur mit dem Admin-Passwort." if on else
                "Ab dem nächsten Start erscheint wieder die normale Anmeldung wie vor dem Kiosk.")
        box = QMessageBox(QMessageBox.Question, "Kioskmodus", text, QMessageBox.Cancel, self)
        ok = box.addButton("Einschalten" if on else "Ausschalten", QMessageBox.AcceptRole)
        box.setDefaultButton(ok)
        box.exec()
        if box.clickedButton() is ok:
            self.btn_kiosk.setEnabled(False)
            self.kiosk_state.setText("Wird umgestellt …")
            self._kiosk_busy_until = time.monotonic() + 25
            self.win.backend.set_kiosk(on)

    def _kiosk_changed(self, k: dict) -> None:
        self._kiosk_busy_until = 0.0
        self._kiosk_show(k)
        self.win._toast("Kioskmodus " + ("eingeschaltet" if k.get("on") else "ausgeschaltet") +
                        ": wirkt ab dem nächsten Start")

    def update_admin(self, a: dict) -> None:
        left = int(a.get("active_seconds") or 0)
        if a.get("root"):
            self.admin_state.setText("Angemeldet als root: alles erlaubt.")
        elif not a.get("has_password"):
            self.admin_state.setText("<b>Noch kein Admin-Passwort festgelegt.</b> Geschützte Aktionen sind "
                                     "gesperrt, bis eins festgelegt ist.")
        elif left > 0:
            self.admin_state.setText(f"Als Admin angemeldet, noch {max(1, round(left / 60))} Minuten.")
        else:
            self.admin_state.setText("Nicht als Admin angemeldet.")
        self.btn_admin_pw.setText("Passwort festlegen …" if not a.get("has_password") else "Passwort ändern …")

    def _admin_pw(self) -> None:
        a = self.win.admin
        if not a.get("has_password"):
            self.win._ask_admin(None, "")
        elif self.win.is_admin():
            self.win.change_admin_password()
        else:
            self.win._ask_admin(self.win.change_admin_password, "Zum Ändern zuerst mit dem bisherigen Passwort "
                                "anmelden.")

    def _build_zoom(self, lay: QVBoxLayout) -> None:
        """Größe der Oberfläche, gilt nur für diesen Benutzer und wirkt nach einem kurzen Neustart der GUI."""
        card = Card("Darstellung")
        row = QHBoxLayout()
        row.setSpacing(12)
        row.addWidget(label("Größe der Oberfläche", "kvKey"))
        self.zoom_box = QComboBox()
        detected = zoom.detected()
        auto_text = "Automatisch" + (f" (erkannt: {zoom.label(detected)})" if detected else "")
        self.zoom_box.addItem(auto_text, zoom.AUTO)
        for f in zoom.STEPS:
            self.zoom_box.addItem(zoom.label(f), f)
        wanted = self.win.zoom_wanted
        idx = self.zoom_box.findData(wanted)
        if idx < 0:  # krummer Wert von der Kommandozeile
            self.zoom_box.addItem(zoom.label(wanted), wanted)
            idx = self.zoom_box.count() - 1
        self.zoom_box.setCurrentIndex(idx)
        self.btn_zoom = button("Übernehmen")
        self.btn_zoom.setEnabled(False)
        self.zoom_box.currentIndexChanged.connect(
            lambda _: self.btn_zoom.setEnabled(self.zoom_box.currentData() != self.win.zoom_wanted))
        self.btn_zoom.clicked.connect(self._apply_zoom)
        row.addWidget(self.zoom_box)
        row.addWidget(self.btn_zoom)
        row.addStretch()
        card.lay.addLayout(row)
        locked = self.win.zoom_locked()
        hint = (locked + " Hier nicht änderbar." if locked else
                "Tastatur: Strg + größer, Strg − kleiner, Strg 0 automatisch. Die Oberfläche startet dafür kurz "
                "neu, eine laufende Prüfung oder Übertragung läuft im Dienst weiter.")
        card.lay.addWidget(label(f"Jetzt: {zoom.label(self.win.zoom_factor())}. {hint}", "small", wrap=True))
        if locked:
            self.zoom_box.setEnabled(False)
        lay.addWidget(card)

    def _apply_zoom(self) -> None:
        self.btn_zoom.setEnabled(False)
        self.win.set_zoom(self.zoom_box.currentData(), delay=False)

    def _build_vt(self, lay: QVBoxLayout) -> None:
        card = Card("VirusTotal (optional)")
        card.lay.addWidget(label("Zweite Meinung nach dem lokalen Scan. Gefragt werden nur Programme, Skripte, "
                                 "Makro-Dokumente, PDFs mit Aktionen und Archive. Ab der Schwelle wird eine Datei "
                                 "gesperrt; VirusTotal kann einen lokalen Fund nie aufheben.", "small", wrap=True))
        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(8)
        self.vt_mode = QComboBox()
        self.vt_mode.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.vt_mode.setMinimumContentsLength(24)
        self.vt_mode.addItem("Aus", "aus")
        self.vt_mode.addItem("Manuell: nur auf Knopfdruck abfragen oder hochladen", "manuell")
        self.vt_mode.addItem("Nur Hash-Abfrage (keine Inhalte verlassen den Rechner)", "hash")
        self.vt_mode.addItem("Hash-Abfrage + Upload unbekannter Dateien auf Nachfrage", "upload")
        self.vt_public = QRadioButton("Kostenlose Public API (nur nicht-kommerziell)")
        self.vt_premium = QRadioButton("Premium-Lizenz (Einsatz in der Firma)")
        lic = QVBoxLayout()
        lic.setSpacing(4)
        lic.addWidget(self.vt_public)
        lic.addWidget(self.vt_premium)
        # Ein QCheckBox bricht nicht um, daher kurzer Text am Kästchen und die Erklärung darunter
        self.vt_confirm = QCheckBox("Nicht-kommerzielle Nutzung bestätigen")
        cbox = QVBoxLayout()
        cbox.setContentsMargins(22, 2, 0, 2)
        cbox.setSpacing(2)
        cbox.addWidget(self.vt_confirm)
        cbox.addWidget(label(vt_mod.NONCOMMERCIAL_TEXT + " Für den Einsatz in einer Firma braucht es eine "
                             "Premium-Lizenz.", "small", wrap=True))
        self.vt_confirm_wrap = QWidget()
        self.vt_confirm_wrap.setLayout(cbox)
        lic.addWidget(self.vt_confirm_wrap)
        self.vt_confirmed = label("", "small", wrap=True)
        lic.addWidget(self.vt_confirmed)
        self.vt_key = QLineEdit()
        self.vt_key.setEchoMode(QLineEdit.Password)
        self.vt_key.setPlaceholderText("64 Zeichen, aus deinem VirusTotal-Konto (API Key)")
        self.vt_clear = QCheckBox("Gespeicherten Key löschen")
        self.vt_threshold = QSpinBox()
        self.vt_threshold.setRange(1, 50)
        self.vt_threshold.setSuffix(" Engines")
        self.vt_threshold.setMaximumWidth(140)
        self.vt_strict = QCheckBox("Übertragen sperren, wenn VirusTotal nicht alles prüfen konnte")
        self.vt_strict.setToolTip("Streng: VirusTotal nicht erreichbar, Kontingent erschöpft oder Analyse nicht "
                                  "fertig sperrt die Übertragung. Sonst steht es nur im Bericht.")
        rows = [("Stufe", self.vt_mode), ("Lizenz", lic), ("API-Key", self.vt_key), ("", self.vt_clear),
                ("Sperren ab", self.vt_threshold), ("", self.vt_strict)]
        for i, (key, w) in enumerate(rows):
            grid.addWidget(label(key, "kvKey"), i, 0, Qt.AlignTop)
            (grid.addLayout if isinstance(w, QVBoxLayout) else grid.addWidget)(w, i, 1)
        grid.setColumnStretch(1, 1)
        card.lay.addLayout(grid)
        self.vt_status = label("", "small", wrap=True)
        self.vt_status.setTextFormat(Qt.RichText)
        card.lay.addWidget(self.vt_status)
        act = QHBoxLayout()
        act.setSpacing(10)
        self.btn_vt_save = button("VirusTotal speichern", "primary")
        self.btn_vt_test = button("Verbindung testen")
        self.vt_spinner = Spinner(20)
        self.vt_hint = label("", "small", wrap=True)
        for w in (self.btn_vt_save, self.btn_vt_test, self.vt_spinner):
            act.addWidget(w)
        act.addWidget(self.vt_hint, 1)
        card.lay.addLayout(act)
        lay.addWidget(card)
        self._vt_dirty = False
        self._vt_filling = False
        self._vt_cfg: dict = {}
        for w in (self.vt_mode, self.vt_threshold):
            (w.currentIndexChanged if isinstance(w, QComboBox) else w.valueChanged).connect(self._vt_changed)
        for w in (self.vt_public, self.vt_premium, self.vt_confirm, self.vt_clear, self.vt_strict):
            w.toggled.connect(self._vt_changed)
        self.vt_key.textChanged.connect(self._vt_changed)
        self.btn_vt_save.clicked.connect(self._vt_save)
        self.btn_vt_test.clicked.connect(self._vt_test)

    def _vt_changed(self, *_):
        if not self._vt_filling:
            self._vt_dirty = True
        self._vt_update_controls()

    def _vt_fill(self, v: dict) -> None:
        self._vt_cfg = v
        if self._vt_dirty:
            self._vt_update_controls()
            return
        self._vt_filling = True
        i = self.vt_mode.findData(v.get("mode", "aus"))
        self.vt_mode.setCurrentIndex(max(0, i))
        self.vt_public.setChecked(v.get("license") == "public")
        self.vt_premium.setChecked(v.get("license") == "premium")
        if not v.get("license"):
            for r in (self.vt_public, self.vt_premium):
                r.setAutoExclusive(False)
                r.setChecked(False)
                r.setAutoExclusive(True)
        self.vt_confirm.setChecked(False)
        self.vt_clear.setChecked(False)
        self.vt_threshold.setValue(int(v.get("threshold") or 3))
        self.vt_strict.setChecked(bool(v.get("block_on_error")))
        self._vt_filling = False
        self._vt_update_controls()

    def _vt_license(self) -> str:
        return "public" if self.vt_public.isChecked() else "premium" if self.vt_premium.isChecked() else ""

    def _vt_update_controls(self) -> None:
        v = self._vt_cfg
        editable = v.get("editable", True)
        mode = self.vt_mode.currentData()
        lic = self._vt_license()
        confirmed = lic == "public" and v.get("license") == "public" and bool(v.get("license_confirmed"))
        upload_item = self.vt_mode.model().item(self.vt_mode.findData("upload"))
        if upload_item is not None:
            upload_item.setEnabled(bool(v.get("allow_upload", True)))
        for w in (self.vt_mode, self.vt_public, self.vt_premium, self.vt_key, self.vt_threshold, self.vt_strict):
            w.setEnabled(editable)
        self.vt_confirm_wrap.setVisible(lic == "public" and not confirmed)
        self.vt_confirm.setEnabled(editable)
        if confirmed:
            self.vt_confirmed.setText(f"✓ Nicht-kommerzielle Nutzung bestätigt am {fmt_when(v['license_confirmed'])}")
        elif lic == "premium" and v.get("license") == "premium" and v.get("license_confirmed"):
            self.vt_confirmed.setText(f"Premium-Lizenz eingetragen am {fmt_when(v['license_confirmed'])}")
        else:
            self.vt_confirmed.setText("")
        self.vt_confirmed.setVisible(bool(self.vt_confirmed.text()))
        self.vt_clear.setVisible(bool(v.get("has_key")) and editable)
        self.vt_key.setPlaceholderText("Key hinterlegt ✓ · leer lassen = unverändert" if v.get("has_key")
                                       else "64 Zeichen, aus deinem VirusTotal-Konto (API Key)")
        problem = ""
        if mode != "aus" and not lic:
            problem = "Bitte angeben, mit welcher Lizenz VirusTotal genutzt wird."
        elif mode != "aus" and lic == "public" and not confirmed and not self.vt_confirm.isChecked():
            problem = "Die kostenlose API ist nur für nicht-kommerzielle Nutzung erlaubt: bitte bestätigen."
        elif mode != "aus" and not v.get("has_key") and not self.vt_key.text().strip():
            problem = "Ohne API-Key fragt die Firebridge VirusTotal nicht."
        if not editable:
            problem = "VirusTotal ist fest in /etc/firebridge/firebridge.toml eingestellt (editable = false)."
        blocking = problem and "API-Key" not in problem
        self.btn_vt_save.setEnabled(editable and self._vt_dirty and not blocking)
        st = self.win.status
        test_hint = ""
        if self.btn_vt_test.text() == "Verbindung testen":
            can_test = bool((st.get("actions") or {}).get("vt_test"))
            self.btn_vt_test.setEnabled(can_test)
            if can_test:
                pass
            elif not v.get("has_key"):
                test_hint = "Testen geht erst, wenn ein API-Key gespeichert ist."
            else:
                test_hint = {"SCAN": "Während der Prüfung gibt es kein Netz.",
                             "UEBERTRAGUNG": "Gerade läuft eine Übertragung.",
                             "VIRUSTOTAL": "Gerade läuft eine VirusTotal-Abfrage."}.get(
                    st.get("state"), "Testen geht erst, wenn kein ungeprüfter Datenträger steckt: "
                                     "Stick prüfen (sauber) oder abziehen bzw. auswerfen.")
            self.btn_vt_test.setToolTip(test_hint)
        self.vt_hint.setText(problem or test_hint)
        self.vt_hint.setStyleSheet(f"color: {C['warn']};" if problem else "")
        used, limit = v.get("quota_used", 0), v.get("quota_limit", 0)
        quota = (f"Heute {fmt_int(used)} von {fmt_int(limit)} Anfragen" if limit else
                 f"Heute {fmt_int(used)} Anfragen") + (f", höchstens {v['per_minute']} pro Minute"
                                                      if v.get("per_minute") else "")
        dot = C["ok"] if v.get("ready") else C["muted"]
        self.vt_status.setText(f"<span style='color:{dot}'>●</span> {html.escape(v.get('message', ''))}"
                               f" · {html.escape(quota)}"
                               + ("" if v.get("allow_upload", True) else
                                  " · Upload gesperrt (allow_upload = false)"))

    def _vt_save(self) -> None:
        data = {"mode": self.vt_mode.currentData(), "license": self._vt_license(),
                "threshold": self.vt_threshold.value(), "block_on_error": self.vt_strict.isChecked()}
        if self.vt_confirm.isChecked() and data["license"] == "public":
            data["confirm_noncommercial"] = True
        if self.vt_key.text().strip():
            data["api_key"] = self.vt_key.text().strip()
        elif self.vt_clear.isChecked():
            data["clear_key"] = True
        self.banner.hide()
        self.win.backend.set_virustotal(data)

    def _vt_config(self, v: dict) -> None:
        if v.get("saved"):
            # Feld leeren ohne _vt_changed: sonst gilt das Formular gleich wieder als geändert
            self._vt_filling = True
            self.vt_key.clear()
            self._vt_filling = False
            self._vt_dirty = False
            self.banner.show_msg("ok", "VirusTotal gespeichert", v.get("message", ""))
        self._vt_fill(v)

    def _vt_test(self) -> None:
        self.btn_vt_test.setEnabled(False)
        self.btn_vt_test.setText("Teste …")
        self.vt_spinner.start()
        self.banner.show_msg("info", "VirusTotal-Test läuft",
                             "Netzwerk-Fenster zu www.virustotal.com wird geöffnet, der Key wird geprüft.")
        self.win.backend.test_virustotal()

    def _vt_tested(self, res: dict) -> None:
        self.vt_spinner.stop()
        self.btn_vt_test.setText("Verbindung testen")
        steps = "\n".join(f"✓ {x}" for x in res.get("steps") or [])
        body = steps if res.get("ok") else f"{steps}\n✗ {res.get('message', '')}".strip()
        self.banner.show_msg("ok" if res.get("ok") else "bad",
                             "VirusTotal erreichbar" if res.get("ok") else "VirusTotal-Test fehlgeschlagen", body)
        self._vt_update_controls()

    # -- Liste

    def fill(self, cfg: dict) -> None:
        self._cfg = cfg
        targets = cfg.get("targets") or []
        keep = self._select_after or cfg.get("saved_id") or self._current.get("id") or cfg.get("active")
        self._select_after = None
        self.list.blockSignals(True)
        self.list.clear()
        for t in targets:
            star = "★ " if t.get("default") else ""
            sub = t.get("target", "") if t.get("name") else ""
            it = QListWidgetItem(f"{star}{t.get('label', '')}" + (f"\n{sub}" if sub else ""))
            it.setData(Qt.UserRole, t.get("id"))
            it.setToolTip(t.get("target", ""))
            self.list.addItem(it)
        self.list.blockSignals(False)
        self.empty.setVisible(not targets)
        self.list.setVisible(bool(targets))
        ids = [t.get("id") for t in targets]
        if keep in ids:
            self.list.setCurrentRow(ids.index(keep))
            self._load_form(targets[ids.index(keep)])
        elif targets:
            self.list.setCurrentRow(0)
            self._load_form(targets[0])
        else:
            self._load_form({})
        editable = cfg.get("editable", True)
        for w in (self.f_name, self.f_server, self.f_share, self.f_folder, self.f_domain, self.f_user,
                  self.f_pass, self.f_port, self.f_encrypt, self.f_verify, self.f_clear, self.btn_save,
                  self.btn_new, self.btn_delete):
            w.setEnabled(editable)
        self.locked.setVisible(not editable)
        self._update_buttons()
        if cfg.get("saved_id"):
            self.banner.show_msg("ok", "Gespeichert", "Das Ziel ist gespeichert und bleibt auch nach einem "
                                                      "Neustart erhalten.")

    def _row_changed(self, row: int) -> None:
        targets = self._cfg.get("targets") or []
        if 0 <= row < len(targets):
            self.banner.hide()
            self._load_form(targets[row])

    def _update_buttons(self) -> None:
        cur = self._current
        editable = self._cfg.get("editable", True)
        self.btn_default.setEnabled(bool(cur.get("id")) and not cur.get("default"))
        self.btn_delete.setEnabled(editable and bool(cur.get("id")))

    def _new(self) -> None:
        self.list.clearSelection()
        self.list.setCurrentRow(-1)
        self.banner.hide()
        self._load_form({})
        self.f_name.setFocus()

    def _make_default(self) -> None:
        if self._current.get("id"):
            self.win.backend.select_share(self._current["id"])

    def _delete(self) -> None:
        cur = self._current
        if not cur.get("id"):
            return
        box = QMessageBox(self)
        box.setWindowTitle("Ziel löschen")
        box.setIcon(QMessageBox.Warning)
        box.setText(f"Ziel „{cur.get('label', '')}“ löschen?")
        box.setInformativeText("Einstellungen und gespeichertes Passwort werden entfernt. "
                               "Bereits übertragene Dateien auf dem Share bleiben, wo sie sind.")
        yes = box.addButton("Löschen", QMessageBox.DestructiveRole)
        box.addButton("Abbrechen", QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() is yes:
            self._current = {}
            self.win.backend.delete_share(cur["id"])
            self.banner.show_msg("ok", "Gelöscht", f"„{cur.get('label', '')}“ wurde entfernt.")

    # -- Formular

    def _load_form(self, t: dict) -> None:
        self._current = t
        self.form_title.setText(("ZIEL BEARBEITEN" + (" · STANDARD" if t.get("default") else ""))
                                if t.get("id") else "NEUES ZIEL")
        self.f_name.setText(t.get("name", ""))
        self.f_server.setText(t.get("server", ""))
        self.f_share.setText(t.get("share", ""))
        self.f_folder.setText(t.get("folder", ""))
        self.f_domain.setText(t.get("domain", ""))
        self.f_user.setText(t.get("username", ""))
        self.f_port.setText(str(t.get("port", 445)))
        self.f_encrypt.setChecked(bool(t.get("encrypt", True)))
        self.f_verify.setChecked(bool(t.get("verify", True)))
        self.f_pass.clear()
        self.f_pass.setPlaceholderText("gespeichert · leer lassen = unverändert" if t.get("has_password")
                                       else "Passwort")
        self.f_clear.setChecked(False)
        self.f_clear.setVisible(bool(t.get("has_password")))
        self._update_preview()
        self._update_buttons()

    def form(self) -> dict:
        data = {"name": self.f_name.text().strip(), "server": self.f_server.text().strip(),
                "share": self.f_share.text().strip(), "folder": self.f_folder.text().strip(),
                "domain": self.f_domain.text().strip(), "username": self.f_user.text().strip(),
                "port": int(self.f_port.text() or 445), "encrypt": self.f_encrypt.isChecked(),
                "verify": self.f_verify.isChecked()}
        if self._current.get("id"):
            data["id"] = self._current["id"]
        if self.f_pass.text():
            data["password"] = self.f_pass.text()
        elif self.f_clear.isChecked():
            data["clear_password"] = True
        return data

    def _update_preview(self) -> None:
        server, share = self.f_server.text().strip(), self.f_share.text().strip()
        if not server or not share:
            self.preview.setText("Ziel: (Server und Freigabe eintragen)")
            return
        folder = "\\".join(p for p in self.f_folder.text().replace("/", "\\").split("\\") if p)
        base = "\\".join(p for p in (f"\\\\{server}", share, folder) if p)
        self.preview.setText("Ziel je Datenträger: " + _breakable_path(
            f"{base}\\<Datum>_<Uhrzeit>_<Hersteller>_<Serien-Nr.>\\"))

    def _save(self) -> None:
        self.banner.hide()
        self.win.backend.set_share(self.form())

    def _test(self) -> None:
        self.btn_test.setEnabled(False)
        self.btn_test.setText("Teste …")
        self.test_spinner.start()
        self.banner.show_msg("info", "Verbindungstest läuft",
                             "Netzwerk-Fenster wird geöffnet, Anmeldung und Schreibrecht werden geprüft.")
        data = self.form()
        cur = self._current
        changed = "password" in data or any(data.get(k) != cur.get(k) for k in data
                                            if k not in ("id", "password", "clear_password"))
        self.win.backend.test_share(data if changed or not cur.get("id") else {"id": cur["id"]})

    def show_test(self, res: dict) -> None:
        self.test_spinner.stop()
        self.btn_test.setText("Verbindung testen")
        self.update_from(self.win.status)
        steps = "\n".join(f"✓ {s}" for s in res.get("steps") or [])
        body = steps if res.get("ok") else f"{steps}\n✗ {res.get('message', '')}".strip()
        self.banner.show_msg("ok" if res.get("ok") else "bad",
                             "Verbindung in Ordnung" if res.get("ok") else "Verbindung fehlgeschlagen", body)

    # -- Richtlinie

    def _policy_changed(self, *_):
        if not self._policy_filling:
            self._policy_dirty = True
            self.btn_policy.setEnabled(self._policy_editable)

    def _fill_policy(self, policy: dict) -> None:
        self._policy_filling = True
        for key, box in self.policy_boxes.items():
            i = box.findData(policy.get(key, "blockieren"))
            box.setCurrentIndex(max(0, i))
        self._policy_filling = False

    def _save_policy(self) -> None:
        self.win.backend.set_policy({k: b.currentData() for k, b in self.policy_boxes.items()})
        self._policy_dirty = False
        self.btn_policy.setEnabled(False)

    def _reset_policy(self) -> None:
        self._fill_policy(policy_mod.defaults())
        self._policy_changed()

    def _update_analysis(self, st: dict) -> None:
        self._policy_editable = bool(st.get("policy_editable", True))
        for box in self.policy_boxes.values():
            box.setEnabled(self._policy_editable)
        self.btn_policy_reset.setEnabled(self._policy_editable)
        if not self._policy_editable:
            self.policy_hint.setText("Die Richtlinie ist fest in /etc/firebridge/firebridge.toml eingestellt "
                                     "(policy_editable = false).")
        if not self._policy_dirty and st.get("policy"):
            self._fill_policy(st["policy"])
        ana = st.get("analysis") or {}
        y = ana.get("yara") or {}

        def yes(ok, text_ok, text_bad):
            color = C["ok"] if ok else C["bad"]
            return f"<span style='color:{color}'>●</span> {html.escape(text_ok if ok else text_bad)}"

        lines = [
            yes(y.get("ready"), f"YARA-X {y.get('yara_x', '')}: {fmt_int(y.get('rules'))} Regeln "
                                f"({y.get('source', '')} {y.get('version', '')})".replace(" )", ")"),
                f"YARA-X: {y.get('message') or 'nicht bereit'}"),
            yes(ana.get("olevba"), "olevba: Makros in Office-Dokumenten", "olevba fehlt (oletools)"),
            yes(ana.get("magic"), "libmagic: Dateityp am Inhalt", "libmagic fehlt (python3-magic), nur eigene Regeln"),
            yes(True, "PDF-Prüfung und ZIP-Inhalt", ""),
        ]
        sc = st.get("scan_cache") or {}
        if sc.get("max"):
            lines.append(f"Zwischenspeicher: {fmt_int(sc.get('entries'))} von {fmt_int(sc['max'])} Dateien "
                         "bekannt (wird bei neuen Signaturen oder Regeln geleert)")
        if y.get("skipped"):
            lines.append(f"<small>{fmt_int(y['skipped'])} YARA-Regeln sind mit YARA-X nicht übersetzbar "
                         "und wurden übersprungen.</small>")
        up = st.get("update") or {}
        if up.get("running"):
            lines.append("<br><b>Update läuft …</b>")
        elif up.get("finished"):
            lines.append(f"<br><b>Letztes Update {html.escape(fmt_when(up['finished']))}</b>")
            for step in up.get("steps", []):
                lines.append(yes(step.get("ok"), f"{step['name']}: {step['message']}",
                                 f"{step['name']}: {step['message']}"))
        else:
            lines.append("<br>Noch kein Update gelaufen. Täglich um 03:00 (firebridge-update.timer).")
        self.ana_text.setText("<br>".join(lines))

    def update_from(self, st: dict) -> None:
        if time.monotonic() > self._kiosk_busy_until:    # während des Umschaltens nicht überschreiben
            self._kiosk_show(st.get("kiosk") or {})
        smb = st.get("smb") or {}
        fw = smb.get("firewall") or {}
        acts = st.get("actions") or {}
        self._update_analysis(st)
        if st.get("virustotal"):
            self._vt_fill(st["virustotal"])
        if self.btn_test.text() == "Verbindung testen":
            self.btn_test.setEnabled(bool(acts.get("test_share")))
            hint = ""
            if not acts.get("test_share"):
                hint = {"SCAN": "Während der Prüfung gibt es kein Netz.",
                        "UEBERTRAGUNG": "Gerade läuft eine Übertragung."}.get(
                    st.get("state"), "Erst testen, wenn kein ungeprüfter Datenträger steckt: "
                                     "Stick prüfen (sauber) oder abziehen bzw. auswerfen.")
            self.btn_test.setToolTip(hint)
            self.test_hint.setText(hint)
        if fw.get("disabled"):
            self.fw_state.setText("AUS")
            self.fw_state.setStyleSheet(f"color: {C['bad']};")
        elif not fw.get("ok"):
            self.fw_state.setText("nicht aktiv · Übertragung gesperrt")
            self.fw_state.setStyleSheet(f"color: {C['bad']};")
        elif fw.get("open"):
            self.fw_state.setText("Fenster offen")
            self.fw_state.setStyleSheet(f"color: {C['warn']};")
        else:
            self.fw_state.setText("aktiv · Netzwerk gesperrt")
            self.fw_state.setStyleSheet(f"color: {C['ok']};")
        self.fw_text.setToolTip(fw.get("message", ""))


def _breakable_path(path: str) -> str:
    # Wortverbinder nach jedem Backslash, sonst bricht Qt den Pfad nach dem ersten Backslash um
    return html.escape(path).replace(chr(92), chr(92) + chr(0x2060))


class TransferDialog(QDialog):
    """Rückfrage vor der Übertragung: Ziel wählen, alle sauberen Dateien oder eine Auswahl."""

    def __init__(self, parent: "MainWindow", st: dict, targets: list[dict]):
        super().__init__(parent)
        self.win = parent
        self.setWindowTitle("Übertragung freigeben")
        self.setMinimumWidth(620)
        self.targets = [t for t in targets if t.get("configured")]
        self.rid = (st.get("result") or {}).get("id", "")
        self.counts = (st.get("result") or {}).get("counts") or {}
        self._files: list[dict] | None = None     # saubere Dateien aus dem Bericht (für die Auswahl)
        self._updating = False
        lay = QVBoxLayout(self)
        lay.setContentsMargins(22, 20, 22, 18)
        lay.setSpacing(10)
        lay.addWidget(label("Saubere Dateien auf das Netzwerkshare übertragen?", "bannerTitle", wrap=True))

        lay.addWidget(label("ZIEL", "lbl"))
        self.combo = QComboBox()
        for t in self.targets:
            self.combo.addItem(("★ " if t.get("default") else "") + t.get("label", ""), t.get("id"))
        default = next((i for i, t in enumerate(self.targets) if t.get("default")), 0)
        self.combo.setCurrentIndex(default)
        self.combo.setVisible(len(self.targets) > 1)
        lay.addWidget(self.combo)
        self.path = QLabel()
        self.path.setTextFormat(Qt.RichText)
        self.path.setWordWrap(True)
        lay.addWidget(self.path)

        lay.addSpacing(4)
        lay.addWidget(label("WAS", "lbl"))
        n_all = self.counts.get("clean", 0) + self.counts.get("released", 0)
        rel = f", davon {fmt_int(self.counts['released'])} freigegebene" if self.counts.get("released") else ""
        self.r_all = QRadioButton(f"Alle sauberen Dateien ({fmt_int(n_all)} Dateien{rel})")
        self.r_sel = QRadioButton("Nur bestimmte Dateien auswählen …")
        self.r_all.setChecked(True)
        lay.addWidget(self.r_all)
        lay.addWidget(self.r_sel)

        self.sel_box = QWidget()
        sl = QVBoxLayout(self.sel_box)
        sl.setContentsMargins(0, 4, 0, 0)
        sl.setSpacing(6)
        tools = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filtern, z. B. .pdf oder Rechnung")
        b_all = button("Alle")
        b_none = button("Keine")
        for b in (b_all, b_none):
            b.setStyleSheet("padding: 6px 10px;")
        tools.addWidget(self.search, 1)
        tools.addWidget(b_all)
        tools.addWidget(b_none)
        sl.addLayout(tools)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["DATEI", "GRÖSSE"])
        self.tree.setMinimumHeight(300)
        self.tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        sl.addWidget(self.tree)
        self.sel_info = label("Lade Dateiliste …", "small")
        sl.addWidget(self.sel_info)
        self.sel_box.hide()
        lay.addWidget(self.sel_box, 1)

        info = ("Die Verbindung wird erst jetzt aufgebaut und nach dem Kopieren wieder getrennt. "
                "Jede Datei wird per SHA-256 mit dem geprüften Stand verglichen.")
        left_out = []
        if self.counts.get("errors"):
            left_out.append(f"{fmt_int(self.counts['errors'])} nicht lesbare Dateien")
        if self.counts.get("skipped"):
            left_out.append(f"{fmt_int(self.counts['skipped'])} Symlinks/Sonderdateien")
        held = self.counts.get("suspicious", 0) - self.counts.get("released", 0)
        if held > 0:
            left_out.append(f"{fmt_int(held)} auffällige, nicht freigegebene Dateien")
        if left_out:
            info += f" Nie übertragen werden {' und '.join(left_out)}."
        lay.addWidget(label(info, "small", wrap=True))
        act = QHBoxLayout()
        act.addStretch()
        cancel = button("Abbrechen")
        self.ok = button("⇪  Übertragen", "go")
        self.ok.setDefault(True)
        act.addWidget(cancel)
        act.addWidget(self.ok)
        lay.addSpacing(6)
        lay.addLayout(act)

        cancel.clicked.connect(self.reject)
        self.ok.clicked.connect(self.accept)
        self.combo.currentIndexChanged.connect(self._update_path)
        self.r_sel.toggled.connect(self._mode_changed)
        self.tree.itemChanged.connect(self._item_changed)
        self.search.textChanged.connect(self._filter)
        b_all.clicked.connect(lambda: self._check_all(True))
        b_none.clicked.connect(lambda: self._check_all(False))
        parent.backend.transferFiles.connect(self._files_loaded)
        if not self.targets:  # Liste noch nicht geladen: Standardziel aus dem Status
            smb = st.get("smb") or {}
            self.targets = [{"id": "", "target": smb.get("target", ""), "label": smb.get("label", "")}]
        self._update_path()

    def done(self, result: int) -> None:
        try:
            self.win.backend.transferFiles.disconnect(self._files_loaded)
        except (RuntimeError, TypeError):
            pass
        super().done(result)

    # -- Ergebnis

    def target_id(self) -> str:
        i = self.combo.currentIndex()
        return self.targets[i].get("id", "") if 0 <= i < len(self.targets) else ""

    def selected_files(self) -> list[str] | None:
        """None = alle sauberen Dateien."""
        if not self.r_sel.isChecked():
            return None
        out = []
        it = QTreeWidgetItemIterator(self.tree)
        while it.value():
            item = it.value()
            path = item.data(0, Qt.UserRole)
            if path and item.checkState(0) == Qt.Checked:
                out.append(path)
            it += 1
        return out

    # -- Anzeige

    def _update_path(self) -> None:
        i = max(0, self.combo.currentIndex())
        t = self.targets[i] if i < len(self.targets) else {}
        self.path.setText(f"<tt>{_breakable_path(t.get('target', '').split(' (Port')[0] + chr(92) + self.rid)}</tt>")

    def _mode_changed(self, sel: bool) -> None:
        self.sel_box.setVisible(sel)
        if sel and self._files is None:
            self.ok.setEnabled(False)
            self.win.backend.load_transfer_files(self.rid)
        self._update_info()
        if sel:
            fit_to_screen(self, max(self.width(), 680), max(self.height(), 760))
        else:
            self.adjustSize()

    def _files_loaded(self, report: dict) -> None:
        if report.get("id") not in (self.rid, "demo") or self._files is not None:
            return
        self._files = [f for f in report.get("files") or [] if transferable(f)]
        parts = {f["path"].split("/", 1)[0] for f in self._files}
        self._updating = True
        self.tree.clear()
        folders: dict[str, QTreeWidgetItem] = {}

        def folder(path: str) -> QTreeWidgetItem:
            if path in folders:
                return folders[path]
            parent_path, _, name = path.rpartition("/")
            parent = folder(parent_path) if parent_path else self.tree.invisibleRootItem()
            item = QTreeWidgetItem(parent, [f"📁 {name}", ""])
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable | Qt.ItemIsAutoTristate)
            item.setCheckState(0, Qt.Checked)
            folders[path] = item
            return item

        for f in sorted(self._files, key=lambda f: f["path"].lower()):
            # bei nur einer Partition den Partitionsordner ("sdb1") weglassen, wie auf dem Share
            shown = f["path"].split("/", 1)[1] if len(parts) == 1 else f["path"]
            dirname, _, name = shown.rpartition("/")
            parent = folder(dirname) if dirname else self.tree.invisibleRootItem()
            item = QTreeWidgetItem(parent, [name, fmt_bytes(f.get("size"))])
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(0, Qt.Checked)
            item.setData(0, Qt.UserRole, f["path"])
            item.setData(1, Qt.UserRole, int(f.get("size") or 0))
        self.tree.expandToDepth(0)
        self._updating = False
        self._update_info()

    def _item_changed(self, *_):
        if not self._updating:
            self._update_info()

    def _check_all(self, on: bool) -> None:
        self._updating = True
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            if not root.child(i).isHidden():
                root.child(i).setCheckState(0, Qt.Checked if on else Qt.Unchecked)
        self._updating = False
        self._update_info()

    def _filter(self, text: str) -> None:
        text = text.strip().lower()

        def walk(item: QTreeWidgetItem) -> bool:
            path = item.data(0, Qt.UserRole)
            if path:
                visible = not text or text in path.lower()
            else:
                visible = False
                for i in range(item.childCount()):
                    visible = walk(item.child(i)) or visible
            item.setHidden(not visible)
            return visible

        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            walk(root.child(i))
        if text:
            self.tree.expandAll()

    def _update_info(self) -> None:
        if not self.r_sel.isChecked():
            self.ok.setEnabled(True)
            return
        if self._files is None:
            self.sel_info.setText("Lade Dateiliste …")
            return
        n, size = 0, 0
        it = QTreeWidgetItemIterator(self.tree)
        while it.value():
            item = it.value()
            if item.data(0, Qt.UserRole) and item.checkState(0) == Qt.Checked:
                n += 1
                size += item.data(1, Qt.UserRole) or 0
            it += 1
        self.sel_info.setText(f"{fmt_int(n)} von {fmt_int(len(self._files))} Dateien ausgewählt · {fmt_bytes(size)}")
        self.ok.setEnabled(n > 0)


def _release_line(releases: list | None) -> str:
    """Wer im Ergebnis Dateien freigegeben oder die Freigabe zurückgenommen hat."""
    parts = []
    for r in releases or []:
        what = []
        if r.get("released"):
            what.append(f"{len(r['released'])} freigegeben")
        if r.get("revoked"):
            what.append(f"{len(r['revoked'])} zurückgenommen")
        if what:
            parts.append(f"{fmt_when(r.get('time'))} {html.escape(r.get('by') or 'unbekannt')}: {', '.join(what)}")
    return "<br>Freigaben: " + " · ".join(parts) if parts else ""


def _transfer_line(tr: dict | None) -> str:
    if not tr:
        return ""
    line = (f"<br>Übertragung {fmt_when(tr.get('finished'))}: <b>{tr.get('verdict', '')}</b> · "
            f"{fmt_int(tr.get('copied'))} von {fmt_int(tr.get('planned'))} Dateien nach {tr.get('target', '')}")
    if tr.get("error"):
        line += f" · {tr['error']}"
    return line


def _analysis_line(ana: dict | None) -> str:
    if not ana:
        return ""
    y = ana.get("yara") or {}
    parts = [f"YARA-X {y.get('rules', 0)} Regeln" if y.get("ready") else "YARA-X aus"]
    parts.append("olevba" if ana.get("olevba") else "ohne olevba")
    parts.append("libmagic" if ana.get("magic") else "ohne libmagic")
    return "<br>Tiefenprüfung: " + " · ".join(parts)


def _vt_line(v: dict | None) -> str:
    if not v:
        return ""
    lic = {"public": "Public API, nicht-kommerziell bestätigt", "premium": "Premium-Lizenz"}.get(v.get("license"), "")
    if v.get("license_confirmed"):
        lic += f" {fmt_when(v['license_confirmed'])}"
    parts = [f"{fmt_int(v.get('checked'))} abgefragt", f"{fmt_int(v.get('hits'))} gefährlich",
             f"{fmt_int(v.get('unknown'))} unbekannt"]
    if v.get("uploaded"):
        parts.append(f"{fmt_int(v['uploaded'])} hochgeladen")
    if v.get("incomplete"):
        parts.append(f"{fmt_int(v['incomplete'])} nicht geprüft")
    return f"<br>VirusTotal ({html.escape(lic)}, Schwelle {v.get('threshold')}): " + " · ".join(parts)


class ReleaseDialog(QDialog):
    """Auffällige Dateien mit "Freigabe nötig" zum Übertragen freigeben."""

    def __init__(self, parent: "MainWindow", st: dict):
        super().__init__(parent)
        self.win = parent
        self.setWindowTitle("Auffällige Dateien freigeben")
        fit_to_screen(self, 860, 560)
        self.rid = (st.get("result") or {}).get("id", "")
        counts = (st.get("result") or {}).get("counts") or {}
        lay = QVBoxLayout(self)
        lay.setContentsMargins(22, 20, 22, 18)
        lay.setSpacing(10)
        lay.addWidget(label("Welche auffälligen Dateien sollen mit übertragen werden?", "bannerTitle", wrap=True))
        text = ("Freigeben ist eine bewusste Entscheidung: Gib nur Dateien frei, die du kennst und erwartest, "
                "z. B. ein Skript der IT. Freigegebene Dateien werden beim Übertragen mitkopiert, der Bericht "
                "vermerkt die Freigabe mit Uhrzeit.")
        if counts.get("blocked"):
            text += (f" {fmt_int(counts['blocked'])} weitere {'ist' if counts['blocked'] == 1 else 'sind'} laut "
                     "Richtlinie gesperrt und lassen sich nicht freigeben.")
        lay.addWidget(label(text, "small", wrap=True))
        self.table = make_table(["", "Datei", "Grund"])
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.Interactive)
        h.setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setColumnWidth(1, 340)
        lay.addWidget(self.table, 1)
        self.info = label("Lade Dateiliste …", "small")
        lay.addWidget(self.info)
        act = QHBoxLayout()
        b_all = button("Alle")
        b_none = button("Keine")
        for b in (b_all, b_none):
            b.setStyleSheet("padding: 6px 10px;")
        act.addWidget(b_all)
        act.addWidget(b_none)
        act.addStretch()
        cancel = button("Abbrechen")
        self.ok = button("Freigabe speichern", "primary")
        self.ok.setEnabled(False)
        act.addWidget(cancel)
        act.addWidget(self.ok)
        lay.addLayout(act)
        cancel.clicked.connect(self.reject)
        self.ok.clicked.connect(self.accept)
        b_all.clicked.connect(lambda: self._check_all(True))
        b_none.clicked.connect(lambda: self._check_all(False))
        self.table.itemChanged.connect(lambda *_: self._update_info())
        self._paths: list[str] = []
        parent.backend.transferFiles.connect(self._loaded)
        parent.backend.load_transfer_files(self.rid)

    def done(self, result: int) -> None:
        try:
            self.win.backend.transferFiles.disconnect(self._loaded)
        except (RuntimeError, TypeError):
            pass
        super().done(result)

    def _loaded(self, report: dict) -> None:
        if report.get("id") not in (self.rid, "demo") or self._paths:
            return
        files = [f for f in report.get("files") or []
                 if f.get("status") == "suspicious" and f.get("action") == "freigabe"]
        t = self.table
        t.blockSignals(True)
        t.setRowCount(len(files))
        for r, f in enumerate(files):
            box = QTableWidgetItem()
            box.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            box.setCheckState(Qt.Checked if f.get("released") else Qt.Unchecked)
            t.setItem(r, 0, box)
            t.setItem(r, 1, cell(f["path"], mono_font=True))
            reason = cell(f.get("detail", ""))
            reason.setToolTip(f.get("detail", ""))
            t.setItem(r, 2, reason)
            self._paths.append(f["path"])
        t.blockSignals(False)
        self.ok.setEnabled(True)
        self._update_info()

    def _check_all(self, on: bool) -> None:
        for r in range(self.table.rowCount()):
            self.table.item(r, 0).setCheckState(Qt.Checked if on else Qt.Unchecked)

    def selected(self) -> list[str]:
        return [p for r, p in enumerate(self._paths) if self.table.item(r, 0).checkState() == Qt.Checked]

    def _update_info(self) -> None:
        self.info.setText(f"{fmt_int(len(self.selected()))} von {fmt_int(len(self._paths))} ausgewählt")


class UsbAlertDialog(QDialog):
    """Alarm für ein neues USB-Gerät (Etappe 4): gesperrt, Tipp-Probe oder Angriff erkannt."""

    def __init__(self, parent: "MainWindow", alert: dict):
        super().__init__(parent)
        self.win = parent
        self.alert_id = alert["id"]
        self.setWindowTitle("Firebridge – USB-Gerät")
        # Ohne Schließen-Knopf: Der Bediener soll bewusst entscheiden
        self.setWindowFlags(Qt.Dialog | Qt.CustomizeWindowHint | Qt.WindowTitleHint | Qt.WindowStaysOnTopHint)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(22, 20, 22, 18)
        # Höhe immer passend zum Inhalt (Probe, Angriff und Gerät sind unterschiedlich groß)
        outer.setSizeConstraint(QLayout.SetFixedSize)
        body = QWidget()
        body.setFixedWidth(600)
        outer.addWidget(body)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)
        self.banner = Banner()
        lay.addWidget(self.banner)

        # Tipp-Probe: großer Code
        self.probe = QFrame()
        self.probe.setProperty("role", "card")
        pl = QVBoxLayout(self.probe)
        pl.setContentsMargins(16, 14, 16, 14)
        pl.setSpacing(6)
        pl.addWidget(label("CODE AUF DER NEUEN TASTATUR EINTIPPEN, DANN ENTER", "lbl"))
        self.code = QLabel()
        f = mono()
        f.setPointSize(30)
        f.setBold(True)
        f.setLetterSpacing(QFont.AbsoluteSpacing, 10)
        self.code.setFont(f)
        self.code.setStyleSheet(f"color: {C['accent']};")
        pl.addWidget(self.code)
        self.typed = label("", "small", wrap=True)
        pl.addWidget(self.typed)
        lay.addWidget(self.probe)

        # Angriff: Gründe und abgefangene Eingabe
        self.attack = QWidget()
        al = QVBoxLayout(self.attack)
        al.setContentsMargins(0, 0, 0, 0)
        al.setSpacing(6)
        self.reasons = label("", None, wrap=True)
        al.addWidget(self.reasons)
        al.addWidget(label("ABGEFANGENE EINGABE (HAT DEN RECHNER NICHT ERREICHT)", "lbl"))
        self.keys = QPlainTextEdit()
        self.keys.setReadOnly(True)
        self.keys.setObjectName("log")
        self.keys.setFont(mono())
        self.keys.setFixedHeight(84)
        al.addWidget(self.keys)
        self.stats = label("", "small", wrap=True)
        al.addWidget(self.stats)
        lay.addWidget(self.attack)

        kv = QGridLayout()
        kv.setHorizontalSpacing(16)
        kv.setVerticalSpacing(3)
        self.kv: dict[str, QLabel] = {}
        for i, key in enumerate(("Gerät", "USB-ID", "Schnittstellen", "Gesperrt durch")):
            kv.addWidget(label(key, "kvKey"), i, 0, Qt.AlignTop)
            val = label("", "kvVal", wrap=True)
            val.setFont(mono())
            kv.addWidget(val, i, 1)
            self.kv[key] = val
        kv.setColumnStretch(1, 1)
        lay.addLayout(kv)

        act = QHBoxLayout()
        act.addStretch()
        self.btn_dismiss = button("Gesperrt lassen")
        self.btn_allow = button("Ja, selbst angeschlossen – freigeben", "primary")
        act.addWidget(self.btn_dismiss)
        act.addWidget(self.btn_allow)
        lay.addLayout(act)
        self.btn_dismiss.clicked.connect(lambda: self._act(parent.backend.usb_dismiss))
        self.btn_allow.clicked.connect(lambda: self._act(parent.backend.usb_allow))
        self.update_from(alert)

    def _act(self, fn) -> None:
        self.btn_allow.setEnabled(False)
        self.btn_dismiss.setEnabled(False)
        fn(self.alert_id)
        # Bei einem Fehler kommt kein neuer Status, dann nach kurzer Zeit wieder bedienbar machen
        QTimer.singleShot(4000, lambda: self.btn_dismiss.setEnabled(True))

    def update_from(self, a: dict) -> None:
        dev = a.get("device") or {}
        state, kind = a.get("state"), a.get("kind")
        keys = a.get("keys") or {}
        if state == "alarm":
            tone, title = "bad", "Angriff erkannt: Das Gerät tippt selbstständig"
        elif state == "probe":
            tone, title = "info", "Tipp-Probe für die neue Tastatur"
        elif kind == "badusb":
            tone, title = "bad", "BadUSB: Speicher meldet sich auch als Tastatur oder Netzwerkkarte"
        elif kind == "netzwerk":
            tone, title = "bad", "USB-Netzwerkadapter gesperrt"
        elif kind == "eingabe":
            kb = dev.get("keyboard")
            tone, title = "warn", "Neue Tastatur angeschlossen" if kb else "Neues Eingabegerät angeschlossen"
        else:
            tone, title = "warn", "Unbekanntes USB-Gerät gesperrt"
        body = a.get("message", "")
        if state == "probe":
            left = a.get("seconds_left", 0)
            body = ("Bis der Code stimmt, erreicht keine Taste dieser Tastatur den Rechner. Ein Angriffs-Stick "
                    f"kennt den Code nicht. Noch {left // 60}:{left % 60:02d} min.")
            if a.get("tries"):
                body += f" Falscher Code, Versuch {a['tries'] + 1} von {a.get('tries_max', 3)}."
        self.banner.show_msg(tone, title, body)

        self.probe.setVisible(state == "probe")
        if state == "probe":
            self.code.setText(" ".join(a.get("code", "")))
            n = keys.get("digits", 0)
            self.typed.setText("Getippt: " + ("●" * n if n else "noch nichts") +
                               ("  ·  Enter drücken" if n >= len(a.get("code", "")) else ""))
        self.attack.setVisible(state == "alarm")
        if state == "alarm":
            self.reasons.setText("".join(f"• {html.escape(r)}<br>" for r in a.get("reasons") or []))
            self.reasons.setTextFormat(Qt.RichText)
            text = keys.get("text") or "(keine Tasten abgefangen)"
            if self.keys.toPlainText() != text:
                self.keys.setPlainText(text)
            parts = [f"{fmt_int(keys.get('keys'))} Tasten"]
            if keys.get("keys_per_min"):
                parts.append(f"≈ {fmt_int(keys['keys_per_min'])} Anschläge/min")
            if keys.get("median_ms") is not None:
                parts.append(f"Abstand {keys['median_ms']:.0f} ms (Mensch: 80–250 ms)")
            if keys.get("first_key_s") is not None:
                parts.append(f"erste Taste nach {keys['first_key_s']:.1f} s")
            self.stats.setText(" · ".join(parts) + ". Anzeige nach US-Tastaturbelegung.")

        self.kv["Gerät"].setText(f"{dev.get('name', '?')} · {dev.get('kind_text', '')}")
        self.kv["USB-ID"].setText(f"{dev.get('usb_id', '?')} · Port {dev.get('port', '?')}"
                                  + (f" · Serien-Nr. {dev['serial']}" if dev.get("serial") else ""))
        ifaces = dev.get("interfaces") or []
        self.kv["Schnittstellen"].setText(", ".join(f"{i['name']} ({i['code']})" for i in ifaces) or "keine lesbar")
        bad_if = kind in ("badusb", "netzwerk")
        self.kv["Schnittstellen"].setStyleSheet(f"color: {C['bad']}; font-weight: 600;" if bad_if else "")
        if a.get("blocked"):
            how = a.get("how") or "—"
        elif state == "probe":
            how = f"vorläufig zugelassen, Tasten festgehalten ({a.get('how', '')})"
        else:
            how = "nicht gesperrt!"
        self.kv["Gesperrt durch"].setText(how)

        allow = bool(a.get("allow_possible"))
        self.btn_allow.setVisible(allow)
        self.btn_allow.setEnabled(allow)
        self.btn_allow.setText("Ja, selbst angeschlossen – freigeben" if kind == "eingabe"
                               else "Bis zum Abziehen zulassen")
        self.btn_dismiss.setEnabled(True)
        if state == "probe":
            self.btn_dismiss.setText("Abbrechen und sperren")
            self.btn_dismiss.setProperty("kind", None)
        elif state == "alarm" or kind in ("badusb", "netzwerk"):
            self.btn_dismiss.setText("Gesperrt lassen und protokollieren")
            self.btn_dismiss.setProperty("kind", "danger")
        else:
            self.btn_dismiss.setText("Gesperrt lassen")
            self.btn_dismiss.setProperty("kind", None)
        repolish(self.btn_dismiss)
        self.adjustSize()


VT_PHASES = {"verbinden": "Verbinde mit www.virustotal.com …", "abfragen": "Hash-Abfrage",
             "hochladen": "Upload", "warten": "Warte auf die Analyse", "trennen": "Trenne die Verbindung …"}


class VtPage(QWidget):
    """Laufende VirusTotal-Abfrage bzw. laufender Upload (Zustand VIRUSTOTAL)."""

    def __init__(self, win: "MainWindow"):
        super().__init__()
        self.win = win
        self.setObjectName("page")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 22)
        lay.setSpacing(16)
        head = QHBoxLayout()
        head.setSpacing(12)
        self.spinner = Spinner(26)
        self.title = label("VirusTotal-Abfrage", "h1")
        head.addWidget(self.spinner)
        head.addWidget(self.title, 1)
        lay.addLayout(head)
        self.banner = Banner()
        lay.addWidget(self.banner)

        card = Card()
        top = QHBoxLayout()
        left = QVBoxLayout()
        left.addWidget(label("FORTSCHRITT", "lbl"))
        self.count = label("0 / 0 Dateien", "big")
        left.addWidget(self.count)
        right = QVBoxLayout()
        right.addWidget(label("RESTZEIT", "lbl"), 0, Qt.AlignRight)
        self.eta = label("—", "big")
        right.addWidget(self.eta, 0, Qt.AlignRight)
        top.addLayout(left, 1)
        top.addLayout(right)
        card.lay.addLayout(top)
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setRange(0, 1000)
        card.lay.addSpacing(6)
        card.lay.addWidget(self.bar)
        self.current = label("", "small")
        self.current.setFont(mono())
        card.lay.addWidget(self.current)
        self.wait = label("", "small", wrap=True)
        card.lay.addWidget(self.wait)
        lay.addWidget(card)

        row = QHBoxLayout()
        row.setSpacing(10)
        self.k_mode = StatCard("Stufe")
        self.k_quota = StatCard("Kontingent heute")
        self.k_net = StatCard("Netzwerk")
        for k in (self.k_mode, self.k_quota, self.k_net):
            k.big.setStyleSheet("font-size: 17px;")
            row.addWidget(k, 1)
        lay.addLayout(row)

        lay.addWidget(label("PROTOKOLL", "lbl"))
        self.log = QPlainTextEdit()
        self.log.setObjectName("log")
        self.log.setReadOnly(True)
        self.log.setFont(mono())
        self.log.setMaximumBlockCount(500)
        lay.addWidget(self.log, 1)
        act = QHBoxLayout()
        self.btn_cancel = button("Abbrechen (Rest bleibt ungeprüft)")
        self.btn_cancel.clicked.connect(win.backend.vt_cancel)
        act.addWidget(self.btn_cancel)
        act.addStretch()
        lay.addLayout(act)
        self._kind = "hash"

    def update_from(self, st: dict) -> None:
        vtc = st.get("virustotal") or {}
        p = vtc.get("progress") or {}
        running = st.get("state") == "VIRUSTOTAL"
        self.spinner.set_running(running)
        self.btn_cancel.setEnabled(bool((st.get("actions") or {}).get("vt_cancel")))
        self.k_mode.set({"public": "Public API", "premium": "Premium"}.get(vtc.get("license"), "—"),
                        "nur nicht-kommerziell (bestätigt)" if vtc.get("license") == "public" else "Lizenz")
        limit = vtc.get("quota_limit")
        self.k_quota.set(f"{fmt_int(vtc.get('quota_used'))} / {fmt_int(limit)}" if limit else
                         fmt_int(vtc.get("quota_used")),
                         f"höchstens {vtc.get('per_minute')} pro Minute" if vtc.get("per_minute") else "ohne Drossel")
        fw = (st.get("smb") or {}).get("firewall") or {}
        self.k_net.set("offen" if fw.get("open") else "gesperrt", "nur tcp/443 zu www.virustotal.com",
                       C["warn"] if fw.get("open") else C["ok"])
        if p:
            self.set_progress(p)

    def set_progress(self, p: dict) -> None:
        self._kind = p.get("kind", "hash")
        upload = self._kind == "upload"
        self.title.setText("Upload zu VirusTotal" if upload else "VirusTotal-Abfrage")
        if upload:
            self.banner.show_msg("warn", "Dateien werden an VirusTotal gesendet",
                                 "Nur die ausgewählten Dateien. Sie sind danach für Sicherheitsfirmen und zahlende "
                                 "VirusTotal-Kunden einsehbar.")
        else:
            self.banner.show_msg("info", "Zweite Meinung von VirusTotal",
                                 "Es wird nur der SHA-256 der Programme, Skripte, Makro-Dokumente und Archive "
                                 "abgefragt. Inhalte verlassen den Rechner nicht.")
        total, done = p.get("total", 0), p.get("done", 0)
        self.count.setText(f"{fmt_int(done)} / {fmt_int(total)} Dateien")
        self.bar.setValue(int(done / total * 1000) if total else 0)
        phase = p.get("phase", "")
        self.current.setText(f"{VT_PHASES.get(phase, phase)}   ·   {p.get('current', '')}".strip(" ·"))
        self.eta.setText("≈ " + fmt_duration(p["eta"]) if p.get("eta") else "—")
        w = p.get("waiting") or 0
        self.wait.setText(f"Nächste Anfrage in {int(w + 0.5)} s: Die kostenlose API erlaubt nur wenige Anfragen "
                          "pro Minute." if w >= 1 else "")

    def set_log(self, lines: list[str]) -> None:
        self.log.setPlainText("\n".join(lines))
        self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())

    def add_log(self, line: str) -> None:
        self.log.appendPlainText(line)


VT_UPLOAD_NOTICE = ("Hochgeladene Dateien sind nicht privat. VirusTotal gibt sie an Sicherheitsfirmen weiter, "
                    "und zahlende Kunden können sie herunterladen und einsehen. Ein Upload lässt sich nicht "
                    "zurücknehmen. Lade nichts Vertrauliches hoch: keine Personal-, Kunden- oder Vertragsdaten, "
                    "keine internen Dokumente oder Skripte mit Passwörtern.")


class VtUploadDialog(QDialog):
    """Nach der Prüfung einzelne Dateien an VirusTotal: nur abfragen (SHA-256) oder unbekannte hochladen."""

    def __init__(self, parent: "MainWindow", st: dict):
        super().__init__(parent)
        self.win = parent
        self.setWindowTitle("Dateien an VirusTotal")
        fit_to_screen(self, 940, 700)
        self.rid = (st.get("result") or {}).get("id", "")
        vtc = st.get("virustotal") or {}
        self.can_upload = bool((st.get("actions") or {}).get("vt_upload"))
        self.max_bytes = int(vtc.get("max_upload_mb") or 650) * 1024 * 1024
        lay = QVBoxLayout(self)
        lay.setContentsMargins(22, 20, 22, 18)
        lay.setSpacing(10)
        lay.addWidget(label("Welche Dateien sollen zu VirusTotal?", "bannerTitle", wrap=True))

        lay.addWidget(label("WIE", "lbl"))
        self.r_hash = QRadioButton("Nur abfragen: es geht nur der SHA-256 raus, kein Inhalt")
        self.r_upload = QRadioButton("Abfragen und Dateien, die VirusTotal nicht kennt, hochladen")
        self.r_hash.setChecked(True)
        self.r_upload.setEnabled(self.can_upload)
        if not self.can_upload:
            self.r_upload.setToolTip("Hochladen geht nur in der Stufe „Hash-Abfrage + Upload“ (Einstellungen)")
        lay.addWidget(self.r_hash)
        lay.addWidget(self.r_upload)
        self.warn = Banner()
        self.warn.show_msg("bad", "Achtung: Hochgeladene Dateien können von Dritten eingesehen werden",
                           VT_UPLOAD_NOTICE)
        lay.addWidget(self.warn)

        lay.addWidget(label("WELCHE", "lbl"))
        tools = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filtern, z. B. .exe oder Rechnung")
        self.only_unknown = QCheckBox("nur noch nicht abgefragte und unbekannte")
        tools.addWidget(self.search, 1)
        tools.addWidget(self.only_unknown)
        lay.addLayout(tools)
        self.table = make_table(["", "Datei", "Größe", "Stufe", "VirusTotal"])
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.Stretch)
        for i in (2, 3, 4):
            h.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        lay.addWidget(self.table, 1)
        sel = QHBoxLayout()
        self.b_all = button("Alle sichtbaren")
        self.b_none = button("Keine")
        for b in (self.b_all, self.b_none):
            b.setStyleSheet("padding: 6px 10px;")
        sel.addWidget(self.b_all)
        sel.addWidget(self.b_none)
        self.info = label("Lade Dateiliste …", "small")
        sel.addWidget(self.info, 1)
        lay.addLayout(sel)

        lic = ("Kostenlose Public API (nicht-kommerzielle Nutzung bestätigt)" if vtc.get("license") == "public"
               else "Premium-Lizenz")
        per = vtc.get("per_minute")
        self.timing = label("", "small", wrap=True)
        self._lic, self._per = lic, per
        lay.addWidget(self.timing)
        self.confirm = QCheckBox("Ich habe den Hinweis gelesen. Die ausgewählten Dateien enthalten nichts "
                                 "Vertrauliches und dürfen an VirusTotal gehen.")
        lay.addWidget(self.confirm)
        act = QHBoxLayout()
        act.addStretch()
        cancel = button("Abbrechen")
        self.ok = button("Abfragen", "primary")
        self.ok.setEnabled(False)
        act.addWidget(cancel)
        act.addWidget(self.ok)
        lay.addLayout(act)
        cancel.clicked.connect(self.reject)
        self.ok.clicked.connect(self.accept)
        self.b_all.clicked.connect(lambda: self._check_all(True))
        self.b_none.clicked.connect(lambda: self._check_all(False))
        self.r_upload.toggled.connect(lambda *_: self._update_info())
        self.confirm.toggled.connect(lambda *_: self._update_info())
        self.search.textChanged.connect(lambda *_: self._apply_filter())
        self.only_unknown.toggled.connect(lambda *_: self._apply_filter())
        self.table.itemChanged.connect(lambda *_: self._update_info())
        self._files: list[dict] = []
        self._loaded_once = False
        self._update_info()
        parent.backend.transferFiles.connect(self._loaded)
        parent.backend.load_transfer_files(self.rid)

    def done(self, result: int) -> None:
        try:
            self.win.backend.transferFiles.disconnect(self._loaded)
        except (RuntimeError, TypeError):
            pass
        super().done(result)

    @property
    def upload(self) -> bool:
        return self.r_upload.isChecked()

    def _loaded(self, report: dict) -> None:
        if report.get("id") not in (self.rid, "demo") or self._loaded_once:
            return
        self._loaded_once = True
        # jede geprüfte Datei außer infizierten; Auffällige zuerst
        order = {"suspicious": 0, "clean": 1}
        self._files = sorted((f for f in report.get("files") or [] if vt_mod.sendable(f)),
                             key=lambda f: (order.get(f.get("status"), 2), f.get("path", "").lower()))
        t = self.table
        t.blockSignals(True)
        t.setRowCount(len(self._files))
        for r, f in enumerate(self._files):
            box = QTableWidgetItem()
            box.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            box.setCheckState(Qt.Unchecked)
            t.setItem(r, 0, box)
            t.setItem(r, 1, cell(f["path"], mono_font=True))
            t.setItem(r, 2, cell(fmt_bytes(f.get("size")), mono_font=True))
            text, color = finding_stage(f)
            t.setItem(r, 3, cell(text, color, bold=True))
            t.setItem(r, 4, vt_cell(f.get("vt")))
        t.blockSignals(False)
        self._apply_filter()

    def _apply_filter(self) -> None:
        text = self.search.text().strip().lower()
        only = self.only_unknown.isChecked()
        for r, f in enumerate(self._files):
            state = (f.get("vt") or {}).get("state")
            hide = (bool(text) and text not in f["path"].lower()) or (only and state in ("found", "uploaded"))
            self.table.setRowHidden(r, hide)
        self._update_info()

    def _check_all(self, on: bool) -> None:
        self.table.blockSignals(True)
        for r in range(self.table.rowCount()):
            if not self.table.isRowHidden(r):
                self.table.item(r, 0).setCheckState(Qt.Checked if on else Qt.Unchecked)
        self.table.blockSignals(False)
        self._update_info()

    def selected(self) -> list[str]:
        return [f["path"] for r, f in enumerate(self._files)
                if self.table.item(r, 0) and self.table.item(r, 0).checkState() == Qt.Checked]

    def _update_info(self) -> None:
        up = self.upload
        self.warn.setVisible(up)
        self.confirm.setVisible(up)
        n = len(self.selected()) if self._loaded_once else 0
        big = sum(1 for r, f in enumerate(self._files) if self.table.item(r, 0)
                  and self.table.item(r, 0).checkState() == Qt.Checked and int(f.get("size") or 0) > self.max_bytes)
        if self._loaded_once:
            extra = f" · {fmt_int(big)} zu groß zum Hochladen" if up and big else ""
            self.info.setText(f"{fmt_int(n)} von {fmt_int(len(self._files))} ausgewählt{extra}")
        timing = f" Höchstens {self._per} Anfragen pro Minute." if self._per else ""
        if self._per and n > self._per:
            timing += f" {fmt_int(n)} Dateien dauern etwa {fmt_duration((n - self._per) * 60 / self._per)} min."
        self.timing.setText(f"Lizenz: {self._lic}.{timing}" + (
            " Nach einem Upload wartet die Firebridge einige Minuten auf das Ergebnis." if up else "")
            + " Die Verbindung geht nur zu www.virustotal.com und wird danach getrennt.")
        self.ok.setEnabled(n > 0 and (not up or self.confirm.isChecked()))
        word = "Datei" if n == 1 else "Dateien"
        self.ok.setText((f"{fmt_int(n)} {word} abfragen und ggf. hochladen" if up else f"{fmt_int(n)} {word} abfragen")
                        if n else "Abfragen")
        self.ok.setProperty("kind", "danger" if up else "primary")
        repolish(self.ok)


class InfoDialog(QDialog):
    """Versions- und Build-Angaben von Oberfläche und Dienst, Link zum Git-Repository."""

    def __init__(self, parent: QWidget, service: dict | None):
        super().__init__(parent)
        from .. import build
        self.setWindowTitle("Über die Firebridge")
        self.setMinimumWidth(460)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(22, 20, 22, 18)
        lay.setSpacing(10)
        lay.addWidget(label("Firebridge", "bannerTitle"))
        lay.addWidget(label("Prüfstation für USB-Sticks und Wechseldatenträger.", None, wrap=True))
        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(4)
        rows = [("Oberfläche", build.info())]
        if service:
            rows.append(("Dienst", service))
        for r, (name, d) in enumerate(rows):
            grid.addWidget(label(name, "small"), r, 0)
            val = label(build.label(d))
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            grid.addWidget(val, r, 1)
        if service and (service.get("build"), service.get("commit")) != (build.info()["build"],
                                                                         build.info()["commit"]):
            hint = label("Dienst und Oberfläche sind verschieden alt: sudo systemctl restart firebridged", None,
                         wrap=True)
            hint.setStyleSheet(f"color: {C['warn']}; font-weight: 600;")
            grid.addWidget(hint, len(rows), 0, 1, 2)
        lay.addLayout(grid)
        if KIOSK:
            link = label(f"Quellcode: {build.REPO_URL}")
            link.setTextInteractionFlags(Qt.TextSelectableByMouse)
        else:
            link = label(f"Quellcode: <a href='{build.REPO_URL}'>{build.REPO_URL.split('://', 1)[1]}</a>")
            link.setOpenExternalLinks(True)
            link.setTextInteractionFlags(Qt.TextBrowserInteraction)
        lay.addWidget(link)
        act = QHBoxLayout()
        copy = button("Link kopieren")
        copy.clicked.connect(lambda: (QGuiApplication.clipboard().setText(build.REPO_URL),
                                      copy.setText("Kopiert")))
        open_ = button("Repository öffnen")
        open_.clicked.connect(self._open)
        close = button("Schließen", "primary")
        close.setDefault(True)
        close.clicked.connect(self.accept)
        act.addWidget(copy)
        act.addStretch()
        if not KIOSK:
            act.addWidget(open_)
        act.addWidget(close)
        lay.addLayout(act)

    def _open(self) -> None:
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        from .. import build
        QDesktopServices.openUrl(QUrl(build.REPO_URL))


class AdminDialog(QDialog):
    """Admin-Passwort eingeben (Anmelden) oder neu festlegen (set=True)."""

    def __init__(self, parent: QWidget, set_new: bool = False, message: str = "", error: str = ""):
        super().__init__(parent)
        self.set_new = set_new
        self.setWindowTitle("Admin-Passwort festlegen" if set_new else "Admin-Anmeldung")
        self.setMinimumWidth(440)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(22, 20, 22, 18)
        lay.setSpacing(10)
        lay.addWidget(label("Admin-Passwort festlegen" if set_new else "Admin-Passwort nötig", "bannerTitle"))
        text = message or ("Einstellungen, Freigaben und Verlauf löschen sind mit diesem Passwort geschützt. "
                           f"Mindestens {6} Zeichen." if set_new else
                           "Diese Aktion ist dem Admin vorbehalten. Die Anmeldung gilt 10 Minuten.")
        lay.addWidget(label(text, None, wrap=True))
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        self.pw.setPlaceholderText("Neues Passwort" if set_new else "Passwort")
        lay.addWidget(self.pw)
        self.pw2 = QLineEdit()
        self.pw2.setEchoMode(QLineEdit.Password)
        self.pw2.setPlaceholderText("Wiederholen")
        self.pw2.setVisible(set_new)
        lay.addWidget(self.pw2)
        self.err = label(error, None, wrap=True)
        self.err.setStyleSheet(f"color: {C['bad']}; font-weight: 600;")
        self.err.setVisible(bool(error))
        lay.addWidget(self.err)
        act = QHBoxLayout()
        act.addStretch()
        cancel = button("Abbrechen")
        ok = button("Festlegen" if set_new else "Anmelden", "primary")
        ok.setDefault(True)
        cancel.clicked.connect(self.reject)
        ok.clicked.connect(self._ok)
        self.pw.returnPressed.connect(self._ok if not set_new else self.pw2.setFocus)
        self.pw2.returnPressed.connect(self._ok)
        act.addWidget(cancel)
        act.addWidget(ok)
        lay.addLayout(act)
        self.pw.setFocus()

    def _ok(self) -> None:
        if self.set_new:
            if len(self.pw.text()) < 6:
                return self._error("Mindestens 6 Zeichen.")
            if self.pw.text() != self.pw2.text():
                return self._error("Die beiden Eingaben sind verschieden.")
        elif not self.pw.text():
            return
        self.accept()

    def _error(self, text: str) -> None:
        self.err.setText(text)
        self.err.show()

    def password(self) -> str:
        return self.pw.text()


class ReportDialog(QDialog):
    def __init__(self, parent: QWidget, report: dict):
        super().__init__(parent)
        self.setWindowTitle(f"Prüfbericht {report.get('id', '')}")
        fit_to_screen(self, 980, 640)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 18)
        dev = report.get("device") or {}
        eng = report.get("engine") or {}
        c = report.get("counts") or {}
        head = label(f"<b>{dev.get('display_name', '?')}</b> ({dev.get('vendor_id')}:{dev.get('product_id')}, "
                     f"Serien-Nr. {dev.get('serial') or '—'})<br>"
                     f"Geprüft {fmt_when(report.get('started'))} auf {report.get('station', '')} mit "
                     f"{eng.get('engine', '')} daily {eng.get('db_version', '')}<br>"
                     f"Ergebnis: <b>{report.get('verdict', '')}</b> · {fmt_int(c.get('files'))} Dateien, "
                     f"{fmt_int(c.get('infected'))} infiziert, {fmt_int(c.get('suspicious'))} auffällig"
                     f" ({fmt_int(c.get('released'))} freigegeben), {fmt_int(c.get('errors'))} nicht lesbar"
                     + _analysis_line(report.get("analysis"))
                     + _vt_line(report.get("virustotal"))
                     + _transfer_line(report.get("transfer"))
                     + _release_line(report.get("releases")),
                     wrap=True)
        lay.addWidget(head)
        self.filter = QComboBox()
        self.filter.addItems(["Alle Dateien", "Nur Funde, Auffälliges und Fehler"])
        self.filter.currentIndexChanged.connect(self._fill)
        lay.addWidget(self.filter, 0, Qt.AlignLeft)
        self.table = make_table(["Datei", "Größe", "Status", "Details", "VirusTotal", "SHA-256"])
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.Stretch)
        for i in (1, 2, 4):
            h.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(3, QHeaderView.Interactive)
        h.setSectionResizeMode(5, QHeaderView.Interactive)
        self.table.setColumnWidth(3, 300 if report.get("virustotal") else 380)
        self.table.setColumnWidth(5, 160)
        self.table.setColumnHidden(4, not report.get("virustotal"))
        self.table.cellDoubleClicked.connect(
            lambda r, c: c == 4 and 0 <= r < len(self._rows) and open_vt_link(self._rows[r].get("vt")))
        lay.addWidget(self.table, 1)
        self.files = report.get("files") or []
        close = button("Schließen")
        close.clicked.connect(self.accept)
        lay.addWidget(close, 0, Qt.AlignRight)
        self._fill()

    def _fill(self) -> None:
        only = self.filter.currentIndex() == 1
        rows = [f for f in self.files
                if not only or f.get("status") in ("infected", "error", "suspicious") or f.get("hits")
                or vt_mod.rate(f.get("vt") or {}, 1) in ("hit", "warn")]
        self._rows = rows
        t = self.table
        t.setRowCount(len(rows))
        for r, f in enumerate(rows):
            text, color = finding_stage(f)
            detail = f.get("detail", "")
            allowed = [h.get("detail", "") for h in f.get("hits", []) if h.get("action") == "zulassen"]
            if allowed and f.get("status") == "clean":
                text, color = "sauber (zugelassen)", C["ok"]
                detail = "; ".join(allowed)
            if f.get("notes"):
                detail = "; ".join([detail] + f["notes"]) if detail else "; ".join(f["notes"])
            t.setItem(r, 0, cell(f.get("path", ""), mono_font=True))
            t.setItem(r, 1, cell(fmt_bytes(f.get("size")), mono_font=True))
            t.setItem(r, 2, cell(text, color, bold=True))
            item = cell(detail)
            item.setToolTip(detail)
            t.setItem(r, 3, item)
            t.setItem(r, 4, vt_cell(f.get("vt")))
            t.setItem(r, 5, cell(f.get("sha256", ""), C["muted"], mono_font=True))


# ---------------------------------------------------------------------------
# Verlauf und Quarantäne


def fmt_date(iso: str | None) -> str:
    """Vollständiges Datum für lange Listen (fmt_when kürzt auf „heute“/„gestern“)."""
    if not iso:
        return "—"
    try:
        t = dt.datetime.fromisoformat(iso).astimezone()
    except ValueError:
        return iso
    return f"{t:%d.%m.%Y %H:%M}"


def search_box(placeholder: str) -> QLineEdit:
    w = QLineEdit()
    w.setPlaceholderText(placeholder)
    w.setClearButtonEnabled(True)
    return w


def _matches(needle: str, *fields) -> bool:
    needle = needle.strip().lower()
    return not needle or any(needle in str(f or "").lower() for f in fields)


HISTORY_FILTERS = [
    ("Alle Einträge", None),
    ("Prüfungen", {"sauber", "auffällig", "infiziert", "unvollständig", "abgebrochen"}),
    ("Sauber", {"sauber"}),
    ("Auffällig", {"auffällig"}),
    ("Infiziert", {"infiziert"}),
    ("Übertragungen", {"übertragen", "teilweise übertragen", "Übertragung fehlgeschlagen",
                       "Übertragung abgebrochen"}),
    ("USB-Ereignisse", {"BadUSB", "Netzwerkadapter gesperrt", "Eingabegerät gesperrt", "USB-Gerät gesperrt",
                        "Tastatur freigegeben", "USB-Gerät freigegeben"}),
]


class HistoryPage(QWidget):
    """Alle Prüfungen, Übertragungen und USB-Ereignisse, mit Filter und Suche."""

    LIMIT = 2000

    def __init__(self, win: "MainWindow"):
        super().__init__()
        self.win = win
        self.setObjectName("page")
        self._rows: list[dict] = []
        self._shown: list[dict] = []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 22)
        lay.setSpacing(16)
        lay.addWidget(label("Verlauf", "h1"))

        card = Card()
        bar = QHBoxLayout()
        bar.setSpacing(10)
        self.search = search_box("Suchen: Gerät, Seriennummer, USB-ID …")
        self.search.textChanged.connect(self._fill)
        self.filter = QComboBox()
        for text, _ in HISTORY_FILTERS:
            self.filter.addItem(text)
        self.filter.currentIndexChanged.connect(self._fill)
        self.btn_reload = button("Aktualisieren")
        self.btn_reload.clicked.connect(self.reload)
        self.btn_clear = button("Verlauf löschen …", "danger")
        self.btn_clear.clicked.connect(self._clear)
        bar.addWidget(self.search, 1)
        bar.addWidget(self.filter)
        bar.addWidget(self.btn_reload)
        bar.addWidget(self.btn_clear)
        card.lay.addLayout(bar)
        self.count = label("", "small")
        card.lay.addWidget(self.count)
        self.table = make_table(["Zeit", "Gerät", "USB-ID", "Serien-Nr.", "Dateien", "Ergebnis", "Bericht"])
        h = self.table.horizontalHeader()
        for i in range(7):
            h.setSectionResizeMode(i, QHeaderView.Stretch if i == 1 else QHeaderView.ResizeToContents)
        self.table.setMinimumHeight(240)
        self.table.cellDoubleClicked.connect(self._open_report)
        card.lay.addWidget(self.table, 1)
        lay.addWidget(card, 1)
        win.backend.historyFull.connect(self.set_rows)

    def reload(self) -> None:
        self.count.setText("Wird geladen …")
        self.win.backend.get_full_history(self.LIMIT)

    def set_rows(self, rows: list[dict]) -> None:
        self._rows = rows
        self._fill()

    def _fill(self, *_):
        allowed = HISTORY_FILTERS[self.filter.currentIndex()][1]
        needle = self.search.text()
        rows = [e for e in self._rows
                if (allowed is None or e.get("result") in allowed)
                and _matches(needle, e.get("device"), e.get("serial"), e.get("usb_id"), e.get("result"))]
        self._shown = rows
        t = self.table
        t.setRowCount(len(rows))
        for r, e in enumerate(rows):
            res = e.get("result", "")
            text = res
            if res == "infiziert" and e.get("infected"):
                text = f"{e['infected']} infiziert"
            elif res == "auffällig" and e.get("suspicious"):
                text = f"{e['suspicious']} auffällig"
            t.setItem(r, 0, cell(fmt_date(e.get("time")), mono_font=True))
            t.setItem(r, 1, cell(e.get("device", "?")))
            t.setItem(r, 2, cell(e.get("usb_id", ""), mono_font=True))
            t.setItem(r, 3, cell(e.get("serial") or "—", mono_font=True))
            t.setItem(r, 4, cell(fmt_int(e.get("files")), mono_font=True))
            t.setItem(r, 5, cell(text, TONES[RESULT_TONES.get(res, "info")][0], bold=True))
            t.setItem(r, 6, cell("öffnen (Doppelklick)" if e.get("id") else "—",
                                 C["accent"] if e.get("id") else C["muted"]))
        if self._rows and len(rows) != len(self._rows):
            self.count.setText(f"{fmt_int(len(rows))} von {fmt_int(len(self._rows))} Einträgen")
        elif self._rows:
            more = " (die neuesten)" if len(self._rows) >= self.LIMIT else ""
            self.count.setText(f"{fmt_int(len(rows))} Einträge{more}")
        else:
            self.count.setText("Noch keine Einträge")

    def _open_report(self, row: int, _col: int) -> None:
        if 0 <= row < len(self._shown) and self._shown[row].get("id"):
            self.win.backend.get_report(self._shown[row]["id"])

    def _clear(self) -> None:
        box = QMessageBox(QMessageBox.Warning, "Verlauf löschen",
                          f"Wirklich den ganzen Verlauf löschen ({fmt_int(len(self._rows))} Einträge)?",
                          QMessageBox.Cancel, self)
        box.setInformativeText("Gelöscht werden alle Einträge, alle Prüfberichte und damit auch die Liste auf der "
                               "Seite Quarantäne. Das lässt sich nicht rückgängig machen.\n\nDas Freigabe-Protokoll "
                               "bleibt erhalten und vermerkt, wer den Verlauf gelöscht hat.")
        ok = box.addButton("Endgültig löschen", QMessageBox.DestructiveRole)
        box.setDefaultButton(QMessageBox.Cancel)
        box.exec()
        if box.clickedButton() is ok:
            self.count.setText("Wird gelöscht …")
            self.win.backend.clear_history()

    def update_from(self, st: dict) -> None:
        allowed = bool((st.get("actions") or {}).get("clear_history"))
        self.btn_clear.setEnabled(allowed)
        self.btn_clear.setToolTip("" if allowed else "Erst den Datenträger auswerfen: solange ein Ergebnis offen "
                                  "ist oder eine Prüfung läuft, wird dessen Bericht noch gebraucht")


QUARANTINE_FILTERS = [
    ("Alle", None),
    ("Infiziert", {"infiziert"}),
    ("Gesperrt (Richtlinie)", {"gesperrt"}),
    ("Nicht freigegeben", {"nicht freigegeben"}),
    ("Freigegeben", {"freigegeben"}),
]
QUARANTINE_TONES = {"infiziert": "bad", "gesperrt": "bad", "nicht freigegeben": "warn", "freigegeben": "info"}
AUDIT_LABELS = {"datei": "Datei", "usb": "USB-Gerät", "uebertragung": "Übertragung", "virustotal": "VirusTotal",
                "loeschen": "Verlauf gelöscht"}


class QuarantinePage(QWidget):
    """Was die Prüfungen gesperrt haben und wer was freigegeben hat.

    Die Dateien bleiben auf dem Datenträger; die Firebridge legt keine Kopie von Schadsoftware an.
    """

    def __init__(self, win: "MainWindow"):
        super().__init__()
        self.win = win
        self.setObjectName("page")
        self._rows: list[dict] = []
        self._shown: list[dict] = []
        self._audit: list[dict] = []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 22)
        lay.setSpacing(16)
        head = QHBoxLayout()
        head.addWidget(label("Quarantäne", "h1"), 1)
        self.btn_reload = button("Aktualisieren")
        self.btn_reload.clicked.connect(self.reload)
        head.addWidget(self.btn_reload)
        lay.addLayout(head)
        lay.addWidget(label("Alle Dateien, die eine Prüfung gesperrt hat, und die auffälligen, die jemand "
                            "freigegeben hat. Die Dateien selbst bleiben auf dem Datenträger: Die Firebridge "
                            "kopiert keine Schadsoftware auf diesen Rechner. Die SHA-256-Prüfsumme zum Wiedererkennen "
                            "zeigt der Tooltip über dem Dateinamen.", "hint", wrap=True))

        card = Card("Gesperrte und freigegebene Dateien")
        bar = QHBoxLayout()
        bar.setSpacing(10)
        self.search = search_box("Suchen: Datei, Grund, Gerät, Prüfsumme …")
        self.search.textChanged.connect(self._fill)
        self.filter = QComboBox()
        for text, _ in QUARANTINE_FILTERS:
            self.filter.addItem(text)
        self.filter.currentIndexChanged.connect(self._fill)
        bar.addWidget(self.search, 1)
        bar.addWidget(self.filter)
        card.lay.addLayout(bar)
        self.count = label("", "small")
        card.lay.addWidget(self.count)
        self.table = make_table(["Zeit", "Gerät", "Datei", "Grund", "Stufe", "Freigegeben"])
        h = self.table.horizontalHeader()
        for i in range(6):
            h.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.Interactive)
        h.setSectionResizeMode(2, QHeaderView.Stretch)
        h.setSectionResizeMode(3, QHeaderView.Interactive)
        h.resizeSection(1, 150)
        h.resizeSection(3, 200)
        self.table.setMinimumHeight(220)
        self.table.cellDoubleClicked.connect(self._open_report)
        self.table.setToolTip("Doppelklick: Prüfbericht öffnen. Die SHA-256-Prüfsumme steht im Tooltip der Datei.")
        card.lay.addWidget(self.table, 1)
        lay.addWidget(card, 3)

        acard = Card("Freigabe-Protokoll: wer hat was freigegeben")
        self.audit_table = make_table(["Zeit", "Wer", "Art", "Was", "Gerät"])  # auch: wer den Verlauf gelöscht hat
        h = self.audit_table.horizontalHeader()
        for i in range(5):
            h.setSectionResizeMode(i, QHeaderView.Stretch if i == 3 else QHeaderView.ResizeToContents)
        self.audit_table.setMinimumHeight(160)
        acard.lay.addWidget(self.audit_table, 1)
        acard.lay.addWidget(label("Der Name kommt vom Betriebssystem (angemeldeter Benutzer, der in der "
                                  "Oberfläche geklickt hat). Das Protokoll wird nur ergänzt, nie geändert: "
                                  "/var/lib/firebridge/audit.jsonl", "small", wrap=True))
        lay.addWidget(acard, 2)
        win.backend.quarantineReady.connect(self.set_rows)
        win.backend.auditReady.connect(self.set_audit)

    def reload(self) -> None:
        self.count.setText("Wird geladen …")
        self.win.backend.get_quarantine()
        self.win.backend.get_audit()

    def set_rows(self, rows: list[dict]) -> None:
        self._rows = rows
        self._fill()

    def _fill(self, *_):
        allowed = QUARANTINE_FILTERS[self.filter.currentIndex()][1]
        needle = self.search.text()
        rows = [q for q in self._rows
                if (allowed is None or q.get("state") in allowed)
                and _matches(needle, q.get("path"), q.get("reason"), q.get("device"), q.get("serial"),
                             q.get("sha256"), q.get("released_by"))]
        self._shown = rows
        t = self.table
        t.setRowCount(len(rows))
        for r, q in enumerate(rows):
            state = q.get("state", "")
            sha = q.get("sha256") or ""
            t.setItem(r, 0, cell(fmt_when(q.get("time")), mono_font=True))
            t.item(r, 0).setToolTip(fmt_date(q.get("time")))
            t.setItem(r, 1, cell(q.get("device", "?")))
            folder, _, name = q.get("path", "").rpartition("/")
            # Dateiname zuerst, damit er auch in einer schmalen Spalte zu sehen ist
            t.setItem(r, 2, cell(f"{name}  ·  {folder}" if folder else name, mono_font=True))
            t.setItem(r, 3, cell(q.get("reason", "")))
            t.setItem(r, 4, cell(state, TONES[QUARANTINE_TONES.get(state, "info")][0], bold=True))
            by = q.get("released_by") or ""
            when = fmt_date(q.get("released")) if q.get("released") else ""
            t.setItem(r, 5, cell(f"{by} · {fmt_when(q.get('released'))}" if by and when else by or when or "—"))
            t.item(r, 5).setToolTip(f"{by} · {when}" if by else when)
            for c in (1, 3):
                t.item(r, c).setToolTip(t.item(r, c).text())
            t.item(r, 2).setToolTip(f"{q.get('path', '')}\nSHA-256: {sha or '—'}\n{fmt_bytes(q.get('size'))}")
        n_inf = sum(1 for q in self._rows if q.get("state") == "infiziert")
        if self._rows:
            shown = f"{fmt_int(len(rows))} von {fmt_int(len(self._rows))}" if len(rows) != len(self._rows) \
                else fmt_int(len(rows))
            self.count.setText(f"{shown} Dateien · davon {fmt_int(n_inf)} infiziert insgesamt")
        else:
            self.count.setText("Bisher wurde nichts gesperrt.")

    def set_audit(self, rows: list[dict]) -> None:
        self._audit = rows
        t = self.audit_table
        t.setRowCount(len(rows))
        for r, a in enumerate(rows):
            t.setItem(r, 0, cell(fmt_date(a.get("time")), mono_font=True))
            t.setItem(r, 1, cell(a.get("by") or "unbekannt", bold=True))
            t.setItem(r, 2, cell(AUDIT_LABELS.get(a.get("action"), a.get("action", ""))))
            t.setItem(r, 3, cell(a.get("text", "")))
            t.item(r, 3).setToolTip(a.get("text", ""))
            t.setItem(r, 4, cell(a.get("device") or "—"))
        if not rows:
            t.setRowCount(1)
            t.setItem(0, 3, cell("Noch nichts freigegeben", C["muted"]))

    def _open_report(self, row: int, _col: int) -> None:
        if 0 <= row < len(self._shown) and self._shown[row].get("report"):
            self.win.backend.get_report(self._shown[row]["report"])

    def update_from(self, st: dict) -> None:
        pass


# ---------------------------------------------------------------------------
# Hauptfenster


class MainWindow(QMainWindow):
    def __init__(self, backend: Backend, demo: bool = False, zoom_wanted: float | str = zoom.AUTO,
                 zoom_source: str = "config", kiosk: bool = False):
        super().__init__()
        self.backend = backend
        self.kiosk = kiosk
        self._may_close = not kiosk
        if kiosk:
            self.setWindowFlag(Qt.FramelessWindowHint)
        self.zoom_wanted = zoom_wanted
        self.zoom_source = zoom_source
        self.status: dict = {}
        self.share_cfg: dict = {}
        self.forced_page: str | None = None
        self._last_state = ""
        self.setWindowTitle("Firebridge" + (" — Demo mit Beispieldaten" if demo else ""))
        self.setWindowIcon(QIcon(usb_pixmap(C["accent"], 64)))
        # Bei großer Skalierung passt 1180 × 820 nicht auf jeden Bildschirm; die Seiten rollen dann
        fit_to_screen(self, 1180, 820)
        self.setMinimumSize(760, 520)

        root = QWidget()
        root.setObjectName("root")
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        self.setCentralWidget(root)

        side = QFrame()
        side.setObjectName("side")
        side.setFixedWidth(210)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(12, 18, 12, 14)
        sl.setSpacing(2)
        brand = QLabel("Firebridge")
        brand.setObjectName("brand")
        self.brand_sub = QLabel("PRÜFSTATION")
        self.brand_sub.setObjectName("brandSub")
        sl.addWidget(brand)
        sl.addWidget(self.brand_sub)
        sl.addSpacing(18)
        self.nav: dict[str, QPushButton] = {}
        for key, text, tip in (("start", "Start", ""), ("history", "Verlauf", ""),
                               ("quarantine", "Quarantäne", ""),
                               ("settings", "Einstellungen", "")):
            b = QPushButton(text)
            b.setProperty("role", "nav")
            b.setCheckable(True)
            b.setCursor(Qt.PointingHandCursor)
            if tip:
                b.setEnabled(False)
                b.setToolTip(f"Kommt in {tip}")
            sl.addWidget(b)
            self.nav[key] = b
        self.nav["start"].setChecked(True)
        self.nav["start"].clicked.connect(self.show_state_page)
        self.nav["settings"].clicked.connect(self._open_settings)
        self.nav["history"].clicked.connect(lambda: self._open_list("history"))
        self.nav["quarantine"].clicked.connect(lambda: self._open_list("quarantine"))
        sl.addSpacing(10)
        self.btn_admin = QPushButton("🔒  Admin anmelden")
        self.btn_admin.setProperty("role", "nav")
        self.btn_admin.setCursor(Qt.PointingHandCursor)
        self.btn_admin.clicked.connect(self._admin_clicked)
        sl.addWidget(self.btn_admin)
        # Restzeit der Admin-Anmeldung unter dem Knopf (im Knopf würde sie bei großer Schrift abgeschnitten)
        self.admin_left = QLabel("")
        self.admin_left.setObjectName("adminLeft")
        self.admin_left.hide()
        sl.addWidget(self.admin_left)
        if kiosk:
            self.btn_kiosk = QPushButton("⏻  Kiosk verlassen")
            self.btn_kiosk.setProperty("role", "nav")
            self.btn_kiosk.setCursor(Qt.PointingHandCursor)
            self.btn_kiosk.setToolTip("Oberfläche beenden und zur Anmeldung zurück (nur mit Admin-Passwort)")
            self.btn_kiosk.clicked.connect(lambda: self.backend.admin_check("kiosk"))
            sl.addWidget(self.btn_kiosk)
            backend.adminConfirmed.connect(self._admin_confirmed)
        sl.addStretch()
        foot = QFrame()
        foot.setObjectName("sideFoot")
        fl = QVBoxLayout(foot)
        fl.setContentsMargins(4, 10, 4, 0)
        fl.setSpacing(2)
        self.st_sig = StatusRow("Signaturen")
        self.st_smb = StatusRow("SMB getrennt")
        self.st_srv = StatusRow("Dienst")
        self.st_ro = StatusRow("Kein Automount")
        self.st_usb = StatusRow("USB-Schutz")
        self.st_vt = StatusRow("VirusTotal aus")
        for w in (self.st_sig, self.st_smb, self.st_usb, self.st_vt, self.st_srv, self.st_ro):
            fl.addWidget(w)
        self.st_smb.set("off", "SMB getrennt")
        self.st_ro.set("ok", "Nur read-only")
        from .. import build
        brow = QHBoxLayout()
        brow.setContentsMargins(0, 6, 0, 0)
        brow.setSpacing(6)
        self.build_label = QLabel(build.label())
        self.build_label.setObjectName("buildLabel")
        self.build_label.setToolTip("Version und Build der Oberfläche")
        info = QPushButton("ⓘ")
        info.setObjectName("infoButton")
        info.setCursor(Qt.PointingHandCursor)
        info.setToolTip("Über die Firebridge, Link zum Git-Repository")
        info.clicked.connect(self._show_info)
        brow.addWidget(self.build_label, 1)
        brow.addWidget(info)
        fl.addLayout(brow)
        sl.addWidget(foot)
        if demo:
            d = QLabel("DEMO · Beispieldaten")
            d.setStyleSheet(f"color: {C['warn']}; font-size: 11px; padding-top: 8px;")
            sl.addWidget(d)
        h.addWidget(side)

        self.stack = QStackedWidget()
        self.pages = {"start": StartPage(self), "scan": ScanPage(self), "result": ResultPage(self),
                      "transfer": TransferPage(self), "virustotal": VtPage(self), "settings": SettingsPage(self),
                      "history": HistoryPage(self), "quarantine": QuarantinePage(self)}
        # Einstellungen rollen schon selbst
        self.holders = {k: p if k == "settings" else scrollable(p) for k, p in self.pages.items()}
        for p in self.holders.values():
            self.stack.addWidget(p)
        h.addWidget(self.stack, 1)
        self._init_zoom()

        backend.statusChanged.connect(self.on_status)
        backend.progressChanged.connect(self.pages["scan"].set_progress)
        backend.transferChanged.connect(self.pages["transfer"].set_progress)
        backend.logLine.connect(self.pages["scan"].add_log)
        backend.logLine.connect(self.pages["transfer"].add_log)
        backend.logLine.connect(self.pages["virustotal"].add_log)
        backend.vtChanged.connect(self.pages["virustotal"].set_progress)
        backend.historyChanged.connect(self.pages["start"].set_history)
        backend.reportReady.connect(lambda r: ReportDialog(self, r).exec())
        backend.connectionChanged.connect(self.on_connection)
        backend.shareConfig.connect(self._on_share_cfg)
        self._share_requested = False
        self.alert_dialogs: dict[str, UsbAlertDialog] = {}
        backend.error.connect(self._on_error)
        self.admin: dict = {}
        self._admin_retry = None
        backend.adminChanged.connect(self._on_admin)
        backend.adminRequired.connect(self._ask_admin)
        backend.adminLoginFailed.connect(self._admin_failed)
        self.on_connection(False, "Verbinde mit dem Dienst …")

    # -- Größe der Oberfläche

    def _init_zoom(self) -> None:
        self._zoom_pending: float | str | None = None
        self._zoom_timer = QTimer(self)
        self._zoom_timer.setSingleShot(True)
        self._zoom_timer.setInterval(900)  # mehrere Tastendrücke sammeln, dann einmal neu starten
        self._zoom_timer.timeout.connect(self._zoom_restart)
        self.zoom_toast = QLabel(self)
        self.zoom_toast.setObjectName("toast")
        self.zoom_toast.hide()
        for keys, step in ((QKeySequence.ZoomIn, 1), ("Ctrl+=", 1), (QKeySequence.ZoomOut, -1), ("Ctrl+0", 0)):
            sc = QShortcut(QKeySequence(keys), self)
            sc.setContext(Qt.ApplicationShortcut)
            sc.activated.connect(lambda step=step: self.zoom_step(step))

    def zoom_factor(self) -> float:
        """Faktor, mit dem die Oberfläche gerade gezeichnet wird."""
        return zoom.current_factor()

    def zoom_locked(self) -> str:
        """Leer, wenn die Größe hier einstellbar ist, sonst der Grund."""
        if self.zoom_source == "cli":
            return "Fest vorgegeben beim Start (--zoom)."
        if self.zoom_source == "env":
            return "Fest vorgegeben über die Umgebungsvariable FIREBRIDGE_ZOOM."
        return ""

    def zoom_step(self, step: int) -> None:
        """Strg + / Strg − / Strg 0 (0 = zurück auf Automatisch)."""
        if self.zoom_locked():
            self._toast(self.zoom_locked())
            return
        if step == 0:
            self.set_zoom(zoom.AUTO)
            return
        base = self._zoom_pending if isinstance(self._zoom_pending, float) else self.zoom_factor()
        if step > 0:
            new = next((f for f in zoom.STEPS if f > base + 0.01), zoom.STEPS[-1])
        else:
            new = next((f for f in reversed(zoom.STEPS) if f < base - 0.01), zoom.STEPS[0])
        self.set_zoom(new)

    def set_zoom(self, value: float | str, delay: bool = True) -> None:
        if value == self.zoom_wanted and self._zoom_pending is None:
            self._toast(f"Größe: {zoom.label(value)}")
            return
        self._zoom_pending = value
        self._toast(f"Größe: {zoom.label(value)} · Oberfläche startet gleich neu …")
        self._zoom_timer.start() if delay else self._zoom_restart()

    def _zoom_restart(self) -> None:
        value = self._zoom_pending
        if value is None:
            return
        try:
            zoom.save(value)
        except OSError as e:
            QMessageBox.warning(self, "Firebridge", f"Größe konnte nicht gespeichert werden: {e}")
            self._zoom_pending = None
            return
        zoom.restart(value)

    def _toast(self, text: str) -> None:
        t = self.zoom_toast
        t.setText(text)
        t.adjustSize()
        t.move((self.width() - t.width()) // 2, self.height() - t.height() - 40)
        t.raise_()
        t.show()
        QTimer.singleShot(2500, lambda: t.text() == text and t.hide())

    # -- Kiosk

    def _admin_confirmed(self, purpose: str) -> None:
        if purpose != "kiosk":
            return
        box = QMessageBox(QMessageBox.Question, "Kiosk verlassen",
                          "Die Firebridge-Oberfläche wird beendet, danach erscheint die Anmeldung. Ein laufender "
                          "Dienst prüft und überträgt weiter. Zurück in den Kiosk geht es mit einem Neustart.",
                          QMessageBox.Cancel, self)
        ok = box.addButton("Kiosk verlassen", QMessageBox.AcceptRole)
        box.setDefaultButton(QMessageBox.Cancel)
        box.exec()
        if box.clickedButton() is ok:
            self._may_close = True
            QApplication.exit(0)

    def closeEvent(self, event) -> None:
        if not self._may_close:
            event.ignore()      # Kiosk: Alt+F4 o. Ä. schließt nicht
            return
        super().closeEvent(event)

    def cover_screen(self) -> None:
        screen = self.screen() or QGuiApplication.primaryScreen()
        if screen is not None:
            self.setGeometry(screen.geometry())

    def _show_info(self) -> None:
        InfoDialog(self, self.status.get("build")).exec()

    # -- Admin

    def _on_admin(self, a: dict) -> None:
        self.admin = a
        left = int(a.get("active_seconds") or 0)
        if a.get("root"):
            text = "Admin (root)"
        elif left > 0:
            text = "🔓  Admin abmelden"
        elif not a.get("has_password"):
            text = "🔒  Admin-Passwort festlegen"
        else:
            text = "🔒  Admin anmelden"
        self.btn_admin.setText(text)
        if left > 0 and not a.get("root"):
            mins = max(1, round(left / 60))
            self.admin_left.setText(f"noch {mins} min")
            self.admin_left.show()
        else:
            self.admin_left.hide()
        self.btn_admin.setToolTip("Einstellungen, Freigaben und Verlauf löschen sind dem Admin vorbehalten. "
                                  "Die Anmeldung gilt 10 Minuten und verlängert sich mit jeder solchen Aktion.")
        self.pages["settings"].update_admin(a)

    def is_admin(self) -> bool:
        return bool(self.admin.get("root") or (self.admin.get("active_seconds") or 0) > 0)

    def _admin_clicked(self) -> None:
        if self.is_admin() and not self.admin.get("root"):
            self.backend.admin_logout()
        elif not self.is_admin():
            self._ask_admin(None, "")

    def _ask_admin(self, retry, message: str, error: str = "") -> None:
        """Passwort abfragen; danach die Aktion, die es verlangt hat, nochmal ausführen."""
        self._admin_retry = retry
        if self.admin and not self.admin.get("has_password"):
            dlg = AdminDialog(self, set_new=True, message="Für diese Aktion braucht es ein Admin-Passwort. "
                              "Es ist noch keins festgelegt; lege jetzt eins fest." if retry else "")
            if dlg.exec() == QDialog.Accepted:
                self.backend.admin_set_password(dlg.password(), then=retry)
            return
        dlg = AdminDialog(self, message="" if not retry else "Diese Aktion ist dem Admin vorbehalten. "
                          "Die Anmeldung gilt 10 Minuten.", error=error)
        if dlg.exec() == QDialog.Accepted:
            self.backend.admin_login(dlg.password(), then=retry)

    def _admin_failed(self, message: str) -> None:
        self._ask_admin(self._admin_retry, "", error=message)

    def change_admin_password(self) -> None:
        dlg = AdminDialog(self, set_new=True, message="Neues Admin-Passwort, ersetzt das bisherige.")
        if dlg.exec() == QDialog.Accepted:
            self.backend.admin_set_password(dlg.password())

    def _on_error(self, msg: str) -> None:
        self.pages["start"].clear_starting()
        QMessageBox.warning(self, "Firebridge", msg)

    def _on_share_cfg(self, cfg: dict) -> None:
        self.share_cfg = cfg
        self._share_requested = False

    def show_page(self, key: str) -> None:
        self.forced_page = key
        self._set_page(key)

    def _set_page(self, key: str) -> None:
        self.stack.setCurrentWidget(self.holders[key])
        for name, b in self.nav.items():
            b.setChecked(name == (key if key in ("settings", "history", "quarantine") else "start"))

    def _state_page(self) -> str:
        return {"SCAN": "scan", "ERGEBNIS": "result", "UEBERTRAGUNG": "transfer",
                "UEBERTRAGEN": "transfer", "VIRUSTOTAL": "virustotal"}.get(self.status.get("state", ""), "start")

    def show_state_page(self) -> None:
        """Ansicht zum aktuellen Zustand (Prüfung, Ergebnis, Übertragung oder Start)."""
        self.forced_page = None
        self._set_page(self._state_page())

    def _open_list(self, key: str) -> None:
        self.show_page(key)
        self.pages[key].reload()

    def _open_settings(self) -> None:
        self.show_page("settings")
        self.pages["settings"].banner.hide()
        self.backend.get_share()
        self.backend.get_virustotal()

    def open_vt_upload(self) -> None:
        dlg = VtUploadDialog(self, self.status)
        if dlg.exec() == QDialog.Accepted and dlg.selected():
            self.backend.vt_send(dlg.selected(), dlg.upload, dlg.upload and dlg.confirm.isChecked())

    def open_release(self) -> None:
        dlg = ReleaseDialog(self, self.status)
        if dlg.exec() == QDialog.Accepted:
            self.backend.release(dlg.selected())

    def confirm_transfer(self) -> None:
        dlg = TransferDialog(self, self.status, self.share_cfg.get("targets") or [])
        if dlg.exec() == QDialog.Accepted:
            self.backend.transfer(dlg.target_id(), dlg.selected_files())

    def on_connection(self, ok: bool, msg: str) -> None:
        self.st_srv.set("ok" if ok else "bad", "Dienst verbunden" if ok else "Dienst getrennt")
        start: StartPage = self.pages["start"]
        if not ok:
            for b in (start.btn_scan, start.btn_eject, start.btn_transfer):
                b.setEnabled(False)
            start.banner.show_msg("bad", "Keine Verbindung zum Prüfdienst",
                                  f"{msg}. Prüfen mit: systemctl status firebridged")
        elif self.status:
            start.update_from(self.status)

    def on_status(self, st: dict) -> None:
        self.status = st
        state = st.get("state", "")
        self.brand_sub.setText((st.get("station_name") or "Prüfstation").upper())
        eng = st.get("engine") or {}
        if not eng.get("available"):
            self.st_sig.set("bad", "Keine Signaturen")
        elif st.get("signatures_outdated"):
            self.st_sig.set("warn", "Signaturen veraltet")
        else:
            self.st_sig.set("ok", "Signaturen aktuell")
        smb = st.get("smb") or {}
        fw = smb.get("firewall") or {}
        if smb.get("connected"):
            self.st_smb.set("warn", "SMB verbunden")
        elif not fw.get("ok") and smb.get("configured"):
            self.st_smb.set("bad", "Netzwerk-Sperre fehlt")
        else:
            self.st_smb.set("off" if not fw.get("disabled") else "bad", "SMB getrennt")
        if smb.get("targets", 0) != len(self.share_cfg.get("targets") or []) and not self._share_requested:
            self._share_requested = True  # Zielliste nachladen (z. B. nach dem Verbinden)
            self.backend.get_share()
        self._update_usb(st.get("usb_guard") or {})
        vtc = st.get("virustotal") or {}
        if vtc:
            label_vt = f"VirusTotal: {vtc.get('mode_label', 'aus')}"
            self.st_vt.set("warn" if state == "VIRUSTOTAL" else ("ok" if vtc.get("ready") else "off"), label_vt)
            self.st_vt.setToolTip(vtc.get("message", ""))
        for key in ("start", "scan", "result", "transfer", "virustotal", "settings", "history"):
            self.pages[key].update_from(st)
        if state != self._last_state:
            if state == "SCAN":
                self.pages["scan"].set_log(st.get("log") or [])
            elif state == "UEBERTRAGUNG":
                self.pages["transfer"].set_log(st.get("log") or [])
            elif state == "VIRUSTOTAL":
                self.pages["virustotal"].set_log(st.get("log") or [])
            # Beim Zustandswechsel springt die Ansicht mit, außer der Benutzer ist in den Einstellungen
            # und es kommt nichts, was er sehen muss
            if self.forced_page not in ("settings", "history", "quarantine") or \
                    state in ("SCAN", "UEBERTRAGUNG", "VIRUSTOTAL", "BLOCKIERT"):
                self.forced_page = None
            elif self.forced_page in ("history", "quarantine"):
                self.pages[self.forced_page].reload()  # neue Einträge zeigen
            self._last_state = state
            self.backend.refresh_history()
        self._set_page(self.forced_page or self._state_page())


    def _update_usb(self, ug: dict) -> None:
        """Seitenleiste und Alarm-Dialoge für neue USB-Geräte."""
        mode = ug.get("mode")
        if mode == "usbguard" and ug.get("active"):
            self.st_usb.set("ok", "USBGuard aktiv")
        elif mode == "sysfs":
            self.st_usb.set("warn", "USB-Schutz eingeschränkt")
        elif mode:
            self.st_usb.set("bad", "USB-Schutz aus")
        self.st_usb.setToolTip(ug.get("message", ""))
        alerts = {a["id"]: a for a in ug.get("alerts") or []}
        for aid in list(self.alert_dialogs):
            if aid not in alerts:
                self.alert_dialogs.pop(aid).done(QDialog.Accepted)
        for aid, a in alerts.items():
            dlg = self.alert_dialogs.get(aid)
            if dlg is None:
                dlg = self.alert_dialogs[aid] = UsbAlertDialog(self, a)
                dlg.show()
                dlg.raise_()
                dlg.activateWindow()
                QApplication.alert(self)
            else:
                dlg.update_from(a)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Firebridge-Oberfläche")
    ap.add_argument("--demo", action="store_true", help="Beispieldaten statt echtem Dienst")
    ap.add_argument("--session-bus", action="store_true", help="Dienst auf dem Session-Bus (Entwicklung)")
    ap.add_argument("--fullscreen", action="store_true", help="Vollbild")
    ap.add_argument("--kiosk", action="store_true",
                    help="Kioskmodus: Vollbild ohne Rahmen, Beenden nur mit Admin-Passwort, kein Browser")
    ap.add_argument("--zoom", metavar="GRÖSSE",
                    help="Größe der Oberfläche: auto oder Prozent, z. B. 150 (überstimmt die Einstellung)")
    args, qt_args = ap.parse_known_args(argv)
    if args.zoom is not None and zoom.parse(args.zoom) is None:
        ap.error(f"--zoom {args.zoom}: erwartet auto oder einen Wert zwischen 50 und 400 (Prozent)")
    zoom_wanted, zoom_source = zoom.choose(args.zoom)
    zoom.apply_before_app(zoom_wanted)
    app = QApplication([sys.argv[0], *qt_args])
    detected = zoom.auto_detect(app, zoom_wanted)
    if detected is not None:
        # Hochauflösender Bildschirm ohne passende Skalierung: einmal mit dem erkannten Faktor neu starten,
        # bevor ein Fenster zu sehen ist
        zoom.restart(detected)
    app.setApplicationName("Firebridge")
    app.setDesktopFileName("io.github.boas2834.Firebridge")
    f = QFont()
    f.setFamilies(FONT_FAMILIES)
    f.setPointSize(10)
    app.setFont(f)
    app.setStyle("Fusion")
    app.setStyleSheet(stylesheet())
    backend: Backend = DemoBackend() if args.demo else DBusBackend(session_bus=args.session_bus)
    global KIOSK
    KIOSK = args.kiosk
    win = MainWindow(backend, demo=args.demo, zoom_wanted=zoom_wanted, zoom_source=zoom_source, kiosk=args.kiosk)
    if args.kiosk:
        # Im Kiosk läuft kein Fenstermanager: Fenster selbst über den ganzen Bildschirm legen
        win.cover_screen()
        win.showFullScreen()
        screen = win.screen()
        if screen is not None:
            screen.geometryChanged.connect(lambda _g: win.cover_screen())
    else:
        win.showFullScreen() if args.fullscreen else win.show()
    backend.start()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
