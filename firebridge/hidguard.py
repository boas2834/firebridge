"""HID-Wächter (Etappe 4): Tastatureingaben neuer Geräte abfangen und bewerten.

Ein neu zugelassenes Gerät, das Tasten senden kann, öffnet der Dienst über
evdev exklusiv (EVIOCGRAB). Solange er es festhält, erreicht keine Taste den
Desktop. Der Bediener tippt auf der neuen Tastatur einen Code, den nur die
Oberfläche zeigt. Ein Angriffs-Stick kennt ihn nicht, er tippt stattdessen
seine eigenen Befehle, und zwar viel schneller als ein Mensch. Das bewertet
KeyAnalyzer.

Ohne Fremdbibliothek: input_event wird direkt aus /dev/input/eventN gelesen.
"""

from __future__ import annotations

import errno
import fcntl
import logging
import os
import select
import statistics
import struct
import threading
from typing import Callable

log = logging.getLogger(__name__)

EVIOCGRAB = 0x40044590          # _IOW('E', 0x90, int)
EV_KEY = 0x01
EVENT = struct.Struct("llHHi")   # struct input_event: timeval, type, code, value

# Auswahl aus linux/input-event-codes.h, Anzeige nach US-Belegung (so tippen Angriffs-Sticks meist)
_ROW_DIGITS = {2: "1", 3: "2", 4: "3", 5: "4", 6: "5", 7: "6", 8: "7", 9: "8", 10: "9", 11: "0"}
_KP_DIGITS = {79: "1", 80: "2", 81: "3", 75: "4", 76: "5", 77: "6", 71: "7", 72: "8", 73: "9", 82: "0"}
_LETTERS = dict(zip([16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 30, 31, 32, 33, 34, 35, 36, 37, 38,
                     44, 45, 46, 47, 48, 49, 50], "qwertyuiopasdfghjklzxcvbnm"))
_PLAIN = {12: "-", 13: "=", 26: "[", 27: "]", 39: ";", 40: "'", 41: "`", 43: "\\", 51: ",", 52: ".",
          53: "/", 57: " ", 55: "*", 74: "-", 78: "+", 83: ".", 98: "/"}
_SHIFTED = {"1": "!", "2": "@", "3": "#", "4": "$", "5": "%", "6": "^", "7": "&", "8": "*", "9": "(",
            "0": ")", "-": "_", "=": "+", "[": "{", "]": "}", ";": ":", "'": '"', "`": "~", "\\": "|",
            ",": "<", ".": ">", "/": "?"}
_NAMED = {1: "ESC", 14: "⌫", 15: "TAB", 58: "CAPS", 102: "POS1", 103: "↑", 104: "BILD↑", 105: "←", 106: "→",
          107: "ENDE", 108: "↓", 109: "BILD↓", 110: "EINFG", 111: "ENTF"}
_NAMED.update({59 + i: f"F{i + 1}" for i in range(10)})
_NAMED.update({87: "F11", 88: "F12"})
ENTER = {28, 96}
BACKSPACE = 14
MOD_CTRL = {29, 97}
MOD_SHIFT = {42, 54}
MOD_ALT = {56, 100}
MOD_META = {125, 126}
MODS = MOD_CTRL | MOD_SHIFT | MOD_ALT | MOD_META

# Befehle, die ein Angriffs-Stick typischerweise tippt
KEYWORDS = ("powershell", "cmd.exe", "cmd /c", "iex", "invoke-", "curl ", "wget ", "bash", "/bin/sh", "sh -c",
            "http://", "https://", "xterm", "terminal", "sudo ", "chmod ", "nc -", "python -c", "python3 -c",
            "certutil", "bitsadmin", "mshta", "rundll32", "regsvr32", "-enc", "downloadstring")

FAST_MS = 25.0          # Median-Abstand darunter: kein Mensch (Mensch: etwa 80–250 ms)
FAST_MIN_KEYS = 6       # erst ab so vielen Anschlägen werten
EARLY_SECONDS = 1.0     # Taste so kurz nach dem Zulassen: tippt selbstständig


class KeyAnalyzer:
    """Wertet die abgefangenen Tasten eines Geräts aus (reine Logik, gut testbar)."""

    def __init__(self, started: float):
        self.started = started          # Zeitpunkt der Zulassung (gleiche Uhr wie die Ereignisse)
        self.mods: set[int] = set()
        self.presses: list[float] = []
        self.shown: list[str] = []       # Anzeige des Getippten
        self.text = ""                   # Getipptes als Text (für Schlüsselwörter)
        self.digits = ""                 # Ziffern seit dem letzten Enter
        self.entries: list[str] = []     # abgeschlossene Eingaben (mit Enter)
        self.combos: list[str] = []
        self._meta_alone = False

    def feed(self, ts: float, code: int, value: int) -> str | None:
        """Ein Tastenereignis (value 1 = gedrückt, 0 = losgelassen, 2 = Wiederholung).
        Gibt die fertige Eingabe zurück, wenn Enter gedrückt wurde."""
        if value == 0:
            if code in MOD_META and self._meta_alone:
                self.combos.append("Super-Taste (Startmenü)")
                self.shown.append("[SUPER]")
            self.mods.discard(code)
            return None
        if value != 1:
            return None
        self.presses.append(ts)
        if code in MODS:
            self.mods.add(code)
            self._meta_alone = code in MOD_META
            return None
        self._meta_alone = False
        ctrl, alt = bool(self.mods & MOD_CTRL), bool(self.mods & MOD_ALT)
        meta, shift = bool(self.mods & MOD_META), bool(self.mods & MOD_SHIFT)
        ch = _ROW_DIGITS.get(code) or _KP_DIGITS.get(code) or _LETTERS.get(code) or _PLAIN.get(code)
        if meta or ctrl or alt:
            name = "+".join([m for m, on in (("SUPER", meta), ("STRG", ctrl), ("ALT", alt)) if on]
                            + [(ch or _NAMED.get(code, f"#{code}")).upper()])
            self.shown.append(f"[{name}]")
            combo = _combo_name(meta, ctrl, alt, ch, code)
            if combo:
                self.combos.append(combo)
            return None
        if code in ENTER:
            self.shown.append("[ENTER]")
            self.text += "\n"
            entry, self.digits = self.digits, ""
            self.entries.append(entry)
            return entry
        if code == BACKSPACE:
            self.shown.append("[⌫]")
            self.digits = self.digits[:-1]
            return None
        if ch is None:
            self.shown.append(f"[{_NAMED.get(code, f'#{code}')}]")
            return None
        if code in _ROW_DIGITS or code in _KP_DIGITS:
            if not shift or code in _KP_DIGITS:
                self.digits += ch
        if shift:
            ch = _SHIFTED.get(ch, ch.upper())
        self.shown.append(ch)
        self.text += ch
        return None

    # -- Auswertung

    @property
    def keys(self) -> int:
        return len(self.presses)

    def median_interval_ms(self) -> float | None:
        if len(self.presses) < 2:
            return None
        gaps = [(b - a) * 1000 for a, b in zip(self.presses, self.presses[1:])]
        return statistics.median(gaps)

    def keys_per_minute(self) -> float | None:
        med = self.median_interval_ms()
        if not med:
            return None
        return 60000 / med

    def first_key_after(self) -> float | None:
        return self.presses[0] - self.started if self.presses else None

    def reasons(self) -> list[str]:
        """Gründe, warum hier kein Mensch tippt (leer = unauffällig)."""
        out = []
        med = self.median_interval_ms()
        if med is not None and self.keys >= FAST_MIN_KEYS and med < FAST_MS:
            out.append(f"Tippt mit etwa {self.keys_per_minute():,.0f} Anschlägen pro Minute "
                       f"(Abstand {med:.0f} ms, ein Mensch braucht 80–250 ms)".replace(",", "."))
        first = self.first_key_after()
        if first is not None and first < EARLY_SECONDS and self.keys >= 3:
            out.append(f"Erste Taste schon {first:.1f} s nach dem Zulassen, bevor jemand den Code lesen konnte")
        for c in dict.fromkeys(self.combos):
            out.append(f"Tastenkombination {c}")
        low = self.text.lower()
        words = [k.strip() for k in KEYWORDS if k in low]
        if words:
            out.append("Befehle im Getippten: " + ", ".join(dict.fromkeys(words)))
        return out

    def display(self, limit: int = 400) -> str:
        s = "".join(self.shown)
        return s if len(s) <= limit else s[:limit] + " …"

    def summary(self) -> dict:
        med = self.median_interval_ms()
        kpm = self.keys_per_minute()
        first = self.first_key_after()
        return {"keys": self.keys, "text": self.display(), "median_ms": round(med, 1) if med is not None else None,
                "keys_per_min": round(kpm) if kpm else None,
                "first_key_s": round(first, 2) if first is not None else None,
                "digits": len(self.digits), "reasons": self.reasons()}


def _combo_name(meta: bool, ctrl: bool, alt: bool, ch: str | None, code: int) -> str:
    if meta and ch == "r":
        return "Super+R (Ausführen-Dialog unter Windows)"
    if meta and ch == "x":
        return "Super+X (Admin-Menü unter Windows)"
    if ctrl and alt and ch == "t":
        return "Strg+Alt+T (Terminal unter Linux)"
    if alt and code == 60:
        return "Alt+F2 (Befehl ausführen unter Linux)"
    if ctrl and code == 1:
        return "Strg+Esc (Startmenü)"
    if meta and ch:
        return f"Super+{ch.upper()}"
    if ctrl and alt:
        return f"Strg+Alt+{(ch or _NAMED.get(code, '?')).upper()}"
    return ""


# ---------------------------------------------------------------------------
# evdev

KeyCallback = Callable[[str, float, int, int], None]


class InputGrabber:
    """Hält Eingabegeräte exklusiv fest und meldet ihre Tasten an on_key(devnode, ts, code, value)."""

    def __init__(self, on_key: KeyCallback, on_gone: Callable[[str], None] | None = None):
        self.on_key = on_key
        self.on_gone = on_gone
        self._fds: dict[int, str] = {}
        self._lock = threading.Lock()
        self._wake_r, self._wake_w = os.pipe()
        self._stop = False
        self._thread = threading.Thread(target=self._loop, name="hid-guard", daemon=True)
        self._thread.start()

    def grab(self, devnode: str) -> None:
        """Gerät öffnen und festhalten. OSError, wenn das nicht geht (z. B. schon von anderen festgehalten)."""
        fd = os.open(devnode, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            fcntl.ioctl(fd, EVIOCGRAB, 1)
        except OSError:
            os.close(fd)
            raise
        with self._lock:
            self._fds[fd] = devnode
        os.write(self._wake_w, b"x")

    def release(self, devnode: str) -> None:
        with self._lock:
            fds = [fd for fd, n in self._fds.items() if n == devnode]
            for fd in fds:
                del self._fds[fd]
        for fd in fds:
            try:
                fcntl.ioctl(fd, EVIOCGRAB, 0)
            except OSError:
                pass
            os.close(fd)
        os.write(self._wake_w, b"x")

    def grabbed(self) -> list[str]:
        with self._lock:
            return list(self._fds.values())

    def close(self) -> None:
        self._stop = True
        for node in self.grabbed():
            self.release(node)

    def _loop(self) -> None:
        while not self._stop:
            with self._lock:
                fds = list(self._fds)
            try:
                ready, _, _ = select.select([self._wake_r, *fds], [], [], 1.0)
            except (OSError, ValueError):
                continue  # ein fd wurde gerade geschlossen
            for fd in ready:
                if fd == self._wake_r:
                    os.read(self._wake_r, 64)
                    continue
                self._read(fd)

    def _read(self, fd: int) -> None:
        with self._lock:
            node = self._fds.get(fd)
        if node is None:
            return
        try:
            data = os.read(fd, EVENT.size * 64)
        except BlockingIOError:
            return
        except OSError as exc:
            if exc.errno in (errno.ENODEV, errno.EIO, errno.EBADF):
                with self._lock:
                    self._fds.pop(fd, None)
                try:
                    os.close(fd)
                except OSError:
                    pass
                if self.on_gone:
                    self.on_gone(node)
            return
        for off in range(0, len(data) - EVENT.size + 1, EVENT.size):
            sec, usec, etype, code, value = EVENT.unpack_from(data, off)
            if etype == EV_KEY:
                try:
                    self.on_key(node, sec + usec / 1e6, code, value)
                except Exception:
                    log.exception("Tastenereignis von %s", node)
