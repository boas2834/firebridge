"""Ein einziger Admin: Passwort für Einstellungen, Freigaben und Verlauf löschen.

Prüfen, Übertragen und Auswerfen darf jeder an der Station. Was Regeln ändert
oder etwas durchlässt, verlangt das Admin-Passwort:

  * Einstellungen speichern (Ziele, Richtlinie, VirusTotal), Verbindung mit
    ungespeicherten Daten testen
  * auffällige Dateien freigeben, USB-Geräte freigeben, VirusTotal-Upload
  * Verlauf löschen

Durchgesetzt wird das im Dienst, nicht in der Oberfläche. Nach der Anmeldung
gilt sie für diese Verbindung (eine laufende Oberfläche) 10 Minuten lang und
verlängert sich mit jeder geschützten Aktion; Schließen der Oberfläche oder
„Abmelden“ beendet sie. Nach 5 Fehlversuchen ist die Anmeldung 60 Sekunden
gesperrt. root (z. B. busctl mit sudo) braucht kein Passwort.

Das Passwort liegt nur als scrypt-Hash in /var/lib/firebridge/admin.json
(nur für root lesbar). Vergessen? Neu setzen mit

    sudo firebridge-admin-passwort
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
from pathlib import Path

SESSION_SECONDS = 600
MAX_FAILS = 5
LOCKOUT_SECONDS = 60
MIN_LENGTH = 6
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}


class AdminError(Exception):
    """Aktion braucht das Admin-Passwort (oder es ist falsch/gesperrt)."""


def _hash(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)


class AdminGate:
    def __init__(self, path: Path, clock=time.monotonic):
        self.path = path
        self.clock = clock
        self._lock = threading.Lock()
        self._sessions: dict[str, float] = {}     # D-Bus-Absender → gültig bis
        self._fails = 0
        self._locked_until = 0.0

    # -- Passwort

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) and data.get("hash") else {}
        except (OSError, ValueError):
            return {}

    def has_password(self) -> bool:
        return bool(self._load())

    def set_password(self, password: str) -> None:
        if len(password) < MIN_LENGTH:
            raise AdminError(f"Das Passwort braucht mindestens {MIN_LENGTH} Zeichen")
        salt = secrets.token_bytes(16)
        data = {"scheme": "scrypt", **_SCRYPT, "salt": base64.b64encode(salt).decode(),
                "hash": base64.b64encode(_hash(password, salt, **_SCRYPT)).decode()}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(tmp, self.path)
        with self._lock:
            self._sessions.clear()   # wer mit dem alten Passwort angemeldet war, muss neu

    def _check(self, password: str) -> bool:
        data = self._load()
        if not data:
            return False
        try:
            salt = base64.b64decode(data["salt"])
            want = base64.b64decode(data["hash"])
            got = _hash(password, salt, int(data["n"]), int(data["r"]), int(data["p"]))
        except (KeyError, ValueError):
            return False
        return hmac.compare_digest(want, got)

    # -- Anmeldung je Verbindung

    def login(self, sender: str, password: str) -> float:
        """Gültig bis (monotone Zeit). Wirft AdminError bei falschem Passwort oder Sperre."""
        now = self.clock()
        with self._lock:
            if now < self._locked_until:
                raise AdminError(f"Zu viele Fehlversuche, bitte {int(self._locked_until - now) + 1} s warten")
        if not self.has_password():
            raise AdminError("Es ist noch kein Admin-Passwort festgelegt")
        ok = self._check(password)
        with self._lock:
            if not ok:
                self._fails += 1
                if self._fails >= MAX_FAILS:
                    self._fails = 0
                    self._locked_until = now + LOCKOUT_SECONDS
                    raise AdminError(f"Passwort falsch. Zu viele Fehlversuche, Anmeldung {LOCKOUT_SECONDS} s gesperrt")
                raise AdminError("Passwort falsch")
            self._fails = 0
            until = now + SESSION_SECONDS
            self._sessions[sender] = until
            return until

    def logout(self, sender: str) -> None:
        with self._lock:
            self._sessions.pop(sender, None)

    def forget(self, sender: str) -> None:
        """Verbindung beendet (Oberfläche geschlossen)."""
        self.logout(sender)

    def active(self, sender: str) -> float:
        """Restsekunden der Anmeldung (0 = nicht angemeldet)."""
        with self._lock:
            left = self._sessions.get(sender, 0) - self.clock()
            if left <= 0:
                self._sessions.pop(sender, None)
                return 0.0
            return left

    def require(self, sender: str, uid: int | None) -> None:
        """Vor einer geschützten Aktion. Verlängert die Anmeldung."""
        if uid == 0:
            return
        if not self.has_password():
            raise AdminError("Für diese Aktion braucht es das Admin-Passwort, es ist aber noch keins festgelegt")
        if self.active(sender) <= 0:
            raise AdminError("Für diese Aktion braucht es das Admin-Passwort")
        with self._lock:
            self._sessions[sender] = self.clock() + SESSION_SECONDS


def main(argv: list[str] | None = None) -> None:
    """firebridge-admin-passwort: Admin-Passwort als root setzen (auch wenn das alte vergessen ist)."""
    from . import config as config_mod
    if os.geteuid() != 0:
        sys.exit("Bitte mit sudo starten: sudo firebridge-admin-passwort")
    cfg = config_mod.load()
    gate = AdminGate(cfg.admin_file)
    print("Neues Admin-Passwort für die Firebridge" + (" (ersetzt das bisherige)" if gate.has_password() else ""))
    first = getpass.getpass("Passwort: ")
    if getpass.getpass("Wiederholen: ") != first:
        sys.exit("Die beiden Eingaben sind verschieden, nichts geändert.")
    try:
        gate.set_password(first)
    except AdminError as exc:
        sys.exit(str(exc))
    print(f"Gespeichert in {cfg.admin_file}. Wer in der Oberfläche angemeldet war, muss sich neu anmelden "
          "(nach einem Neustart von firebridged).")


if __name__ == "__main__":
    main()
