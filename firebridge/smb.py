"""SMB-Zugriff im Userspace mit smbprotocol (kein mount.cifs, kein Kernel-Mount).

Ablauf einer Sitzung:
  1. Netzwerk-Fenster für DNS öffnen, Servernamen auflösen,
  2. Fenster nur noch für tcp/<port> zu genau diesen IPs offen lassen,
  3. per IP verbinden (kein zweites Auflösen, kein DNS-Rebinding),
  4. am Ende Sitzung abmelden, Verbindung schließen, Fenster zu.

Die Klasse SmbSession kapselt alle smbclient-Aufrufe. Tests ersetzen sie
durch eine Attrappe, die in ein lokales Verzeichnis schreibt.
"""

from __future__ import annotations

import errno
import hashlib
import ipaddress
import logging
import socket
import uuid
from typing import BinaryIO, Callable

from .share import ShareSettings

log = logging.getLogger(__name__)

CHUNK = 1024 * 1024

# NTSTATUS-Werte, die in Meldungen übersetzt werden
STATUS_LOGON_FAILURE = 0xC000006D
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_BAD_NETWORK_NAME = 0xC00000CC
STATUS_NOT_FOUND = 0xC0000225
STATUS_DISK_FULL = 0xC000007F


class SmbError(RuntimeError):
    pass


def resolve(server: str, port: int) -> list[str]:
    try:
        ipaddress.ip_address(server)
        return [server]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(server, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SmbError(f"Server {server} nicht gefunden ({exc.strerror})") from exc
    out: list[str] = []
    for info in infos:
        addr = info[4][0].split("%")[0]
        if addr not in out:
            out.append(addr)
    if not out:
        raise SmbError(f"Server {server} nicht gefunden")
    return out


def _dialect_name(value: int) -> str:
    return {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}.get(
        value, hex(value))


def _ntstatus(exc: BaseException) -> int | None:
    # SMBOSError hat .ntstatus, die SMBResponseException-Klassen (z. B. NotFound) .status
    value = getattr(exc, "ntstatus", None) or getattr(exc, "status", None)
    return value if isinstance(value, int) else None


def explain(exc: BaseException) -> str:
    """Fehler von smbprotocol in einen verständlichen Satz übersetzen."""
    text = str(exc)
    name = exc.__class__.__name__
    status = _ntstatus(exc)
    if isinstance(exc, SmbError):
        return text
    if status == STATUS_DISK_FULL:
        return "Auf dem Share ist kein Platz mehr frei"
    if status == STATUS_LOGON_FAILURE or "STATUS_LOGON_FAILURE" in text or "LogonFailure" in name:
        return "Anmeldung abgelehnt: Benutzername oder Passwort falsch"
    if status == STATUS_BAD_NETWORK_NAME or "STATUS_BAD_NETWORK_NAME" in text or "BadNetworkName" in name:
        return "Freigabe nicht gefunden: Freigabename prüfen"
    if status == STATUS_ACCESS_DENIED or "STATUS_ACCESS_DENIED" in text or "AccessDenied" in name:
        return "Zugriff verweigert: Der Benutzer darf auf dem Share nicht schreiben"
    if "encrypt" in text.lower() and ("not support" in text.lower() or "require" in text.lower()):
        return ("Der Server unterstützt keine SMB3-Verschlüsselung. "
                "In den Einstellungen abschalten oder den Server auf SMB3 umstellen")
    if isinstance(exc, (ConnectionRefusedError,)) or "refused" in text.lower():
        return "Verbindung abgelehnt: Läuft auf dem Server SMB (Port prüfen)?"
    if isinstance(exc, (TimeoutError, socket.timeout)) or "timed out" in text.lower():
        return "Zeitüberschreitung: Server antwortet nicht"
    if "no route to host" in text.lower() or getattr(exc, "errno", None) == errno.EHOSTUNREACH:
        return "Server nicht erreichbar (keine Route, oder der Paketfilter blockiert)"
    if "admin-prohibited" in text.lower() or getattr(exc, "errno", None) in (errno.EACCES, errno.EPERM):
        return "Vom Paketfilter blockiert (nftables-Fenster nicht offen)"
    return f"{name}: {text}"


class SmbSession:
    """Eine Verbindung zu genau einem Share. Pfade sind Tupel relativ zum Basisordner."""

    def __init__(self, settings: ShareSettings, password: str, timeout: float = 30.0):
        self.settings = settings
        self.password = password
        self.timeout = timeout
        self.host = ""
        self.info = ""
        self._cache: dict = {}
        self._kw: dict = {}

    def connect(self, addrs: list[str]) -> None:
        import smbclient  # erst hier: smbprotocol wird nur für die Übertragung gebraucht

        s = self.settings
        user = s.username or None
        if user and s.domain:
            user = f"{s.domain}\\{user}"
        last: BaseException | None = None
        # IPv4 zuerst, das klappt mit den meisten NAS am zuverlässigsten
        for addr in sorted(addrs, key=lambda a: ":" in a):
            self._cache = {}
            self._kw = dict(username=user, password=self.password if user else None, port=s.port,
                            encrypt=True if s.encrypt else None, connection_timeout=self.timeout,
                            connection_cache=self._cache)
            try:
                session = smbclient.register_session(addr, **self._kw)
            except Exception as exc:  # nächste Adresse versuchen
                last = exc
                self._reset()
                continue
            self.host = addr
            dialect = _dialect_name(session.connection.dialect)
            enc = "verschlüsselt" if getattr(session, "encrypt_data", False) or s.encrypt else "unverschlüsselt"
            self.info = f"SMB {dialect}, {enc}, angemeldet als {user or 'Gast'} ({addr})"
            # Freigabe gleich verbinden, damit Fehler im Freigabenamen sofort auffallen
            try:
                smbclient.stat(f"\\\\{addr}\\{s.share}", **self._kw)
            except Exception as exc:
                self._reset()
                if _ntstatus(exc) in (STATUS_BAD_NETWORK_NAME, STATUS_NOT_FOUND):
                    raise SmbError(f"Freigabe „{s.share}“ nicht gefunden: Freigabename prüfen") from exc
                raise SmbError(explain(exc)) from exc
            return
        raise SmbError(explain(last) if last else "keine Adresse")

    def path(self, *parts: str) -> str:
        return self.settings.unc(self.host, *parts)

    def makedirs(self, parts: tuple[str, ...]) -> None:
        import smbclient
        if parts or self.settings.folder_parts():
            smbclient.makedirs(self.path(*parts), exist_ok=True, **self._kw)

    def mkdir_unique(self, name: str) -> str:
        """Legt einen neuen Ordner an. Gibt es ihn schon, wird -2, -3 … angehängt."""
        import smbclient
        for n in range(1, 100):
            candidate = name if n == 1 else f"{name}-{n}"
            try:
                smbclient.mkdir(self.path(candidate), **self._kw)
                return candidate
            except OSError as exc:
                if getattr(exc, "errno", None) != errno.EEXIST:
                    raise
        raise SmbError(f"Kein freier Ordnername für {name}")

    def create(self, parts: tuple[str, ...]) -> BinaryIO:
        """Neue Datei anlegen. Existiert sie schon, schlägt das fehl (nie überschreiben)."""
        import smbclient
        return smbclient.open_file(self.path(*parts), mode="xb", **self._kw)

    def sha256(self, parts: tuple[str, ...], cancel: Callable[[], bool] = lambda: False) -> str:
        import smbclient
        h = hashlib.sha256()
        with smbclient.open_file(self.path(*parts), mode="rb", **self._kw) as fh:
            while chunk := fh.read(CHUNK):
                if cancel():
                    raise SmbError("abgebrochen")
                h.update(chunk)
        return h.hexdigest()

    def rename(self, src: tuple[str, ...], dst: tuple[str, ...]) -> None:
        import smbclient
        smbclient.rename(self.path(*src), self.path(*dst), **self._kw)

    def remove(self, parts: tuple[str, ...]) -> None:
        import smbclient
        smbclient.remove(self.path(*parts), **self._kw)

    def write_test(self) -> None:
        """Schreibrecht prüfen: Testdatei anlegen und wieder löschen."""
        name = (f".firebridge-test-{uuid.uuid4().hex[:8]}",)
        with self.create(name) as fh:
            fh.write(b"firebridge")
        self.remove(name)

    def _reset(self) -> None:
        try:
            import smbclient
            smbclient.reset_connection_cache(fail_on_error=False, connection_cache=self._cache)
        except Exception:  # Verbindung ist ohnehin weg
            log.debug("reset_connection_cache", exc_info=True)
        self._cache = {}

    def close(self) -> None:
        self._reset()
        self.host = ""
