"""Netzwerk-Sperre des Dienstes mit nftables.

Der Dienst darf grundsätzlich nichts ins Netz schicken. Eine eigene Tabelle
"inet firebridge" verwirft alle Pakete, die aus der cgroup von firebridged
kommen (also nur vom Dienst, nicht vom Rest des Rechners):

    table inet firebridge {
      chain window { }                       ← leer = kein Netz
      chain fb_out { jump window; reject }
      chain output { hook output; socket cgroupv2 … "system.slice/firebridged.service" jump fb_out }
    }

Nur während einer Übertragung oder eines Verbindungstests stehen in "window"
Regeln für tcp/445 (bzw. den eingestellten Port) zur IP des Servers, kurz
auch für DNS. Danach wird "window" wieder geleert. Beim Beenden des Dienstes
löscht systemd die Tabelle (ExecStopPost).
"""

from __future__ import annotations

import ipaddress
import logging
import subprocess
import threading
from pathlib import Path
from typing import Callable, Iterable, Sequence

log = logging.getLogger(__name__)

TABLE = "firebridge"

Runner = Callable[[Sequence[str], str], subprocess.CompletedProcess]


class FirewallError(RuntimeError):
    pass


def default_runner(cmd: Sequence[str], stdin: str) -> subprocess.CompletedProcess:
    return subprocess.run(list(cmd), input=stdin, capture_output=True, text=True, timeout=20)


def own_cgroup(proc_file: Path = Path("/proc/self/cgroup")) -> str:
    """cgroup-v2-Pfad des eigenen Prozesses, z. B. "system.slice/firebridged.service"."""
    for line in proc_file.read_text().splitlines():
        if line.startswith("0::"):
            path = line[3:].strip().strip("/")
            if not path:
                raise FirewallError("Dienst läuft in der Wurzel-cgroup, Netzwerk-Sperre nicht möglich")
            return path
    raise FirewallError("Kein cgroup v2 gefunden (nötig für die Netzwerk-Sperre)")


def cgroup_match(path: str) -> str:
    level = len(path.split("/"))
    return f'socket cgroupv2 level {level} "{path}"'


def base_ruleset(match: str) -> str:
    return (
        f"table inet {TABLE}\n"
        f"delete table inet {TABLE}\n"
        f"table inet {TABLE} {{\n"
        "  chain window {\n"
        "  }\n"
        "  chain fb_out {\n"
        "    jump window\n"
        "    counter reject with icmpx type admin-prohibited\n"
        "  }\n"
        "  chain output {\n"
        "    type filter hook output priority 0; policy accept;\n"
        f"    {match} jump fb_out\n"
        "  }\n"
        "}\n"
    )


def _addr_rule(addr: str, port: int) -> str:
    fam = "ip6" if ipaddress.ip_address(addr).version == 6 else "ip"
    return f"add rule inet {TABLE} window {fam} daddr {addr} tcp dport {port} accept"


DNS_RULES = [
    f"add rule inet {TABLE} window udp dport {{ 53, 5353 }} accept",
    f"add rule inet {TABLE} window tcp dport 53 accept",
]


class Firewall:
    """Öffnet und schließt das Netzwerk-Fenster für den Dienst."""

    def __init__(self, nft: str = "nft", match: str | None = None, run: Runner = default_runner):
        self.nft = nft
        self.match = match
        self.run = run
        self.ready = False
        self.message = "noch nicht eingerichtet"
        self.open = False
        self._lock = threading.Lock()

    def _apply(self, script: str) -> None:
        try:
            res = self.run([self.nft, "-f", "-"], script)
        except (OSError, subprocess.SubprocessError) as exc:
            raise FirewallError(f"nft nicht ausführbar: {exc}") from exc
        if res.returncode != 0:
            raise FirewallError((res.stderr or res.stdout or "nft fehlgeschlagen").strip().splitlines()[0])

    def setup(self) -> None:
        """Legt die Tabelle an (Fenster geschlossen). Fehler → keine Übertragung möglich."""
        try:
            match = self.match or cgroup_match(own_cgroup())
            self._apply(base_ruleset(match))
        except (FirewallError, OSError) as exc:
            self.ready = False
            self.message = f"Netzwerk-Sperre nicht aktiv: {exc}"
            log.error("%s", self.message)
            raise FirewallError(self.message) from exc
        self.ready = True
        self.open = False
        self.message = "nftables: Netzwerk gesperrt"
        log.info("nftables-Tabelle inet %s geladen (%s)", TABLE, match)

    def allow_dns(self) -> None:
        with self._lock:
            self._apply("\n".join(DNS_RULES) + "\n")
            self.open = True

    def allow(self, addrs: Iterable[str], port: int) -> None:
        """Nur noch diese Adressen auf diesem Port (DNS wird wieder zugemacht)."""
        rules = [f"flush chain inet {TABLE} window"] + [_addr_rule(a, port) for a in addrs]
        with self._lock:
            self._apply("\n".join(rules) + "\n")
            self.open = True

    def close(self) -> None:
        with self._lock:
            if not self.ready:
                return
            try:
                self._apply(f"flush chain inet {TABLE} window\n")
            except FirewallError:
                # Notfalls die ganze Tabelle neu laden, damit das Fenster sicher zu ist
                log.exception("Fenster schließen fehlgeschlagen, lade Tabelle neu")
                self._apply(base_ruleset(self.match or cgroup_match(own_cgroup())))
            self.open = False

    def status(self) -> dict:
        return {"ok": self.ready, "open": self.open, "message": self.message}


class NoFirewall:
    """firewall = "off": keine Sperre. Nur für Tests ohne nftables gedacht."""

    ready = True
    open = False
    message = "AUS (firewall = \"off\"), der Dienst hat immer Netz"

    def setup(self) -> None: ...
    def allow_dns(self) -> None: ...
    def allow(self, addrs, port) -> None: ...
    def close(self) -> None: ...

    def status(self) -> dict:
        return {"ok": True, "open": False, "message": self.message, "disabled": True}
