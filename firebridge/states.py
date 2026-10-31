"""Zustände von Firebridge und die erlaubten Übergänge.

Eine Netzwerkverbindung zum Ziel-Share gibt es nur im Zustand UEBERTRAGUNG, und
dorthin führt nur ein Weg: ERGEBNIS (sauber) → Freigabe durch den Benutzer.
Im Zustand VIRUSTOTAL (optional, nur nach einem Scan ohne Virenfund) ist das
Fenster nur zu www.virustotal.com auf tcp/443 offen.
"""

from __future__ import annotations

import enum


class State(str, enum.Enum):
    LEERLAUF = "LEERLAUF"            # kein Datenträger
    GERAET_ERKANNT = "GERAET_ERKANNT"  # wird gerade eingebunden
    EINGEBUNDEN = "EINGEBUNDEN"      # read-only eingebunden, bereit zum Prüfen
    SCAN = "SCAN"
    VIRUSTOTAL = "VIRUSTOTAL"        # nach dem Scan: Abfrage/Upload bei VirusTotal, Fenster zu tcp/443
    ERGEBNIS = "ERGEBNIS"
    UEBERTRAGUNG = "UEBERTRAGUNG"    # freigegeben, SMB-Verbindung offen, Dateien werden kopiert
    UEBERTRAGEN = "UEBERTRAGEN"      # fertig, Verbindung wieder abgebaut
    BLOCKIERT = "BLOCKIERT"          # Gerät meldet Tastatur/Netzwerk, wird nicht eingebunden
    FEHLER = "FEHLER"                # Einbinden fehlgeschlagen
    AUSGEWORFEN = "AUSGEWORFEN"      # ausgehängt, kann abgezogen werden


TRANSITIONS: dict[State, set[State]] = {
    State.LEERLAUF: {State.GERAET_ERKANNT, State.BLOCKIERT},
    State.GERAET_ERKANNT: {State.EINGEBUNDEN, State.FEHLER, State.LEERLAUF},
    State.EINGEBUNDEN: {State.SCAN, State.AUSGEWORFEN, State.LEERLAUF},
    State.SCAN: {State.ERGEBNIS, State.VIRUSTOTAL, State.EINGEBUNDEN, State.LEERLAUF},
    State.VIRUSTOTAL: {State.ERGEBNIS, State.LEERLAUF},
    State.ERGEBNIS: {State.SCAN, State.VIRUSTOTAL, State.UEBERTRAGUNG, State.AUSGEWORFEN, State.LEERLAUF},
    State.UEBERTRAGUNG: {State.UEBERTRAGEN, State.ERGEBNIS, State.LEERLAUF},
    State.UEBERTRAGEN: {State.AUSGEWORFEN, State.LEERLAUF},
    State.BLOCKIERT: {State.LEERLAUF},
    State.FEHLER: {State.AUSGEWORFEN, State.LEERLAUF},
    State.AUSGEWORFEN: {State.LEERLAUF},
}


class StateError(RuntimeError):
    """Aktion ist im aktuellen Zustand nicht erlaubt."""


def check_transition(current: State, new: State) -> None:
    if new not in TRANSITIONS[current]:
        raise StateError(f"Übergang {current.value} → {new.value} nicht erlaubt")
