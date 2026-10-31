"""Größe der Oberfläche (HiDPI): Automatisch oder fest 100–300 %.

Qt skaliert die ganze Oberfläche gleichmäßig über die Umgebungsvariable QT_SCALE_FACTOR (Schrift,
Abstände, feste Breiten, Symbole). Die Variable wirkt nur beim Start, deshalb startet die Oberfläche
nach einer Änderung kurz neu. Dem Prüfdienst ist das egal, er läuft weiter.

Reihenfolge: --zoom auf der Kommandozeile, dann FIREBRIDGE_ZOOM, dann die gespeicherte Einstellung
(~/.config/firebridge/gui.json), sonst Automatisch.
"""

from __future__ import annotations

import json
import math
import os
import sys
from pathlib import Path

STEPS = [1.0, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0]
AUTO = "auto"
# Kleinste Fläche (bei 100 %), die die Seiten ohne Rollbalken brauchen
MIN_W, MIN_H = 1000, 700
# Merker, damit die automatische Erkennung nach dem Neustart nicht nochmal neu startet
_AUTO_ENV = "FIREBRIDGE_ZOOM_AUTO"
# Merker: QT_SCALE_FACTOR stammt von uns (sonst kommt es von außen und Automatisch lässt es stehen)
_OWN_ENV = "FIREBRIDGE_ZOOM_OWN"


def config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "firebridge" / "gui.json"


def parse(value) -> float | str | None:
    """'auto', '150', '150%', '1.5', 1.5 → AUTO oder Faktor; Unsinn → None."""
    if value is None:
        return None
    if isinstance(value, str):
        v = value.strip().lower().rstrip("%").strip().replace(",", ".")
        if v in ("auto", "automatisch", ""):
            return AUTO
        try:
            f = float(v)
        except ValueError:
            return None
    elif isinstance(value, (int, float)):
        f = float(value)
    else:
        return None
    if f >= 10:  # Prozentangabe
        f /= 100
    if not 0.5 <= f <= 4:
        return None
    return round(f, 2)


def label(value: float | str) -> str:
    if value == AUTO:
        return "Automatisch"
    return f"{round(float(value) * 100)} %"


def load() -> float | str:
    try:
        data = json.loads(config_path().read_text())
    except (OSError, ValueError):
        return AUTO
    return parse(data.get("zoom") if isinstance(data, dict) else None) or AUTO


def save(value: float | str) -> None:
    path = config_path()
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    data["zoom"] = value
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    tmp.replace(path)


def auto_factor(logical_dpi: float, width_mm: float, avail_w: int, avail_h: int) -> float:
    """Faktor aus der echten Pixeldichte des Bildschirms.

    logical_dpi: Bildpunkte pro Zoll so, wie Qt sie bei Faktor 1 zeichnet (QScreen.physicalDotsPerInch,
    eine Skalierung des Desktops ist darin schon enthalten). 96 dpi gilt als 100 %. Abgerundet auf
    25-%-Schritte und so begrenzt, dass das Fenster noch auf den Bildschirm passt.
    """
    # Manche Bildschirme melden Unsinn (0 mm, oder das Seitenverhältnis in cm)
    if width_mm < 150 or not 50 <= logical_dpi <= 600:
        return 1.0
    f = math.floor(logical_dpi / 96 * 4) / 4
    # auch die Obergrenze auf 25-%-Schritte abrunden (sonst z. B. 254 %)
    return max(1.0, math.floor(min(f, fit_limit(avail_w, avail_h)) * 4) / 4)


def fit_limit(avail_w: int, avail_h: int) -> float:
    """Größter Faktor, bei dem die Seiten noch ohne Rollbalken auf den Bildschirm passen."""
    if avail_w <= 0 or avail_h <= 0:
        return STEPS[-1]
    return max(1.0, min(avail_w / MIN_W, avail_h / MIN_H, STEPS[-1]))


def choose(cli: str | None) -> tuple[float | str, str]:
    """Gewünschte Einstellung und woher sie kommt ('cli', 'env', 'config')."""
    if cli is not None and parse(cli) is not None:
        return parse(cli), "cli"
    env = parse(os.environ.get("FIREBRIDGE_ZOOM"))
    if env is not None:
        return env, "env"
    return load(), "config"


def apply_before_app(wanted: float | str) -> None:
    """Fester Faktor: QT_SCALE_FACTOR setzen, bevor QApplication entsteht."""
    if wanted != AUTO:
        os.environ["QT_SCALE_FACTOR"] = f"{float(wanted):g}"
        os.environ[_OWN_ENV] = "1"


def current_factor() -> float:
    try:
        return float(os.environ.get("QT_SCALE_FACTOR") or 1)
    except ValueError:
        return 1.0


def auto_detect(app, wanted: float | str) -> float | None:
    """Nach dem Anlegen der QApplication: Faktor für Automatisch, None = nichts tun.

    Liefert nur dann einen Wert, wenn ein Neustart mit diesem Faktor nötig ist.
    """
    if wanted != AUTO or os.environ.get(_AUTO_ENV) is not None:
        return None  # fest eingestellt oder schon erkannt
    if os.environ.get("QT_SCALE_FACTOR") and not os.environ.get(_OWN_ENV):
        return None  # von außen vorgegeben (Desktop, Kiosk), nicht überstimmen
    screen = app.primaryScreen()
    if screen is None:
        return None
    avail = screen.availableGeometry()
    f = auto_factor(screen.physicalDotsPerInch(), screen.physicalSize().width(), avail.width(), avail.height())
    os.environ[_AUTO_ENV] = f"{f:g}"
    return f if abs(f - current_factor()) > 0.01 else None


def detected() -> float | None:
    try:
        return float(os.environ[_AUTO_ENV])
    except (KeyError, ValueError):
        return None


def restart(factor: float | str) -> None:
    """Oberfläche mit neuem Faktor neu starten (ersetzt den laufenden Prozess)."""
    if factor == AUTO:
        for name in (_AUTO_ENV, _OWN_ENV, "QT_SCALE_FACTOR"):
            os.environ.pop(name, None)
    else:
        os.environ["QT_SCALE_FACTOR"] = f"{float(factor):g}"
        os.environ[_OWN_ENV] = "1"
    argv = list(getattr(sys, "orig_argv", None) or [sys.executable, *sys.argv])
    sys.stdout.flush()
    sys.stderr.flush()
    os.execv(sys.executable, [sys.executable, *argv[1:]])
