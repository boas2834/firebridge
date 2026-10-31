"""Farben und Stylesheet, angelehnt an die GUI-Beispiele im Konzept."""

C = {
    "bg": "#e9edf1",
    "side": "#1b2733",
    "side_fg": "#c9d3dc",
    "card": "#ffffff",
    "fg": "#16202a",
    "muted": "#56636f",
    "line": "#d5dce3",
    "accent": "#0f5f78",
    "accent_soft": "#e0eef2",
    "ok": "#1d7a46", "ok_soft": "#e1f2e8",
    "warn": "#9a6200", "warn_soft": "#fbefd6",
    "bad": "#b3261e", "bad_soft": "#fbe3e1",
    "off": "#6b7a87",
}

TONES = {
    "ok": (C["ok"], C["ok_soft"]),
    "warn": (C["warn"], C["warn_soft"]),
    "bad": (C["bad"], C["bad_soft"]),
    "info": (C["accent"], C["accent_soft"]),
    "off": (C["off"], "#eef1f4"),
}

FONT_FAMILIES = ["IBM Plex Sans", "Inter", "Noto Sans", "Cantarell", "DejaVu Sans"]
MONO_FAMILIES = ["IBM Plex Mono", "JetBrains Mono", "DejaVu Sans Mono", "Noto Sans Mono"]


def stylesheet() -> str:
    pills = "".join(
        f'QLabel[role="pill"][tone="{t}"] {{ color: {fg}; background: {bg}; }}\n'
        f'QFrame[role="banner"][tone="{t}"] {{ background: {bg}; border: 1px solid {fg}; }}\n'
        f'QFrame[role="banner"][tone="{t}"] QLabel[role="bannerTitle"] {{ color: {fg}; }}\n'
        for t, (fg, bg) in TONES.items()
    )
    return f"""
QWidget#root, QStackedWidget, QScrollArea, QWidget#page {{ background: {C['bg']}; }}
QWidget {{ color: {C['fg']}; font-size: 14px; }}
QToolTip {{ color: {C['fg']}; background: {C['card']}; border: 1px solid {C['line']}; padding: 4px; }}

QFrame#side {{ background: {C['side']}; }}
QFrame#side QLabel {{ color: {C['side_fg']}; }}
QLabel#brand {{ color: #ffffff; font-size: 19px; font-weight: 800; }}
QLabel#brandSub {{ font-size: 11px; letter-spacing: 1px; }}
QPushButton[role="nav"] {{ text-align: left; color: {C['side_fg']}; background: transparent; border: none;
    padding: 9px 12px; border-radius: 4px; font-size: 14px; }}
QPushButton[role="nav"]:hover {{ background: rgba(255,255,255,0.05); }}
QPushButton[role="nav"]:checked {{ background: rgba(255,255,255,0.10); color: #ffffff; }}
QPushButton[role="nav"]:disabled {{ color: #5d6b78; background: transparent; border: none; }}
QFrame#sideFoot {{ border-top: 1px solid rgba(255,255,255,0.10); }}
QFrame#sideFoot QLabel {{ font-size: 12px; }}
QFrame#side QLabel#adminLeft {{ color: #8796a5; font-size: 12px; padding: 0 4px 4px 38px; }}
QFrame#sideFoot QLabel#buildLabel {{ color: #8796a5; font-size: 11px; }}
QPushButton#infoButton {{ color: {C['side_fg']}; background: transparent; border: 1px solid rgba(255,255,255,0.18);
    border-radius: 11px; min-width: 22px; max-width: 22px; min-height: 22px; max-height: 22px; padding: 0;
    font-size: 13px; }}
QPushButton#infoButton:hover {{ background: rgba(255,255,255,0.10); color: #ffffff; }}

QLabel[role="h1"] {{ font-size: 22px; font-weight: 700; }}
QLabel[role="lbl"] {{ color: {C['muted']}; font-size: 11px; letter-spacing: 1px; font-weight: 600; }}
QLabel[role="big"] {{ font-size: 24px; font-weight: 700; }}
QLabel[role="name"] {{ font-size: 20px; font-weight: 700; }}
QLabel[role="small"] {{ color: {C['muted']}; font-size: 12px; }}
QLabel[role="kvKey"] {{ color: {C['muted']}; font-size: 13px; }}
QLabel[role="kvVal"] {{ font-size: 13px; }}
QLabel[role="hint"] {{ color: {C['muted']}; font-size: 14px; }}

QFrame[role="card"] {{ background: {C['card']}; border: 1px solid {C['line']}; border-radius: 6px; }}
QFrame[role="card"][selected="true"] {{ border: 2px solid {C['accent']}; }}
QFrame[role="card"][tone="bad"] {{ border: 2px solid {C['bad']}; background: {C['bad_soft']}; }}
QFrame[role="iconBox"] {{ background: {C['accent_soft']}; border-radius: 8px; border: none; }}
QFrame[role="iconBox"][tone="bad"] {{ background: {C['card']}; }}

QLabel[role="pill"] {{ border-radius: 10px; padding: 3px 10px; font-size: 12px; font-weight: 600; }}
QFrame[role="banner"] {{ border-radius: 6px; }}
QFrame[role="card"][tone="bad"] QLabel[role="pill"] {{ background: #ffffff; border: 1px solid {C['bad']}; }}
QLabel[role="bannerTitle"] {{ font-size: 16px; font-weight: 700; }}
{pills}

QPushButton {{ font-size: 14px; font-weight: 600; padding: 10px 16px; border-radius: 5px;
    border: 1px solid {C['line']}; background: {C['card']}; color: {C['fg']}; }}
QPushButton:hover {{ border-color: {C['accent']}; }}
QPushButton:disabled {{ color: #a3adb6; background: #f3f5f7; border-color: {C['line']}; }}
QPushButton[size="xl"] {{ padding: 15px 22px; font-size: 16px; }}
QPushButton[kind="primary"] {{ background: {C['accent']}; border-color: {C['accent']}; color: #ffffff; }}
QPushButton[kind="primary"]:hover {{ background: #0c5165; }}
QPushButton[kind="go"] {{ background: {C['ok']}; border-color: {C['ok']}; color: #ffffff; }}
QPushButton[kind="danger"] {{ background: {C['bad']}; border-color: {C['bad']}; color: #ffffff; }}
QPushButton[kind="primary"]:disabled, QPushButton[kind="go"]:disabled, QPushButton[kind="danger"]:disabled {{
    background: #c7d0d8; border-color: #c7d0d8; color: #f3f5f7; }}

QProgressBar {{ background: {C['line']}; border: none; border-radius: 5px; height: 10px; max-height: 10px; }}
QProgressBar::chunk {{ background: {C['accent']}; border-radius: 5px; }}

QPlainTextEdit#log {{ background: {C['side']}; color: {C['side_fg']}; border: none; border-radius: 5px;
    padding: 8px; font-size: 12px; }}

QTableWidget {{ background: {C['card']}; border: none; gridline-color: {C['line']}; font-size: 13px;
    selection-background-color: {C['accent_soft']}; selection-color: {C['fg']}; }}
QTableWidget::item {{ border-bottom: 1px solid {C['line']}; padding: 4px 6px; }}
QHeaderView::section {{ background: {C['card']}; color: {C['muted']}; border: none;
    border-bottom: 1px solid {C['line']}; padding: 6px; font-size: 11px; font-weight: 600; }}
QDialog {{ background: {C['bg']}; }}

QLineEdit {{ background: {C['card']}; border: 1px solid {C['line']}; border-radius: 4px;
    padding: 7px 9px; font-size: 14px; selection-background-color: {C['accent_soft']}; selection-color: {C['fg']}; }}
QLineEdit:focus {{ border-color: {C['accent']}; }}
QLineEdit:disabled {{ color: {C['muted']}; background: #f3f5f7; }}
QCheckBox {{ font-size: 13px; spacing: 8px; }}
QListWidget#targets {{ background: {C['card']}; border: 1px solid {C['line']}; border-radius: 4px;
    font-size: 13px; outline: none; }}
QListWidget#targets::item {{ padding: 8px 8px; border-bottom: 1px solid {C['line']}; }}
QListWidget#targets::item:selected {{ background: {C['accent_soft']}; color: {C['fg']}; }}
QTreeWidget {{ background: {C['card']}; border: 1px solid {C['line']}; border-radius: 4px; font-size: 13px; }}
QRadioButton {{ font-size: 14px; spacing: 8px; }}
QComboBox {{ background: {C['card']}; border: 1px solid {C['line']}; border-radius: 4px; padding: 6px 9px;
    font-size: 14px; }}
QFrame[role="banner"] QLabel {{ font-size: 13px; }}
QLabel#toast {{ background: {C['side']}; color: #ffffff; border-radius: 6px; padding: 10px 16px;
    font-size: 14px; font-weight: 600; }}
"""
