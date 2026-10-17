from __future__ import annotations

from icescan.core.types import Severity

SEV_COLOR = {
    Severity.CRITICAL: "#ff3b5c",
    Severity.HIGH: "#ff6b3b",
    Severity.MEDIUM: "#ffb020",
    Severity.LOW: "#3b9eff",
    Severity.INFO: "#6b7280",
}

SEV_RICH = {
    Severity.CRITICAL: "bold #ff3b5c",
    Severity.HIGH: "bold #ff6b3b",
    Severity.MEDIUM: "#ffb020",
    Severity.LOW: "#3b9eff",
    Severity.INFO: "dim #6b7280",
}

BRAND = "#ff3b5c"
ACCENT = "#3b9eff"
DIM = "#8b90a0"
BG = "#0a0b0f"
PANEL = "#12141a"
BORDER = "#1f2330"
TEXT = "#e6e8ee"


def sev_style(sev: Severity) -> str:
    return SEV_RICH.get(sev, "white")
