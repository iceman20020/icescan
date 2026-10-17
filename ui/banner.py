from __future__ import annotations

from rich.console import Console
from rich.text import Text

from icescan import __version__, __author__, __description__
from icescan.ui.theme import BRAND, ACCENT, DIM, BORDER

WORDMARK = r"""
  ██████╗ ██╗   ██╗██╗     ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔════╝ ██║   ██║██║     ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ███████╗ ██║   ██║██║     ██║    ███████╗██║     ███████║██╔██╗ ██║
 ╚════██║ ██║   ██║██║     ██║    ╚════██║██║     ██╔══██║██║╚██╗██║
 ███████║ ╚██████╔╝███████╗██║    ███████║╚██████╗██║  ██║██║ ╚████║
 ╚══════╝  ╚═════╝ ╚══════╝╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""

TAGLINE = f"{__description__}  ·  v{__version__}"
DIVIDER = "─────────────────────"
CREDIT  = ("crafted by ", __author__)


def print_banner(console: Console, quiet: bool = False, no_color: bool = False) -> None:
    if quiet:
        return
    if no_color:
        console.print(WORDMARK)
        console.print(f"\n              {TAGLINE}\n                    {DIVIDER}\n                        {CREDIT[0]}{CREDIT[1]}\n")
        return

    console.print(Text(WORDMARK, style=f"bold {BRAND}"))
    t = Text()
    t.append("\n              ")
    t.append(TAGLINE, style=f"dim {DIM}")
    t.append("\n                    ")
    t.append(DIVIDER, style=BORDER)
    t.append("\n                        ")
    t.append(CREDIT[0], style=f"dim {DIM}")
    t.append(CREDIT[1], style=f"bold {ACCENT}")
    t.append("\n")
    console.print(t)
