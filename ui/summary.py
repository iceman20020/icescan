from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from icescan.core.types import ScanContext, Severity
from icescan.ui.theme import SEV_RICH, DIM, BORDER


def print_summary(console: Console, ctx: ScanContext, elapsed: float) -> None:
    counts = Counter(f.severity for f in ctx.findings)
    total = len(ctx.findings)

    lines = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        n = counts.get(sev, 0)
        if n == 0:
            continue
        bar = "█" * min(n, 30)
        style = SEV_RICH.get(sev, "white")
        lines.append(f"   [{style}]{sev.value.upper():<10}[/] {bar} {n}")

    lines.append("")
    lines.append(f"   [{DIM}]total:[/] {total} findings  ·  {ctx.client.requests_sent} requests  ·  {_fmt(elapsed)}")
    if ctx.cfg.output:
        lines.append(f"   [{DIM}]report →[/] {ctx.cfg.output}/index.html")

    body = Text.from_markup("\n".join(lines))
    console.print(Panel(body, title="scan complete", border_style=BORDER))


def _fmt(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    return f"{m:02d}:{s:02d}"
