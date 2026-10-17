from __future__ import annotations

from dataclasses import dataclass, field

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn
from rich.table import Table

from icescan.core.types import Finding, Severity
from icescan.ui.theme import SEV_RICH, DIM, BORDER


@dataclass
class LiveState:
    target: str = ""
    server: str = ""
    tech: list[str] = field(default_factory=list)
    waf: str = ""

    crawl_pct: float = 0.0
    inject_pct: float = 0.0
    checks_done: int = 0
    checks_total: int = 0

    recent: list[Finding] = field(default_factory=list)

    requests: int = 0
    errors: int = 0
    elapsed: float = 0.0


class LiveUI:
    def __init__(self, console: Console):
        self.console = console
        self.state = LiveState()
        self._live: Live | None = None

    def __enter__(self) -> "LiveUI":
        self._live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=6,
            transient=False,
        )
        self._live.__enter__()
        return self

    def __exit__(self, *exc) -> None:
        if self._live:
            self._live.update(self._render())
            self._live.__exit__(*exc)

    def _render(self):
        return Group(
            self._render_target(),
            self._render_progress(),
            self._render_findings(),
            self._render_footer(),
        )

    def _render_target(self):
        body = (
            f"[bold]{self.state.target or '—'}[/bold]\n"
            f"[{DIM}]server:[/] {self.state.server or '—'}\n"
            f"[{DIM}]tech:[/] {', '.join(self.state.tech) or '—'}\n"
            f"[{DIM}]waf:[/] {self.state.waf or '—'}"
        )
        return Panel(body, title="target", border_style=BORDER)

    def _render_progress(self):
        crawl = Progress(
            TextColumn("[dim]crawl[/]"),
            BarColumn(bar_width=28),
            TextColumn("[dim]{task.percentage:>3.0f}%[/]"),
        )
        t1 = crawl.add_task("crawl", total=100, completed=self.state.crawl_pct)

        inject = Progress(
            TextColumn("[dim]checks[/]"),
            BarColumn(bar_width=28),
            TextColumn(f"{self.state.checks_done}/{self.state.checks_total}"),
        )
        t2 = inject.add_task("checks", total=max(self.state.checks_total, 1), completed=self.state.checks_done)

        return Panel(Group(crawl, inject), title="progress", border_style=BORDER)

    def _render_findings(self):
        table = Table(show_header=True, header_style=f"bold {DIM}", border_style=BORDER, expand=True)
        table.add_column("sev", width=9)
        table.add_column("check", width=22)
        table.add_column("url", overflow="fold")
        table.add_column("info", overflow="fold")
        table.add_column("t", width=6, justify="right")

        for f in self.state.recent[-10:]:
            style = SEV_RICH.get(f.severity, "white")
            info = ""
            if f.evidence:
                info = str(list(f.evidence.keys()))[:60]
            table.add_row(
                f"[{style}]{f.severity.value.upper()}[/]",
                f.check,
                f.url[:80],
                info,
                f"{f.timestamp - (f.timestamp - 0.0):.2f}" if f.timestamp else "",
            )
        return Panel(table, title="live findings", border_style=BORDER)

    def _render_footer(self):
        return Panel(
            f"[{DIM}]requests:[/] {self.state.requests}   "
            f"[{DIM}]errors:[/] {self.state.errors}   "
            f"[{DIM}]elapsed:[/] {int(self.state.elapsed):02d}:{int(self.state.elapsed % 60):02d}   "
            f"[{DIM}]ctrl-c to stop[/]",
            border_style=BORDER,
        )

    def update(self, **kw) -> None:
        for k, v in kw.items():
            setattr(self.state, k, v)
        if self._live:
            self._live.update(self._render())

    def add_finding(self, f: Finding) -> None:
        self.state.recent.append(f)
        if self._live:
            self._live.update(self._render())
