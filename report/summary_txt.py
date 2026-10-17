from __future__ import annotations

from collections import Counter
from pathlib import Path

from icescan import __version__
from icescan.core.types import ScanContext, Severity


def write_summary(ctx: ScanContext, path: Path, scan_id: str) -> None:
    counts = Counter(f.severity for f in ctx.findings)
    lines = [
        f"icescan v{__version__} — crafted by iceman",
        f"scan id: {scan_id}",
        f"target:  {ctx.cfg.target}",
        f"level:   {ctx.cfg.level}",
        "",
        "summary:",
    ]
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        n = counts.get(sev, 0)
        if n:
            lines.append(f"  {sev.value.upper():<10} {n}")
    lines.append(f"  total      {len(ctx.findings)}")
    lines.append("")
    lines.append("findings:")
    for f in sorted(ctx.findings, key=lambda x: -x.severity.rank):
        lines.append(f"  [{f.severity.value.upper():<8}] {f.check:<24} {f.method:<5} {f.url}")
    path.write_text("\n".join(lines))
