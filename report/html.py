from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from icescan import __version__
from icescan.core.types import ScanContext, Severity

TPL_DIR = Path(__file__).resolve().parent / "templates"


def write_html(ctx: ScanContext, path: Path, scan_id: str) -> None:
    env = Environment(
        loader=FileSystemLoader(str(TPL_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    tpl = env.get_template("index.html.j2")

    counts = Counter(f.severity for f in ctx.findings)
    by_cat = defaultdict(int)
    for f in ctx.findings:
        by_cat[f.category] += 1

    styles = (TPL_DIR / "styles.css").read_text()
    script = (TPL_DIR / "report.js").read_text()

    html = tpl.render(
        version=__version__,
        scan_id=scan_id,
        target=ctx.cfg.target,
        level=ctx.cfg.level,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        stats={
            "findings": len(ctx.findings),
            "critical": counts.get(Severity.CRITICAL, 0),
            "high": counts.get(Severity.HIGH, 0),
            "medium": counts.get(Severity.MEDIUM, 0),
            "low": counts.get(Severity.LOW, 0),
            "info": counts.get(Severity.INFO, 0),
            "crawled": len(ctx.crawled_urls),
            "surfaces": len(ctx.surfaces),
            "requests": ctx.client.requests_sent,
            "errors": ctx.client.errors,
        },
        severity_counts={
            "critical": counts.get(Severity.CRITICAL, 0),
            "high": counts.get(Severity.HIGH, 0),
            "medium": counts.get(Severity.MEDIUM, 0),
            "low": counts.get(Severity.LOW, 0),
            "info": counts.get(Severity.INFO, 0),
        },
        category_counts=dict(by_cat),
        findings=sorted(ctx.findings, key=lambda f: -f.severity.rank),
        recon=ctx.recon,
        styles=styles,
        script=script,
    )
    path.write_text(html)
