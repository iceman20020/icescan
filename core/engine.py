from __future__ import annotations

import time
import uuid

from icescan.core.types import ScanContext, Finding, Severity
from icescan.core.http_client import HttpClient
from icescan.core.crawler import Crawler
from icescan.core.recon import run_recon
from icescan.core.surfaces import build_surfaces
from icescan.core.baseline import BaselineCache
from icescan.core.detector import Detector
from icescan.core.checkpoint import Checkpoint
from icescan.core.oob_server import OobListener
from icescan.checks.registry import load_checks


async def run_scan(cfg, console) -> int:
    start = time.time()
    scan_id = uuid.uuid4().hex[:12]

    detector = Detector()
    checkpoint = Checkpoint(cfg.checkpoint)
    oob = None
    if cfg.oob_listen:
        oob = OobListener(port=cfg.oob_port)
        await oob.start()

    try:
        async with HttpClient(cfg, console) as client:
            ctx = ScanContext(
                cfg=cfg,
                client=client,
                console=console,
                baseline=BaselineCache(client),
                detector=detector,
                oob_server=oob,
                start_time=start,
            )
            ctx.recon = await run_recon(client, cfg.target)
            ctx.waf_detected = ctx.recon.get("waf")

            if cfg.crawl:
                crawler = Crawler(cfg, client, console)
                ctx.crawled_urls = await crawler.crawl(cfg.target)
                ctx.surfaces = build_surfaces(ctx.crawled_urls, crawler.all_surfaces())
            else:
                ctx.surfaces = build_surfaces([cfg.target], [])

            checks = load_checks(cfg)
            for chk in checks:
                if checkpoint.is_done(f"{chk.name}:start"):
                    continue
                try:
                    results = await chk.execute(ctx)
                    for f in results:
                        f.timestamp = time.time()
                        ctx.add_finding(f)
                except Exception as e:
                    console.log(f"check {chk.name} failed: {e}")
                checkpoint.mark_done(f"{chk.name}:start")

            from icescan.report.html import write_html
            from icescan.report.json_out import write_json
            from icescan.report.sarif import write_sarif
            from icescan.report.summary_txt import write_summary
            from icescan.ui.summary import print_summary

            cfg.output.mkdir(parents=True, exist_ok=True)
            if "json" in cfg.formats:
                write_json(ctx, cfg.output / "findings.json", scan_id)
            if "html" in cfg.formats:
                write_html(ctx, cfg.output / "index.html", scan_id)
            if "sarif" in cfg.formats:
                write_sarif(ctx, cfg.output / "findings.sarif")
            if "txt" in cfg.formats:
                write_summary(ctx, cfg.output / "summary.txt", scan_id)

            print_summary(console, ctx, elapsed=time.time() - start)
            return 0
    finally:
        if oob:
            await oob.stop()
