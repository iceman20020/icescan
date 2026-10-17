from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

DATA = Path(__file__).resolve().parent.parent.parent / "data" / "wordlists"

EXTRA_PATHS = [
    "/admin", "/backup", "/backups", "/config", "/db", "/debug",
    "/internal", "/private", "/staging", "/test", "/dev", "/api/v1",
    "/api/internal", "/robots.txt", "/sitemap.xml", "/.git/", "/.env",
    "/actuator", "/metrics", "/health", "/status", "/swagger",
    "/swagger.json", "/openapi.json", "/api-docs",
]

SIGS_DENY = ["not found", "404", "forbidden", "unauthorized", "login"]


class ForcedBrowsing(BaseCheck):
    name = "forced_browsing"
    category = "access"
    level = 1
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        u = urlparse(ctx.cfg.target)
        root = f"{u.scheme}://{u.netloc}"

        baseline_url = root + "/icescan_random_" + __import__("secrets").token_hex(4)
        base_r = await ctx.client.get(baseline_url)
        baseline_status = base_r.status if not base_r.error else 404
        baseline_body = (base_r.body or "")[:200].lower() if not base_r.error else ""

        wordlist_path = DATA / "paths.txt"
        paths = list(EXTRA_PATHS)
        if wordlist_path.exists():
            for line in wordlist_path.read_text().splitlines()[:500]:
                line = line.strip()
                if line and not line.startswith("#"):
                    paths.append("/" + line.lstrip("/"))

        findings: list[Finding] = []
        for path in dict.fromkeys(paths):
            url = root + path
            r = await ctx.client.get(url)
            if r.error:
                continue
            if r.status == baseline_status:
                continue
            if r.status >= 400:
                continue
            body = (r.body or "")[:200].lower()
            if body and baseline_body and ctx.detector.similarity(body, baseline_body) > 0.9:
                continue
            if any(s in body for s in SIGS_DENY):
                continue
            findings.append(self.finding(
                severity=Severity.LOW,
                url=url, method="GET", param=None,
                payload=path,
                evidence={"status": r.status, "length": r.length},
                confidence="low",
            ))
        return findings
