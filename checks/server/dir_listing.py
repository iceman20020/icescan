from __future__ import annotations

from urllib.parse import urlparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

SIGS = ["Index of /", "<title>Index of", "Directory listing for", "[To Parent Directory]"]


class DirectoryListing(BaseCheck):
    name = "dir_listing"
    category = "server"
    level = 1
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        urls = set(ctx.crawled_urls or [])
        urls.add(ctx.cfg.target)

        checked_dirs: set[str] = set()
        for url in urls:
            u = urlparse(url)
            parts = u.path.rstrip("/").split("/")
            for i in range(1, len(parts) + 1):
                d = "/".join(parts[: i]) + "/"
                full = f"{u.scheme}://{u.netloc}{d}"
                if full in checked_dirs:
                    continue
                checked_dirs.add(full)
                r = await ctx.client.get(full)
                if r.error:
                    continue
                body = r.body or ""
                for sig in SIGS:
                    if sig.lower() in body.lower():
                        findings.append(self.finding(
                            severity=Severity.MEDIUM,
                            url=full, method="GET", param=None,
                            payload=None,
                            evidence={"signature": sig, "status": r.status},
                            confidence="high",
                        ))
                        break
        return findings
