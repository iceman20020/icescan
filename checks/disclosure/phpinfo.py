from __future__ import annotations

from urllib.parse import urlparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

PATHS = ["/phpinfo.php", "/info.php", "/test.php", "/php.php", "/i.php", "/phpinfo"]
SIGS = ["PHP Version", "php.ini", "allow_url_fopen", "display_errors", "Loaded Configuration File"]


class Phpinfo(BaseCheck):
    name = "phpinfo"
    category = "disclosure"
    level = 1
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        u = urlparse(ctx.cfg.target)
        root = f"{u.scheme}://{u.netloc}"
        findings: list[Finding] = []

        for path in PATHS:
            url = root + path
            r = await ctx.client.get(url)
            if r.error or r.status >= 400:
                continue
            body = r.body or ""
            matched = [s for s in SIGS if s in body]
            if len(matched) >= 2:
                findings.append(self.finding(
                    severity=Severity.HIGH,
                    url=url, method="GET", param=None,
                    payload=None,
                    evidence={"signatures": matched, "status": r.status},
                    confidence="high",
                ))
        return findings
