from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity


class Clickjacking(BaseCheck):
    name = "clickjacking"
    category = "client"
    level = 1
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        r = await ctx.client.get(ctx.cfg.target)
        if r.error:
            return []

        xfo = r.header("X-Frame-Options").strip().lower()
        csp = r.header("Content-Security-Policy").lower()

        xfo_ok = xfo in ("deny", "sameorigin") or xfo.startswith("allow-from")
        csp_ok = "frame-ancestors" in csp and ("'none'" in csp or "'self'" in csp)

        if xfo_ok or csp_ok:
            return []

        return [self.finding(
            severity=Severity.MEDIUM,
            url=ctx.cfg.target, method="GET", param=None,
            payload=None,
            evidence={"x-frame-options": xfo or None, "csp-frame-ancestors": "frame-ancestors" in csp},
            confidence="high",
        )]
