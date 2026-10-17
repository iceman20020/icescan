from __future__ import annotations

from urllib.parse import urlparse, parse_qs

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity
from icescan.core.surfaces import inject_into_url

ID_HINTS = ("user", "userid", "user_id", "uid", "account", "account_id", "member", "customer")


class HorizontalPrivesc(BaseCheck):
    name = "horiz_privesc"
    category = "access"
    level = 3

    async def run_surface(self, ctx: ScanContext, surface: Surface) -> list[Finding]:
        if surface.kind != SurfaceKind.QUERY:
            return []
        if not any(h in surface.name.lower() for h in ID_HINTS):
            return []

        u = urlparse(surface.url)
        params = parse_qs(u.query)
        val = params.get(surface.name, [""])[0]
        if not val:
            return []

        base = await ctx.client.get(surface.url)
        if base.error or base.status >= 400:
            return []

        for probe in (val + "x", "admin", "1", "0", "99999999"):
            if probe == val:
                continue
            test_url = inject_into_url(surface.url, surface.name, probe)
            r = await ctx.client.get(test_url)
            if r.error or r.status != base.status:
                continue
            sim = ctx.detector.similarity(base.body, r.body)
            if sim < 0.5 and r.length > 200:
                return [self.finding(
                    severity=Severity.MEDIUM,
                    url=test_url, method="GET", param=surface.name,
                    payload=probe,
                    evidence={"similarity": round(sim, 3), "status": r.status, "length": r.length},
                    confidence="low",
                    note="user id param returns different content, verify it belongs to another account",
                )]
        return []
