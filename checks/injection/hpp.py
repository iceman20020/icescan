from __future__ import annotations

from urllib.parse import urlparse, urlencode, urlunparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity


class HTTPParamPollution(BaseCheck):
    name = "hpp"
    category = "injection"
    level = 2

    async def run_surface(self, ctx, surface):
        if surface.kind != SurfaceKind.QUERY:
            return []
        u = urlparse(surface.url)
        if not u.query:
            return []
        polluted = u.query + "&" + urlencode({surface.name: "icescan_dup"})
        new_url = urlunparse((u.scheme, u.netloc, u.path, u.params, polluted, u.fragment))
        r = await ctx.client.get(new_url)
        if r.error:
            return []
        if r.length and abs(r.length - 0) and r.status < 500:
            if "icescan_dup" in (r.body or ""):
                return [self.finding(
                    severity=Severity.LOW,
                    url=new_url, method="GET", param=surface.name,
                    payload="duplicate parameter",
                    evidence={"status": r.status, "length": r.length},
                    confidence="low",
                    note="server accepted duplicate parameter, may be exploitable",
                )]
        return []
