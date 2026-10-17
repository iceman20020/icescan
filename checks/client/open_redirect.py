from __future__ import annotations

from urllib.parse import urlparse, parse_qs

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity
from icescan.core.surfaces import inject_into_url

PAYLOADS = [
    "https://icescan-probe.example/redirect",
    "//icescan-probe.example/redirect",
    "/\\icescan-probe.example",
    "https:icescan-probe.example",
    "////icescan-probe.example",
]

REDIRECT_HINTS = ["redirect", "url", "next", "return", "continue", "target", "goto", "dest", "destination", "callback", "redir", "out", "link"]


class OpenRedirect(BaseCheck):
    name = "open_redirect"
    category = "client"
    level = 2

    async def run_surface(self, ctx: ScanContext, surface: Surface) -> list[Finding]:
        if surface.kind != SurfaceKind.QUERY:
            return []
        if not any(h in surface.name.lower() for h in REDIRECT_HINTS):
            return []

        for payload in PAYLOADS:
            url = inject_into_url(surface.url, surface.name, payload)
            r = await ctx.client.get(url)
            if r.error:
                continue
            loc = r.header("Location")
            if loc and "icescan-probe.example" in loc:
                return [self.finding(
                    severity=Severity.MEDIUM,
                    url=url, method="GET", param=surface.name,
                    payload=payload,
                    evidence={"location": loc, "status": r.status},
                    confidence="high",
                )]
            if r.status in (301, 302, 303, 307, 308) and loc and "icescan-probe" in loc:
                return [self.finding(
                    severity=Severity.MEDIUM,
                    url=url, method="GET", param=surface.name,
                    payload=payload,
                    evidence={"location": loc},
                    confidence="medium",
                )]
        return []
