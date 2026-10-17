from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity
from icescan.core.surfaces import inject_into_url

LFI_HINTS = ("file", "page", "path", "load", "include", "template", "url", "src")


class RFI(BaseCheck):
    name = "rfi"
    category = "server"
    level = 3

    async def run_surface(self, ctx, surface):
        if surface.kind != SurfaceKind.QUERY:
            return []
        if not any(h in surface.name.lower() for h in LFI_HINTS):
            return []

        if ctx.oob_server:
            token = ctx.oob_server.new_token("rfi")
            host = ctx.cfg.oob_host or f"127.0.0.1:{ctx.cfg.oob_port}"
            payload = f"http://{host}/{token}"
            url = inject_into_url(surface.url, surface.name, payload)
            await ctx.client.get(url)
            hit = await ctx.oob_server.wait_for_async(token, timeout=4.0)
            if hit:
                return [self.finding(
                    severity=Severity.CRITICAL,
                    url=url, method="GET", param=surface.name,
                    payload=payload,
                    evidence={"oob_token": token, "hit": True},
                    confidence="high",
                )]

        if ctx.cfg.oob_host:
            token = "rfi_" + __import__("secrets").token_hex(4)
            payload = f"http://{ctx.cfg.oob_host}/{token}"
            url = inject_into_url(surface.url, surface.name, payload)
            r = await ctx.client.get(url)
            if not r.error and "icescan" in (r.body or "")[:500].lower():
                return [self.finding(
                    severity=Severity.MEDIUM,
                    url=url, method="GET", param=surface.name,
                    payload=payload,
                    evidence={"external_host": ctx.cfg.oob_host},
                    confidence="low",
                )]
        return []
