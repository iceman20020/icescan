from __future__ import annotations

import time

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity
from icescan.core.surfaces import inject_into_url, inject_into_form

PAYLOADS = [
    ";sleep 3",
    "|sleep 3",
    "&sleep 3",
    "`sleep 3`",
    "$(sleep 3)",
    "|| sleep 3",
    "&& sleep 3",
    "%0asleep 3",
]


class CommandInjection(BaseCheck):
    name = "cmd_injection"
    category = "injection"
    level = 3

    async def run_surface(self, ctx: ScanContext, surface: Surface) -> list[Finding]:
        for payload in PAYLOADS:
            t0 = time.monotonic()
            r = await self._send(ctx, surface, payload)
            if r is None or r.error:
                continue
            elapsed = time.monotonic() - t0
            if elapsed > 2.1:
                return [self.finding(
                    severity=Severity.CRITICAL,
                    url=r.url, method=surface.method, param=surface.name,
                    payload=payload,
                    evidence={"elapsed": round(elapsed, 2)},
                    confidence="medium",
                )]
        return []

    async def _send(self, ctx, surface, payload):
        if surface.kind == SurfaceKind.QUERY:
            url = inject_into_url(surface.url, surface.name, payload)
            return await ctx.client.get(url)
        if surface.kind == SurfaceKind.BODY_FORM:
            fields = surface.extra.get("all_fields", [surface.name])
            data = inject_into_form(fields, surface.name, payload)
            return await ctx.client.request(surface.method, surface.url, data=data)
        return None
