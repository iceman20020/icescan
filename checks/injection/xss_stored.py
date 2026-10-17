from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity
from icescan.core.surfaces import inject_into_form


class StoredXSS(BaseCheck):
    name = "xss_stored"
    category = "injection"
    level = 3

    async def run_surface(self, ctx: ScanContext, surface: Surface) -> list[Finding]:
        if surface.kind != SurfaceKind.BODY_FORM:
            return []
        if not ctx.cfg.second_order_url:
            return []

        payload = "<svg/onload=alert('icescan')>"
        fields = surface.extra.get("all_fields", [surface.name])
        data = inject_into_form(fields, surface.name, payload)

        submit = await ctx.client.request(surface.method, surface.url, data=data)
        if submit is None or submit.error:
            return []

        check = await ctx.client.get(ctx.cfg.second_order_url)
        if check.error:
            return []

        if payload in (check.body or ""):
            return [self.finding(
                severity=Severity.HIGH,
                url=ctx.cfg.second_order_url, method="GET", param=None,
                payload=payload,
                evidence={
                    "stored_at": surface.url,
                    "triggered_at": ctx.cfg.second_order_url,
                    "field": surface.name,
                },
                confidence="medium",
                note="stored payload reflected on trigger endpoint",
            )]
        return []
