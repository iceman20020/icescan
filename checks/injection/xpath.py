from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity
from icescan.core.surfaces import inject_into_url, inject_into_form

PAYLOADS = [
    "' or '1'='1",
    "' or ''='",
    "x' or 1=1 or 'x'='x",
    "'] | //* | //*['",
    "1 or count(/*)>0",
]

ERROR_SIGS = ["XPathException", "XPath syntax error", "unterminated literal", "javax.xml.xpath"]


class XPathInjection(BaseCheck):
    name = "xpath"
    category = "injection"
    level = 3

    async def run_surface(self, ctx, surface):
        for payload in PAYLOADS:
            r = await self._send(ctx, surface, payload)
            if r is None or r.error:
                continue
            body = r.body or ""
            for sig in ERROR_SIGS:
                if sig.lower() in body.lower():
                    return [self.finding(
                        severity=Severity.HIGH,
                        url=r.url, method=surface.method, param=surface.name,
                        payload=payload,
                        evidence={"signature": sig},
                        confidence="medium",
                    )]
        return []

    async def _send(self, ctx, surface, payload):
        if surface.kind == SurfaceKind.QUERY:
            return await ctx.client.get(inject_into_url(surface.url, surface.name, payload))
        if surface.kind == SurfaceKind.BODY_FORM:
            fields = surface.extra.get("all_fields", [surface.name])
            return await ctx.client.request(surface.method, surface.url, data=inject_into_form(fields, surface.name, payload))
        return None
