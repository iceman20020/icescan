from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity
from icescan.core.surfaces import inject_into_url, inject_into_form

PAYLOADS = [
    ("{{7*7}}", "49", "jinja2/twig"),
    ("${7*7}", "49", "freemarker/spring"),
    ("#{7*7}", "49", "ruby/erb"),
    ("<%= 7*7 %>", "49", "erb/ejs"),
    ("{7*7}", "49", "smarty"),
    ("{{7*'7'}}", "7777777", "jinja2"),
    ("${7*7}${7*7}", "4949", "freemarker"),
    ("a{*comment*}b", "ab", "smarty"),
]


class SSTI(BaseCheck):
    name = "ssti"
    category = "injection"
    level = 2

    async def run_surface(self, ctx, surface):
        for payload, expected, engine in PAYLOADS:
            r = await self._send(ctx, surface, payload)
            if r is None or r.error:
                continue
            body = r.body or ""
            if expected in body and payload not in body:
                return [self.finding(
                    severity=Severity.CRITICAL,
                    url=r.url, method=surface.method, param=surface.name,
                    payload=payload,
                    evidence={"rendered": expected, "engine": engine},
                    confidence="high",
                )]
        return []

    async def _send(self, ctx, surface, payload):
        if surface.kind == SurfaceKind.QUERY:
            return await ctx.client.get(inject_into_url(surface.url, surface.name, payload))
        if surface.kind == SurfaceKind.BODY_FORM:
            fields = surface.extra.get("all_fields", [surface.name])
            return await ctx.client.request(surface.method, surface.url, data=inject_into_form(fields, surface.name, payload))
        return None
