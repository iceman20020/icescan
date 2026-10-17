from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity
from icescan.core.surfaces import inject_into_url, inject_into_form

PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "\"><svg onload=confirm(1)>",
]

MARKER = "icescan_xss_marker_"


class ReflectedXSS(BaseCheck):
    name = "xss_reflected"
    category = "injection"
    level = 2

    async def run_surface(self, ctx: ScanContext, surface: Surface) -> list[Finding]:
        findings: list[Finding] = []
        for payload in PAYLOADS:
            r = await self._send(ctx, surface, payload)
            if r is None or r.error or r.status >= 500:
                continue
            body = r.body or ""
            if payload in body:
                severity = Severity.HIGH if "<script" in payload or "onerror" in payload or "onload" in payload else Severity.MEDIUM
                findings.append(self.finding(
                    severity=severity,
                    url=r.url, method=surface.method, param=surface.name,
                    payload=payload,
                    evidence={"context": self._context(body, payload), "status": r.status},
                    confidence="high",
                ))
                break
        return findings

    async def _send(self, ctx, surface, payload):
        if surface.kind == SurfaceKind.QUERY:
            url = inject_into_url(surface.url, surface.name, payload)
            return await ctx.client.get(url)
        if surface.kind == SurfaceKind.BODY_FORM:
            fields = surface.extra.get("all_fields", [surface.name])
            data = inject_into_form(fields, surface.name, payload)
            return await ctx.client.request(surface.method, surface.url, data=data)
        return None

    def _context(self, body: str, payload: str, width: int = 160) -> str:
        idx = body.find(payload)
        if idx == -1:
            return ""
        s = max(0, idx - 60)
        e = min(len(body), idx + width)
        return body[s:e]
