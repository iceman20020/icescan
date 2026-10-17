from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity

PAYLOADS = [
    "icescan\r\nX-Injected: yes",
    "icescan%0d%0aX-Injected: yes",
    "icescan\nSet-Cookie: icescan=1",
]


class HeaderInjection(BaseCheck):
    name = "header_injection"
    category = "injection"
    level = 3
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for payload in PAYLOADS:
            r = await ctx.client.get(ctx.cfg.target, headers={"X-Forwarded-Host": payload})
            if r.error:
                continue
            if "x-injected" in {k.lower() for k in r.headers}:
                findings.append(self.finding(
                    severity=Severity.HIGH,
                    url=ctx.cfg.target, method="GET", param="X-Forwarded-Host",
                    payload=payload,
                    evidence={"headers": {k: v for k, v in r.headers.items() if "injected" in k.lower()}},
                    confidence="high",
                ))
                break
        return findings
