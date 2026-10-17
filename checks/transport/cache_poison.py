from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

PROBE = "icescan-poison.example"


class CachePoison(BaseCheck):
    name = "cache_poison"
    category = "transport"
    level = 3
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        r1 = await ctx.client.get(ctx.cfg.target, headers={"X-Forwarded-Host": PROBE})
        r2 = await ctx.client.get(ctx.cfg.target)
        if r1.error or r2.error:
            return []

        if PROBE in (r1.body or "") and PROBE in (r2.body or ""):
            findings.append(self.finding(
                severity=Severity.HIGH,
                url=ctx.cfg.target, method="GET", param="X-Forwarded-Host",
                payload=PROBE,
                evidence={"reflected_in_cache": True, "first_len": r1.length, "second_len": r2.length},
                confidence="medium",
                note="x-forwarded-host value persisted into next response, cache poisoning candidate",
            ))

        r3 = await ctx.client.get(ctx.cfg.target, headers={"X-Forwarded-Scheme": "http"})
        if not r3.error and r3.header("Location").startswith("http://"):
            findings.append(self.finding(
                severity=Severity.MEDIUM,
                url=ctx.cfg.target, method="GET", param="X-Forwarded-Scheme",
                payload="http",
                evidence={"location": r3.header("Location")},
                confidence="medium",
            ))
        return findings
