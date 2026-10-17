from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

PROBE_HOST = "icescan-probe.example"


class HostHeader(BaseCheck):
    name = "host_header"
    category = "transport"
    level = 2
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for hdrs in (
            {"Host": PROBE_HOST},
            {"X-Forwarded-Host": PROBE_HOST},
            {"X-Forwarded-Server": PROBE_HOST},
        ):
            r = await ctx.client.get(ctx.cfg.target, headers=hdrs)
            if r.error:
                continue
            loc = r.header("Location")
            if loc and PROBE_HOST in loc:
                findings.append(self.finding(
                    severity=Severity.HIGH,
                    url=ctx.cfg.target, method="GET", param=list(hdrs.keys())[0],
                    payload=str(hdrs),
                    evidence={"header": hdrs, "location": loc, "status": r.status},
                    confidence="high",
                    note="host header reflected in redirect (password reset poisoning risk)",
                ))
                break
            if PROBE_HOST in (r.body or ""):
                findings.append(self.finding(
                    severity=Severity.MEDIUM,
                    url=ctx.cfg.target, method="GET", param=list(hdrs.keys())[0],
                    payload=str(hdrs),
                    evidence={"header": hdrs, "reflected": True},
                    confidence="medium",
                ))
                break
        return findings
