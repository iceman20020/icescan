from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

RISKY = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]


class HTTPMethods(BaseCheck):
    name = "http_methods"
    category = "transport"
    level = 1
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        r = await ctx.client.options(ctx.cfg.target)
        allow = r.header("Allow") or r.header("Access-Control-Allow-Methods")

        if allow:
            methods = [m.strip().upper() for m in allow.split(",")]
            for m in RISKY:
                if m in methods:
                    findings.append(self.finding(
                        severity=Severity.MEDIUM if m in ("PUT", "DELETE") else Severity.LOW,
                        url=ctx.cfg.target, method="OPTIONS", param=m,
                        payload=None,
                        evidence={"allow": allow},
                        confidence="high",
                    ))

        trace = await ctx.client.request("TRACE", ctx.cfg.target)
        if not trace.error and trace.status == 200 and "TRACE" in (trace.body or "")[:200]:
            findings.append(self.finding(
                severity=Severity.MEDIUM,
                url=ctx.cfg.target, method="TRACE", param=None,
                payload=None,
                evidence={"status": trace.status},
                confidence="high",
                note="TRACE method echoes request (cross-site tracing risk)",
            ))
        return findings
