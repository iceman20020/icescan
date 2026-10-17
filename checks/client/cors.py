from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity


class CORS(BaseCheck):
    name = "cors"
    category = "client"
    level = 1
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        probe_origin = "https://icescan-cors.example"
        findings: list[Finding] = []

        r = await ctx.client.get(ctx.cfg.target, headers={"Origin": probe_origin})
        if r.error:
            return []

        acao = r.header("Access-Control-Allow-Origin").strip()
        acac = r.header("Access-Control-Allow-Credentials").strip().lower()

        if acao == "*" and acac == "true":
            findings.append(self.finding(
                severity=Severity.HIGH,
                url=ctx.cfg.target, method="GET", param=None,
                payload="Origin: " + probe_origin,
                evidence={"acao": acao, "acac": acac},
                confidence="high",
                note="wildcard acao with credentials (browsers block but indicates misconfig)",
            ))
        elif acao == probe_origin:
            sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
            findings.append(self.finding(
                severity=sev,
                url=ctx.cfg.target, method="GET", param=None,
                payload="Origin: " + probe_origin,
                evidence={"acao": acao, "acac": acac, "reflected": True},
                confidence="high",
                note="origin reflected back in acao",
            ))
        elif acao == "null":
            findings.append(self.finding(
                severity=Severity.MEDIUM,
                url=ctx.cfg.target, method="GET", param=None,
                payload="Origin: null",
                evidence={"acao": acao},
                confidence="medium",
            ))
        return findings
