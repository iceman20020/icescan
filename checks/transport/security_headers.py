from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

REQUIRED = [
    ("strict-transport-security", "HSTS missing", Severity.MEDIUM, "https"),
    ("content-security-policy", "CSP missing", Severity.MEDIUM, None),
    ("x-content-type-options", "X-Content-Type-Options missing", Severity.LOW, None),
    ("referrer-policy", "Referrer-Policy missing", Severity.LOW, None),
    ("permissions-policy", "Permissions-Policy missing", Severity.INFO, None),
    ("x-frame-options", "X-Frame-Options missing", Severity.LOW, None),
]


class SecurityHeaders(BaseCheck):
    name = "security_headers"
    category = "transport"
    level = 1
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        r = await ctx.client.get(ctx.cfg.target)
        if r.error:
            return []

        findings: list[Finding] = []
        present = {k.lower() for k in r.headers.keys()}
        is_https = ctx.cfg.target.startswith("https://")

        for hname, msg, sev, requires in REQUIRED:
            if requires == "https" and not is_https:
                continue
            if hname in present:
                continue
            findings.append(self.finding(
                severity=sev,
                url=ctx.cfg.target, method="GET", param=hname,
                payload=None,
                evidence={"missing_header": hname},
                confidence="high",
                note=msg,
            ))
        return findings
