from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity


class CookieFlags(BaseCheck):
    name = "cookie_flags"
    category = "auth"
    level = 1
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        r = await ctx.client.get(ctx.cfg.target)
        if r.error:
            return []

        findings: list[Finding] = []
        seen: set[str] = set()

        for hk, hv in r.headers.items():
            if hk.lower() != "set-cookie":
                continue
            for raw in hv.split(","):
                cookie = raw.strip()
                if not cookie:
                    continue
                name = cookie.split("=")[0].strip()
                if name in seen:
                    continue
                seen.add(name)

                lc = cookie.lower()
                issues = []
                if "httponly" not in lc:
                    issues.append("httponly")
                if "secure" not in lc:
                    issues.append("secure")
                if "samesite" not in lc:
                    issues.append("samesite")

                if not issues:
                    continue

                sev = Severity.MEDIUM if "secure" in issues or "httponly" in issues else Severity.LOW
                findings.append(self.finding(
                    severity=sev,
                    url=ctx.cfg.target, method="GET", param=name,
                    payload=None,
                    evidence={"cookie": name, "missing": issues, "raw": cookie[:200]},
                    confidence="high",
                ))
        return findings
