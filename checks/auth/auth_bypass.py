from __future__ import annotations

from urllib.parse import urlparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/users", "/admin/config", "/admin/settings",
    "/api/admin", "/api/v1/admin", "/api/users", "/internal", "/private",
    "/dashboard", "/manage", "/management", "/console", "/system",
]

BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
]

PROTECTED_HINTS = ["login", "unauthorized", "forbidden", "authentication required", "access denied"]


class AuthBypass(BaseCheck):
    name = "auth_bypass"
    category = "auth"
    level = 2
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        u = urlparse(ctx.cfg.target)
        root = f"{u.scheme}://{u.netloc}"
        findings: list[Finding] = []

        for path in ADMIN_PATHS:
            url = root + path
            bare = await ctx.client.get(url)
            if bare.error:
                continue
            if bare.status not in (401, 403) and "login" not in (bare.body or "").lower()[:500]:
                continue

            for hdrs in BYPASS_HEADERS:
                r = await ctx.client.get(url, headers=hdrs)
                if r.error:
                    continue
                body = (r.body or "").lower()
                if r.status == 200 and not any(h in body for h in PROTECTED_HINTS):
                    findings.append(self.finding(
                        severity=Severity.CRITICAL,
                        url=url, method="GET", param=list(hdrs.keys())[0],
                        payload=str(hdrs),
                        evidence={"bypass_headers": hdrs, "status": r.status, "snippet": body[:200]},
                        confidence="medium",
                    ))
                    break
        return findings
