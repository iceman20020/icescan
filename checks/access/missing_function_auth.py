from __future__ import annotations

from urllib.parse import urlparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

ADMIN_PATTERNS = ("/admin", "/manage", "/internal", "/private", "/superuser", "/root", "/api/admin")
PROTECTED_STATUSES = (401, 403)
LOGIN_HINTS = ["type=\"password\"", "login", "sign in", "authentication required"]


class MissingFunctionAuth(BaseCheck):
    name = "missing_function_auth"
    category = "access"
    level = 2
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        urls = list(set(ctx.crawled_urls or []))
        urls.append(ctx.cfg.target)

        for url in urls:
            path = urlparse(url).path.lower()
            if not any(p in path for p in ADMIN_PATTERNS):
                continue
            r = await ctx.client.get(url)
            if r.error:
                continue
            if r.status in PROTECTED_STATUSES:
                continue
            body = (r.body or "").lower()[:2000]
            if any(h in body for h in LOGIN_HINTS):
                continue
            findings.append(self.finding(
                severity=Severity.MEDIUM,
                url=url, method="GET", param=None,
                payload=None,
                evidence={"status": r.status, "path": path},
                confidence="low",
                note="admin-looking path reachable without auth",
            ))
        return findings
