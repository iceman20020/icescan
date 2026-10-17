from __future__ import annotations

from urllib.parse import urlparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

ADMIN_PATHS = ["/admin", "/admin/users", "/admin/settings", "/admin/config", "/api/admin", "/manage/users"]
ADMIN_BODY_HINTS = ["users", "settings", "config", "system", "roles", "permissions", "delete", "create"]
USER_BODY_HINTS = ["profile", "my account", "dashboard"]
LOGIN_HINTS = ["login", "password"]


class VerticalPrivesc(BaseCheck):
    name = "vert_privesc"
    category = "access"
    level = 3
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        u = urlparse(ctx.cfg.target)
        root = f"{u.scheme}://{u.netloc}"
        findings: list[Finding] = []

        for path in ADMIN_PATHS:
            url = root + path
            r = await ctx.client.get(url)
            if r.error or r.status >= 400:
                continue
            body = (r.body or "").lower()
            if any(h in body for h in LOGIN_HINTS):
                continue
            hit_count = sum(1 for h in ADMIN_BODY_HINTS if h in body)
            if hit_count >= 3:
                findings.append(self.finding(
                    severity=Severity.HIGH,
                    url=url, method="GET", param=None,
                    payload=None,
                    evidence={"admin_hints": [h for h in ADMIN_BODY_HINTS if h in body][:5], "status": r.status},
                    confidence="low",
                    note="admin interface reachable without elevated auth",
                ))
        return findings
