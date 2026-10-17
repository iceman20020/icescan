from __future__ import annotations

from urllib.parse import urlparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

WEAK = ["password", "123456", "12345678", "qwerty", "abc123", "letmein", "admin123", "welcome", "monkey", "1234567890", "password1", "Password1"]

LOGIN_PATHS = ["/login", "/admin/login", "/signin", "/auth/login", "/user/login"]
FAIL_SIGS = ["invalid", "incorrect", "wrong", "failed", "denied", "locked", "too many"]
LOCKOUT_HINTS = ["locked", "too many attempts", "rate limit", "try again in"]


class WeakPassword(BaseCheck):
    name = "weak_password"
    category = "auth"
    level = 3
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        u = urlparse(ctx.cfg.target)
        root = f"{u.scheme}://{u.netloc}"
        findings: list[Finding] = []

        if not ctx.cfg.headers.get("X-Username") and not ctx.cfg.cookie:
            return []

        username = ctx.cfg.headers.get("X-Username", "admin")
        for path in LOGIN_PATHS:
            url = root + path
            probe = await ctx.client.get(url)
            if probe.error or probe.status >= 400:
                continue
            if "type=\"password\"" not in (probe.body or "").lower():
                continue

            for pw in WEAK:
                r = await ctx.client.post(url, data={"username": username, "password": pw, "user": username, "pass": pw})
                if r.error:
                    continue
                body = (r.body or "").lower()
                if any(h in body for h in LOCKOUT_HINTS):
                    break
                if r.status == 200 and not any(s in body for s in FAIL_SIGS):
                    findings.append(self.finding(
                        severity=Severity.HIGH,
                        url=url, method="POST", param="password",
                        payload=f"{username}:{pw}",
                        evidence={"status": r.status},
                        confidence="low",
                        note="weak password accepted, verify",
                    ))
                    return findings
        return findings
