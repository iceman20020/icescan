from __future__ import annotations

import re
from urllib.parse import urlparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

RESET_PATHS = ["/password/reset", "/forgot-password", "/reset", "/account/recover", "/auth/forgot"]
TOKEN_IN_URL = re.compile(r"(token|reset|key|code)=[a-f0-9]{6,}", re.I)


class PasswordReset(BaseCheck):
    name = "password_reset"
    category = "auth"
    level = 3
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        u = urlparse(ctx.cfg.target)
        root = f"{u.scheme}://{u.netloc}"
        findings: list[Finding] = []

        for path in RESET_PATHS:
            url = root + path
            r = await ctx.client.get(url)
            if r.error or r.status >= 400:
                continue
            body = r.body or ""

            if "type=\"email\"" not in body.lower():
                continue

            if re.search(r"<form[^>]*>", body, re.I) and "csrf" not in body.lower():
                findings.append(self.finding(
                    severity=Severity.LOW,
                    url=url, method="GET", param=None,
                    payload=None,
                    evidence={"form_found": True, "csrf_token_present": False},
                    confidence="low",
                    note="password reset form lacks csrf token",
                ))

            test = await ctx.client.post(url, data={"email": "test@x.com", "user_email": "test@x.com"})
            if test.error:
                continue
            loc = test.header("Location")
            if loc and TOKEN_IN_URL.search(loc):
                findings.append(self.finding(
                    severity=Severity.HIGH,
                    url=url, method="POST", param="email",
                    payload="test@x.com",
                    evidence={"token_in_url": loc},
                    confidence="medium",
                    note="reset token exposed in url/location header",
                ))
        return findings
