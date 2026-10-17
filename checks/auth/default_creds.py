from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

DATA = Path(__file__).resolve().parent.parent.parent / "data" / "wordlists"

DEFAULTS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "12345"), ("admin", "123456"), ("admin", "root"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("test", "test"), ("user", "user"), ("guest", "guest"),
    ("administrator", "administrator"), ("admin", "letmein"),
    ("admin", "welcome"), ("admin", "changeme"), ("admin", "admin@123"),
]

LOGIN_PATHS = [
    "/admin", "/admin/login", "/administrator", "/login", "/wp-admin",
    "/wp-login.php", "/user/login", "/account/login", "/signin", "/auth/login",
    "/manager/html", "/console", "/cpanel", "/webadmin", "/phpmyadmin/",
]

SUCCESS_SIGS = ["dashboard", "logout", "sign out", "welcome", "profile", "account"]
FAIL_SIGS = ["invalid", "incorrect", "wrong", "failed", "denied", "try again"]


class DefaultCreds(BaseCheck):
    name = "default_creds"
    category = "auth"
    level = 2
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        u = urlparse(ctx.cfg.target)
        root = f"{u.scheme}://{u.netloc}"
        findings: list[Finding] = []

        candidates = [root + p for p in LOGIN_PATHS]
        for url in candidates:
            probe = await ctx.client.get(url)
            if probe.error or probe.status >= 400:
                continue
            if not self._looks_like_login(probe.body or ""):
                continue

            for user, pw in DEFAULTS:
                r = await ctx.client.post(url, data={"username": user, "password": pw, "user": user, "pass": pw, "login": "Login"})
                if r.error:
                    continue
                body = (r.body or "").lower()
                loc = r.header("Location").lower()
                if any(s in body for s in SUCCESS_SIGS) and not any(s in body for s in FAIL_SIGS):
                    findings.append(self.finding(
                        severity=Severity.CRITICAL,
                        url=url, method="POST", param="username/password",
                        payload=f"{user}:{pw}",
                        evidence={"status": r.status, "location": loc, "snippet": body[:200]},
                        confidence="high",
                    ))
                    return findings
                if r.status in (301, 302, 303) and "login" not in loc and loc:
                    findings.append(self.finding(
                        severity=Severity.HIGH,
                        url=url, method="POST", param="username/password",
                        payload=f"{user}:{pw}",
                        evidence={"redirect_to": loc},
                        confidence="low",
                        note="redirect after login suggests success, verify manually",
                    ))
                    return findings
        return findings

    def _looks_like_login(self, body: str) -> bool:
        b = body.lower()
        return ("password" in b and ("username" in b or "user" in b)) or ("type=\"password\"" in b)
