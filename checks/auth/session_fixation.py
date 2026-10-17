from __future__ import annotations

import re
from urllib.parse import urlparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

SESSION_COOKIE_HINTS = ("session", "sess", "sid", "auth", "token", "jwt", "id")
LOGIN_PATHS = ["/login", "/signin", "/auth/login", "/admin/login"]


class SessionFixation(BaseCheck):
    name = "session_fixation"
    category = "auth"
    level = 3
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        u = urlparse(ctx.cfg.target)
        root = f"{u.scheme}://{u.netloc}"

        for path in LOGIN_PATHS:
            url = root + path
            r1 = await ctx.client.get(url)
            if r1.error:
                continue
            pre = self._session_cookie(r1)
            if not pre:
                continue

            username = ctx.cfg.headers.get("X-Username", "admin")
            pw = ctx.cfg.headers.get("X-Password", "admin")
            r2 = await ctx.client.post(url, data={"username": username, "password": pw, "user": username, "pass": pw}, headers={"Cookie": f"{pre[0]}={pre[1]}"})
            if r2.error:
                continue
            post = self._session_cookie(r2)
            if post and post[0] == pre[0] and post[1] == pre[1]:
                return [self.finding(
                    severity=Severity.MEDIUM,
                    url=url, method="POST", param=None,
                    payload=None,
                    evidence={"cookie_name": pre[0], "value_unchanged": True},
                    confidence="low",
                    note="session id not rotated on login",
                )]
        return []

    def _session_cookie(self, r):
        for hk, hv in r.headers.items():
            if hk.lower() == "set-cookie":
                m = re.match(r"([^=]+)=([^;]+)", hv)
                if not m:
                    continue
                name, val = m.group(1).strip(), m.group(2).strip()
                if any(h in name.lower() for h in SESSION_COOKIE_HINTS):
                    return (name, val)
        return None
