from __future__ import annotations

import re

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity

CSRF_NAME_HINTS = ("csrf", "token", "_token", "authenticity_token", "__requestverificationtoken", "nonce")


class CSRF(BaseCheck):
    name = "csrf"
    category = "client"
    level = 1

    async def run_surface(self, ctx: ScanContext, surface: Surface) -> list[Finding]:
        if surface.kind != SurfaceKind.BODY_FORM:
            return []
        if surface.method.upper() != "POST":
            return []

        r = await ctx.client.get(surface.url)
        if r.error:
            return []
        body = r.body or ""

        form_blocks = re.findall(r"<form\b[^>]*>(.*?)</form>", body, re.I | re.S)
        if not form_blocks:
            return []

        found_token = False
        for block in form_blocks:
            for input_match in re.finditer(r"<input\b([^>]+)>", block, re.I):
                attrs = input_match.group(1).lower()
                if any(h in attrs for h in CSRF_NAME_HINTS):
                    found_token = True
                    break
            if found_token:
                break

        if found_token:
            return []

        cookie_hdr = r.header("Set-Cookie").lower()
        samesite = "samesite" in cookie_hdr and any(x in cookie_hdr for x in ("samesite=strict", "samesite=lax"))
        if samesite:
            return []

        return [self.finding(
            severity=Severity.LOW,
            url=surface.url, method="POST", param=None,
            payload=None,
            evidence={"form_action": surface.url, "has_token_field": False, "samesite_strict_or_lax": False},
            confidence="low",
            note="POST form has no csrf token and cookie lacks samesite protection",
        )]
