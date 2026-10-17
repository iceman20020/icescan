from __future__ import annotations

import json

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity

ADMIN_FIELDS = [
    {"is_admin": True},
    {"role": "admin"},
    {"admin": True},
    {"privileges": ["admin"]},
    {"user_type": "admin"},
    {"is_superuser": True},
]

ADMIN_SIGS = ["admin", "dashboard", "superuser", "settings"]


class MassAssignment(BaseCheck):
    name = "mass_assignment"
    category = "api"
    level = 3

    def surface_kinds(self):
        return (SurfaceKind.BODY_JSON, SurfaceKind.BODY_FORM)

    async def run_surface(self, ctx: ScanContext, surface: Surface) -> list[Finding]:
        base_body = {surface.name: "icescan_base"}
        base = await ctx.client.request(surface.method, surface.url, json=base_body)
        if base.error or base.status >= 400:
            return []

        for extra in ADMIN_FIELDS:
            body = dict(base_body)
            body.update(extra)
            r = await ctx.client.request(surface.method, surface.url, json=body)
            if r.error:
                continue
            if r.status in (200, 201) and "error" not in (r.body or "").lower()[:200]:
                return [self.finding(
                    severity=Severity.HIGH,
                    url=surface.url, method=surface.method, param=",".join(extra.keys()),
                    payload=json.dumps(extra),
                    evidence={"status": r.status, "snippet": (r.body or "")[:200]},
                    confidence="low",
                    note="extra fields accepted without rejection, verify they're persisted",
                )]
        return []
