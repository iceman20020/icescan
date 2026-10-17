from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity
from icescan.core.surfaces import inject_into_url

ID_RE = re.compile(r"^\d+$")


class IDOR(BaseCheck):
    name = "idor"
    category = "access"
    level = 2

    async def run_surface(self, ctx: ScanContext, surface: Surface) -> list[Finding]:
        if surface.kind != SurfaceKind.QUERY:
            return []

        u = urlparse(surface.url)
        params = parse_qs(u.query)
        if surface.name not in params:
            return []
        val = params[surface.name][0]
        if not ID_RE.match(val):
            return []

        base_id = int(val)
        if base_id < 1:
            return []

        base = await ctx.client.get(surface.url)
        if base.error or base.status >= 400:
            return []

        for delta in (1, 2, -1, 10, 100):
            new_id = base_id + delta
            if new_id < 1:
                continue
            test_url = inject_into_url(surface.url, surface.name, str(new_id))
            r = await ctx.client.get(test_url)
            if r.error or r.status != base.status:
                continue
            sim = ctx.detector.similarity(base.body, r.body)
            if sim < 0.75:
                return [self.finding(
                    severity=Severity.MEDIUM,
                    url=test_url, method="GET", param=surface.name,
                    payload=str(new_id),
                    evidence={
                        "original_id": base_id,
                        "tested_id": new_id,
                        "similarity": round(sim, 3),
                        "status": r.status,
                    },
                    confidence="low",
                    note="different content with numeric id pivot, verify access control",
                )]
        return []
