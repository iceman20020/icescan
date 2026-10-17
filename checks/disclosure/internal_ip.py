from __future__ import annotations

import re

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"169\.254\.\d{1,3}\.\d{1,3})\b"
)


class InternalIPLeak(BaseCheck):
    name = "internal_ip"
    category = "disclosure"
    level = 1
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        r = await ctx.client.get(ctx.cfg.target)
        if r.error:
            return []
        body = r.body or ""
        headers_text = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        hits = set(IP_RE.findall(body + "\n" + headers_text))
        if not hits:
            return []

        return [self.finding(
            severity=Severity.LOW,
            url=ctx.cfg.target, method="GET", param=None,
            payload=None,
            evidence={"ips": sorted(hits)[:10]},
            confidence="medium",
        )]
