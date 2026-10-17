from __future__ import annotations

import re

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity
from icescan.core.surfaces import inject_into_url

PROBES = ["'", "\"", "\\", "%00", "../../", "<", "{{7*7}}"]

ERROR_SIGS = [
    "Traceback (most recent call last)", "at java.", "at javax.", "at org.springframework",
    "System.NullReferenceException", "System.ArgumentException", "System.Data.SqlClient",
    "stack trace", "File \"", "line \\d+, in ", "pdo_mysql", "mysqli_",
    "Undefined variable", "Notice:", "Warning:", "Fatal error", "Parse error",
    "Call to undefined", "expects parameter",
]


class VerboseErrors(BaseCheck):
    name = "verbose_errors"
    category = "disclosure"
    level = 1

    async def run_surface(self, ctx: ScanContext, surface: Surface) -> list[Finding]:
        if surface.kind != SurfaceKind.QUERY:
            return []

        for probe in PROBES:
            url = inject_into_url(surface.url, surface.name, probe)
            r = await ctx.client.get(url)
            if r.error or not r.body:
                continue
            body = r.body
            for sig in ERROR_SIGS:
                if sig.lower() in body.lower():
                    snippet = self._snippet(body, sig)
                    return [self.finding(
                        severity=Severity.MEDIUM,
                        url=url, method="GET", param=surface.name,
                        payload=probe,
                        evidence={"signature": sig, "snippet": snippet, "status": r.status},
                        confidence="high",
                    )]
        return []

    def _snippet(self, body: str, needle: str, width: int = 240) -> str:
        idx = body.lower().find(needle.lower())
        if idx == -1:
            return body[:width]
        s = max(0, idx - 60)
        e = min(len(body), idx + width)
        return body[s:e]
