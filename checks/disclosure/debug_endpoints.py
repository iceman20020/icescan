from __future__ import annotations

from urllib.parse import urlparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

PATHS = [
    ("/actuator", ["_links", "self", "health"]),
    ("/actuator/env", ["propertySources", "systemProperties"]),
    ("/actuator/heapdump", []),
    ("/actuator/threaddump", ["threadName", "threadState"]),
    ("/actuator/mappings", ["contexts", "mappings"]),
    ("/actuator/beans", ["context", "beans"]),
    ("/debug", ["debug", "vars", "dump"]),
    ("/debug/pprof/", ["goroutine", "heap", "profile"]),
    ("/console", ["H2 Console", "JDBC URL"]),
    ("/__debug__/", ["Django", "debug toolbar"]),
    ("/phpinfo.php", ["PHP Version", "System"]),
    ("/trace", ["trace", "request"]),
    ("/metrics", ["http_requests", "process_", "jvm_"]),
]


class DebugEndpoints(BaseCheck):
    name = "debug_endpoints"
    category = "disclosure"
    level = 1
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        u = urlparse(ctx.cfg.target)
        root = f"{u.scheme}://{u.netloc}"
        findings: list[Finding] = []

        for path, sigs in PATHS:
            url = root + path
            r = await ctx.client.get(url)
            if r.error or r.status >= 400 or not r.body:
                continue
            body = r.body
            if sigs and not any(s in body for s in sigs):
                continue
            findings.append(self.finding(
                severity=Severity.HIGH if not sigs else Severity.MEDIUM,
                url=url, method="GET", param=None,
                payload=None,
                evidence={"status": r.status, "length": r.length, "snippet": body[:200]},
                confidence="high",
            ))
        return findings
