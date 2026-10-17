from __future__ import annotations

from urllib.parse import urlparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/api/swagger.json",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/v1/api-docs",
    "/v2/api-docs", "/v3/api-docs", "/swagger-ui.html", "/swagger-ui/",
    "/docs", "/redoc",
]

SIGS = ["\"swagger\":", "\"openapi\":", "swagger-ui", "api-docs", "Redoc"]


class Swagger(BaseCheck):
    name = "swagger"
    category = "api"
    level = 1
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        u = urlparse(ctx.cfg.target)
        root = f"{u.scheme}://{u.netloc}"
        findings: list[Finding] = []

        for path in PATHS:
            url = root + path
            r = await ctx.client.get(url)
            if r.error or r.status >= 400:
                continue
            body = r.body or ""
            for sig in SIGS:
                if sig in body:
                    findings.append(self.finding(
                        severity=Severity.LOW,
                        url=url, method="GET", param=None,
                        payload=None,
                        evidence={"signature": sig, "status": r.status, "length": r.length},
                        confidence="high",
                    ))
                    break
        return findings
