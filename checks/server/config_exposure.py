from __future__ import annotations

from urllib.parse import urlparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

PATHS = [
    ("/server-status", ["Apache Server Status", "Total accesses"]),
    ("/server-info", ["Apache Server Information"]),
    ("/nginx_status", ["Active connections", "server accepts"]),
    ("/phpinfo.php", ["PHP Version", "php.ini", "allow_url_fopen"]),
    ("/info.php", ["PHP Version", "php.ini"]),
    ("/.htaccess", ["<IfModule", "RewriteEngine"]),
    ("/web.config", ["<configuration>", "<system.web>"]),
    ("/actuator/env", ["activeProfiles", "systemProperties", "propertySources"]),
    ("/actuator/health", ["\"status\":\"UP\""]),
    ("/_debug", ["debug", "trace"]),
    ("/__debug__/", ["Django", "debug toolbar"]),
]


class ConfigExposure(BaseCheck):
    name = "config_exposure"
    category = "server"
    level = 1
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        u = urlparse(ctx.cfg.target)
        root = f"{u.scheme}://{u.netloc}"
        for path, sigs in PATHS:
            url = root + path
            r = await ctx.client.get(url)
            if r.error or r.status >= 400:
                continue
            body = r.body or ""
            for sig in sigs:
                if sig.lower() in body.lower():
                    findings.append(self.finding(
                        severity=Severity.MEDIUM,
                        url=url, method="GET", param=None,
                        payload=None,
                        evidence={"signature": sig, "status": r.status, "length": r.length},
                        confidence="high",
                    ))
                    break
        return findings
