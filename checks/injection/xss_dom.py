from __future__ import annotations

import re

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

SINKS = [
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"document\.write(?:ln)?\s*\(",
    r"eval\s*\(",
    r"setTimeout\s*\(\s*['\"]",
    r"setInterval\s*\(\s*['\"]",
    r"new\s+Function\s*\(",
    r"location\.hash",
    r"location\.search",
    r"\$\(\s*['\"][^'\"]*['\"]\s*\)\s*\.html\s*\(",
    r"\.insertAdjacentHTML\s*\(",
    r"\.html\s*\(",
]


class DOMXSS(BaseCheck):
    name = "xss_dom"
    category = "injection"
    level = 2
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        urls = ctx.crawled_urls or [ctx.cfg.target]
        for url in urls[:50]:
            r = await ctx.client.get(url)
            if r.error:
                continue
            body = r.body or ""
            hits = [s for s in SINKS if re.search(s, body, re.I)]
            script_tags = len(re.findall(r"<script\b", body, re.I))
            if hits and script_tags:
                findings.append(self.finding(
                    severity=Severity.MEDIUM,
                    url=url, method="GET", param=None,
                    payload=None,
                    evidence={"sinks": hits[:6], "script_tags": script_tags},
                    confidence="low",
                    note="dangerous JS sinks present, manual verify",
                ))
        return findings
