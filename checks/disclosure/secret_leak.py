from __future__ import annotations

import re

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret", re.compile(r"aws_secret_access_key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", re.I)),
    ("gcp_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("stripe_key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("jwt_like", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("generic_secret", re.compile(r"(?:api[_-]?key|secret|password|token)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]", re.I)),
]


class SecretLeak(BaseCheck):
    name = "secret_leak"
    category = "disclosure"
    level = 2
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        urls = (ctx.crawled_urls or []) + [ctx.cfg.target]

        for url in list(dict.fromkeys(urls))[:60]:
            r = await ctx.client.get(url)
            if r.error:
                continue
            body = (r.body or "")[:500_000]
            for label, pat in PATTERNS:
                m = pat.search(body)
                if m:
                    matched = m.group(0)
                    findings.append(self.finding(
                        severity=Severity.HIGH,
                        url=url, method="GET", param=label,
                        payload=None,
                        evidence={"type": label, "snippet": matched[:60] + "..." if len(matched) > 60 else matched},
                        confidence="high",
                    ))
        return findings
