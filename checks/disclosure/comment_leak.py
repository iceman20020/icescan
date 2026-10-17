from __future__ import annotations

import re

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
JS_BLOCK = re.compile(r"<script\b[^>]*>(.*?)</script>", re.I | re.S)
JS_COMMENT = re.compile(r"//[^\n]+|/\*.*?\*/", re.S)

SENSITIVE = [
    "todo", "fixme", "hack", "password", "passwd", "secret", "api_key", "apikey",
    "token", "auth", "admin", "debug", "internal", "private", "backdoor", "deprecated",
]


class CommentLeak(BaseCheck):
    name = "comment_leak"
    category = "disclosure"
    level = 1
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        urls = (ctx.crawled_urls or []) + [ctx.cfg.target]

        for url in list(dict.fromkeys(urls))[:50]:
            r = await ctx.client.get(url)
            if r.error:
                continue
            body = r.body or ""

            for block in HTML_COMMENT.findall(body)[:30]:
                hits = [s for s in SENSITIVE if s in block.lower()]
                if hits:
                    findings.append(self.finding(
                        severity=Severity.LOW,
                        url=url, method="GET", param="html-comment",
                        payload=None,
                        evidence={"hits": hits, "snippet": block.strip()[:240]},
                        confidence="medium",
                    ))
                    break

            for script in JS_BLOCK.findall(body)[:10]:
                for comment in JS_COMMENT.findall(script)[:20]:
                    hits = [s for s in SENSITIVE if s in comment.lower()]
                    if hits:
                        findings.append(self.finding(
                            severity=Severity.LOW,
                            url=url, method="GET", param="js-comment",
                            payload=None,
                            evidence={"hits": hits, "snippet": comment.strip()[:240]},
                            confidence="medium",
                        ))
                        break
        return findings
