from __future__ import annotations

import re

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

HEADER_PATTERNS = [
    ("Server", re.compile(r"[\w./\-]+/[\d.]+")),
    ("X-Powered-By", re.compile(r".+")),
    ("X-AspNet-Version", re.compile(r"[\d.]+")),
    ("X-AspNetMvc-Version", re.compile(r"[\d.]+")),
    ("X-Generator", re.compile(r".+")),
]

META_PATTERNS = [
    (r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)', "meta generator"),
    (r"jQuery v?([\d.]+)", "jQuery"),
    (r"Bootstrap v?([\d.]+)", "Bootstrap"),
    (r"React v?([\d.]+)", "React"),
    (r"Vue(?:\.js)? v?([\d.]+)", "Vue"),
]


class VersionDisclosure(BaseCheck):
    name = "version_disclosure"
    category = "disclosure"
    level = 1
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        r = await ctx.client.get(ctx.cfg.target)
        if r.error:
            return []

        findings: list[Finding] = []

        for hname, pat in HEADER_PATTERNS:
            v = r.header(hname)
            if v and pat.search(v):
                findings.append(self.finding(
                    severity=Severity.LOW,
                    url=ctx.cfg.target, method="GET", param=hname,
                    payload=None,
                    evidence={"header": hname, "value": v},
                    confidence="high",
                ))

        body = r.body or ""
        for pat, label in META_PATTERNS:
            m = re.search(pat, body, re.I)
            if m:
                findings.append(self.finding(
                    severity=Severity.INFO,
                    url=ctx.cfg.target, method="GET", param=label,
                    payload=None,
                    evidence={"label": label, "match": m.group(0)[:120]},
                    confidence="medium",
                ))
        return findings
