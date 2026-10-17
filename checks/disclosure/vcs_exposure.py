from __future__ import annotations

from urllib.parse import urlparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

PATHS = [
    ("/.git/config", ["[core]", "repositoryformatversion"]),
    ("/.git/HEAD", ["ref: refs/heads/"]),
    ("/.git/refs/heads/main", []),
    ("/.git/index", []),
    ("/.svn/entries", ["dir", "svn"]),
    ("/.svn/wc.db", []),
    ("/.hg/requires", ["dotencode", "fncache", "revlogv1"]),
    ("/.hg/store/00manifest.i", []),
    ("/.bzr/README", ["Bazaar"]),
    ("/.DS_Store", ["Bud1"]),
]


class VCSExposure(BaseCheck):
    name = "vcs_exposure"
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
            if r.error or r.status >= 400:
                continue
            if r.length == 0:
                continue
            body = r.body or ""
            if sigs and not any(s.lower() in body.lower() for s in sigs):
                continue
            findings.append(self.finding(
                severity=Severity.HIGH,
                url=url, method="GET", param=None,
                payload=None,
                evidence={"status": r.status, "length": r.length, "snippet": body[:200]},
                confidence="high",
            ))
        return findings
