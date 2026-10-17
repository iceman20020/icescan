from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

DATA = Path(__file__).resolve().parent.parent.parent / "data" / "wordlists"
SUFFIXES = [".bak", ".old", ".orig", ".swp", ".save", ".tmp", ".copy", "~", ".backup", ".1"]
PATHS = [
    ".git/config", ".git/HEAD", ".svn/entries", ".hg/requires", ".env", ".env.local", ".env.prod",
    ".DS_Store", "web.config", ".htaccess", "phpinfo.php", "info.php", "backup.zip", "backup.tar.gz",
    "db.sql", "dump.sql", "database.sql", "config.php.bak", "wp-config.php.bak",
]
SIGS = ["[core]", "ref: refs", "APP_KEY=", "DB_PASSWORD=", "DB_USER=", "<?php", "<configuration>", "sql dump"]


class BackupFiles(BaseCheck):
    name = "backup_files"
    category = "server"
    level = 1
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        base = ctx.cfg.target.rstrip("/")
        root = f"{urlparse(base).scheme}://{urlparse(base).netloc}"

        targets: list[str] = []
        for p in PATHS:
            targets.append(f"{root}/{p}")

        crawled = set(ctx.crawled_urls or [])
        crawled.add(ctx.cfg.target)
        for url in list(crawled)[:30]:
            for suf in SUFFIXES:
                targets.append(url.rstrip("/") + suf)

        for url in targets:
            r = await ctx.client.get(url)
            if r.error or r.status >= 400:
                continue
            body = r.body or ""
            matched = None
            for sig in SIGS:
                if sig.lower() in body.lower():
                    matched = sig
                    break
            if matched:
                findings.append(self.finding(
                    severity=Severity.HIGH,
                    url=url, method="GET", param=None,
                    payload=None,
                    evidence={"signature": matched, "status": r.status, "length": r.length},
                    confidence="high",
                ))
        return findings
