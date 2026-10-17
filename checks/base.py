from __future__ import annotations

import time
from abc import ABC, abstractmethod

from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity


class BaseCheck(ABC):
    name: str = "base"
    category: str = "misc"
    level: int = 1
    needs_surface: bool = True
    needs_crawl: bool = False

    async def execute(self, ctx: ScanContext) -> list[Finding]:
        if not self.needs_surface:
            return await self.run_global(ctx)
        findings: list[Finding] = []
        for surface in ctx.surfaces:
            if surface.kind not in self.surface_kinds():
                continue
            try:
                res = await self.run_surface(ctx, surface)
                findings.extend(res)
            except Exception:
                continue
        return findings

    def surface_kinds(self) -> tuple[SurfaceKind, ...]:
        return (
            SurfaceKind.QUERY,
            SurfaceKind.BODY_FORM,
        )

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        return []

    async def run_surface(self, ctx: ScanContext, surface: Surface) -> list[Finding]:
        return []

    def finding(
        self,
        *,
        severity: Severity,
        url: str,
        method: str,
        param: str | None = None,
        payload: str | None = None,
        evidence: dict | None = None,
        confidence: str = "medium",
        dbms: str | None = None,
        note: str | None = None,
    ) -> Finding:
        return Finding(
            check=self.name,
            category=self.category,
            severity=severity,
            url=url,
            method=method,
            param=param,
            payload=payload,
            evidence=evidence or {},
            confidence=confidence,
            dbms=dbms,
            note=note,
            timestamp=time.time(),
        )
