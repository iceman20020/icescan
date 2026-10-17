from __future__ import annotations

import json

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity
from icescan.core.surfaces import inject_into_url

PAYLOADS_QUERY = [
    "' || '1'=='1",
    "'; return true; var x='",
    "\" || \"1\"==\"1",
    "' && this.password.match(/.*/)//",
]

JSON_PAYLOAD = {"$ne": None}
JSON_PAYLOAD2 = {"$gt": ""}

ERROR_SIGS = [
    "MongoError", "MongoServerError", "E11000 duplicate key", "CastError",
    "BSONTypeError", "cannot unmarshal", "$where", "$ne",
]


class NoSQLInjection(BaseCheck):
    name = "nosql"
    category = "injection"
    level = 2

    def surface_kinds(self):
        return (SurfaceKind.QUERY, SurfaceKind.BODY_FORM, SurfaceKind.BODY_JSON)

    async def run_surface(self, ctx, surface):
        if surface.kind == SurfaceKind.QUERY:
            return await self._query(ctx, surface)
        if surface.kind == SurfaceKind.BODY_FORM:
            return await self._form_json(ctx, surface)
        return []

    async def _query(self, ctx, surface):
        for payload in PAYLOADS_QUERY:
            r = await ctx.client.get(inject_into_url(surface.url, surface.name, payload))
            if r.error:
                continue
            body = r.body or ""
            for sig in ERROR_SIGS:
                if sig.lower() in body.lower():
                    return [self.finding(
                        severity=Severity.HIGH,
                        url=r.url, method="GET", param=surface.name,
                        payload=payload,
                        evidence={"signature": sig},
                        confidence="medium",
                    )]
        return []

    async def _form_json(self, ctx, surface):
        for payload in (JSON_PAYLOAD, JSON_PAYLOAD2):
            try:
                r = await ctx.client.request(surface.method, surface.url, json={surface.name: payload})
            except Exception:
                continue
            if r.error:
                continue
            body = r.body or ""
            for sig in ERROR_SIGS:
                if sig.lower() in body.lower():
                    return [self.finding(
                        severity=Severity.HIGH,
                        url=r.url, method=surface.method, param=surface.name,
                        payload=json.dumps({surface.name: payload}),
                        evidence={"signature": sig},
                        confidence="medium",
                    )]
        return []
