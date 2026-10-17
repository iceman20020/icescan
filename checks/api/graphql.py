from __future__ import annotations

from urllib.parse import urlparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

PATHS = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query"]

INTROSPECTION = {"query": "query { __schema { types { name } } }"}
SIGS = ["__schema", "__type", "queryType", "mutationType", "subscriptionType"]


class GraphQL(BaseCheck):
    name = "graphql"
    category = "api"
    level = 2
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        u = urlparse(ctx.cfg.target)
        root = f"{u.scheme}://{u.netloc}"
        findings: list[Finding] = []

        for path in PATHS:
            url = root + path
            r = await ctx.client.post(url, json=INTROSPECTION)
            if r.error or r.status >= 400:
                continue
            body = r.body or ""
            hits = [s for s in SIGS if s in body]
            if hits:
                findings.append(self.finding(
                    severity=Severity.MEDIUM,
                    url=url, method="POST", param="graphql-introspection",
                    payload=INTROSPECTION["query"],
                    evidence={"signatures": hits, "snippet": body[:200]},
                    confidence="high",
                ))
        return findings
