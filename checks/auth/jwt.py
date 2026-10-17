from __future__ import annotations

import base64
import json
import re

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")

WEAK_SECRETS = [
    "secret", "password", "123456", "your-256-bit-secret", "changeme",
    "jwt", "jwtsecret", "mysecret", "supersecret", "admin", "test",
]


class JWT(BaseCheck):
    name = "jwt"
    category = "auth"
    level = 2
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen_tokens: set[str] = set()

        tokens = self._tokens_from_cfg(ctx)
        for url in (ctx.crawled_urls or [ctx.cfg.target])[:30]:
            r = await ctx.client.get(url)
            if r.error:
                continue
            tokens.extend(self._find_tokens(r))
            for hk, hv in r.headers.items():
                if hk.lower() == "set-cookie":
                    tokens.extend(self._find_tokens_str(hv))

        for tok in tokens:
            if tok in seen_tokens:
                continue
            seen_tokens.add(tok)
            issues = self._analyze(tok)
            if issues:
                findings.append(self.finding(
                    severity=Severity.HIGH if issues["critical"] else Severity.MEDIUM,
                    url=ctx.cfg.target, method="GET", param="jwt",
                    payload=tok[:80] + "...",
                    evidence=issues,
                    confidence="high" if issues["critical"] else "medium",
                ))
        return findings

    def _tokens_from_cfg(self, ctx):
        out = []
        if ctx.cfg.bearer:
            out.append(ctx.cfg.bearer)
        if ctx.cfg.cookie:
            out.extend(self._find_tokens_str(ctx.cfg.cookie))
        for k, v in (ctx.cfg.headers or {}).items():
            if k.lower() == "authorization":
                out.extend(self._find_tokens_str(v))
        return out

    def _find_tokens(self, r):
        out = self._find_tokens_str(r.body or "")
        for k, v in r.headers.items():
            out.extend(self._find_tokens_str(v))
        return out

    def _find_tokens_str(self, s: str):
        return JWT_RE.findall(s or "")

    def _analyze(self, tok: str) -> dict | None:
        try:
            parts = tok.split(".")
            if len(parts) < 3:
                return None
            header_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        except Exception:
            return None

        issues = {"alg": header.get("alg"), "critical": False, "flags": []}

        if header.get("alg", "").lower() == "none" or parts[2] == "":
            issues["critical"] = True
            issues["flags"].append("none-algorithm")

        if header.get("alg", "").startswith("HS"):
            for secret in WEAK_SECRETS:
                if self._hs256_verify(tok, secret):
                    issues["critical"] = True
                    issues["flags"].append(f"weak-hs256-secret:{secret}")
                    break

        if "exp" not in payload:
            issues["flags"].append("no-expiry")
        if "iat" not in payload:
            issues["flags"].append("no-issued-at")

        return issues if issues["flags"] else None

    def _hs256_verify(self, tok: str, secret: str) -> bool:
        try:
            import hmac
            import hashlib
            head, body, sig = tok.split(".")
            signing_input = f"{head}.{body}".encode()
            expected = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
            ).rstrip(b"=").decode()
            return expected == sig
        except Exception:
            return False
