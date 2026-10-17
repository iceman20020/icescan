from __future__ import annotations

import socket
import ssl
from urllib.parse import urlparse

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity


class TLS(BaseCheck):
    name = "tls"
    category = "transport"
    level = 1
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        u = urlparse(ctx.cfg.target)
        if u.scheme != "https":
            return []

        host = u.hostname
        port = u.port or 443
        findings: list[Finding] = []

        for proto_name, proto in [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]:
            if self._accepts(host, port, proto):
                findings.append(self.finding(
                    severity=Severity.MEDIUM,
                    url=ctx.cfg.target, method="GET", param=None,
                    payload=None,
                    evidence={"protocol": proto_name, "accepted": True},
                    confidence="high",
                ))

        cert = self._cert_info(host, port)
        if cert:
            if cert.get("self_signed"):
                findings.append(self.finding(
                    severity=Severity.MEDIUM,
                    url=ctx.cfg.target, method="GET", param="certificate",
                    payload=None,
                    evidence={"self_signed": True, "subject": cert.get("subject", "")},
                    confidence="medium",
                ))
        return findings

    def _accepts(self, host: str, port: int, proto) -> bool:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = proto
            ctx.maximum_version = proto
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except Exception:
            return False

    def _cert_info(self, host: str, port: int) -> dict | None:
        try:
            ctx = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as s:
                    cert = s.getpeercert()
                    return {
                        "subject": str(cert.get("subject", "")),
                        "issuer": str(cert.get("issuer", "")),
                        "self_signed": cert.get("subject") == cert.get("issuer"),
                    }
        except Exception:
            return None
