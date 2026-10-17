from __future__ import annotations

import time

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Severity

CL_TE = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 6\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "G"
)

TE_CL = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 3\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "1\r\n"
    "G\r\n"
    "0\r\n"
    "\r\n"
)


class Smuggling(BaseCheck):
    name = "smuggling"
    category = "transport"
    level = 3
    needs_surface = False

    async def run_global(self, ctx: ScanContext) -> list[Finding]:
        from urllib.parse import urlparse
        import socket
        import ssl

        u = urlparse(ctx.cfg.target)
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
        if not host:
            return []

        findings: list[Finding] = []
        for label, raw in [("CL.TE", CL_TE), ("TE.CL", TE_CL)]:
            t0 = time.monotonic()
            try:
                if u.scheme == "https":
                    ctx_s = ssl._create_unverified_context()
                    sock = ctx_s.wrap_socket(socket.create_connection((host, port), timeout=5), server_hostname=host)
                else:
                    sock = socket.create_connection((host, port), timeout=5)
                payload = raw.format(host=host).encode()
                sock.sendall(payload)
                time.sleep(0.2)
                sock.sendall(payload)
                time.sleep(2.5)
                sock.settimeout(1.5)
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    data = b""
                sock.close()
                elapsed = time.monotonic() - t0
                if elapsed > 4.0 and not data:
                    findings.append(self.finding(
                        severity=Severity.MEDIUM,
                        url=ctx.cfg.target, method="POST", param=label,
                        payload="raw smuggling probe",
                        evidence={"elapsed": round(elapsed, 2), "label": label},
                        confidence="low",
                        note="timing anomaly during smuggling probe, verify manually",
                    ))
            except Exception:
                continue
        return findings
