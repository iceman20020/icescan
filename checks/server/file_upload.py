from __future__ import annotations

from icescan.checks.base import BaseCheck
from icescan.core.types import Finding, ScanContext, Surface, SurfaceKind, Severity

PHP_SHELL = b"<?php echo 'icescan_pwn'; ?>"
JSP_SHELL = b"<% out.println(\"icescan_pwn\"); %>"
ASP_SHELL = b"<% Response.Write(\"icescan_pwn\") %>"
MARKER = "icescan_pwn"


class FileUpload(BaseCheck):
    name = "file_upload"
    category = "server"
    level = 3

    async def run_surface(self, ctx, surface):
        if surface.kind != SurfaceKind.BODY_FORM:
            return []
        if surface.method.upper() != "POST":
            return []

        fields = surface.extra.get("all_fields", [surface.name])
        if not any(f in ("file", "upload", "attachment", "image", "avatar", "photo") for f in fields):
            return []

        findings = []
        for filename, content, ctype in [
            ("icescan.php", PHP_SHELL, "application/x-php"),
            ("icescan.php.jpg", PHP_SHELL, "image/jpeg"),
            ("icescan.jsp", JSP_SHELL, "text/plain"),
            ("icescan.asp", ASP_SHELL, "text/plain"),
        ]:
            try:
                files = {surface.name: (filename, content, ctype)}
                data = {f: "test" for f in fields if f != surface.name}
                r = await ctx.client._client.post(surface.url, data=data, files=files)
            except Exception:
                continue
            if r.status_code in (200, 201, 302):
                text = r.text or ""
                if "invalid" not in text.lower() and "not allowed" not in text.lower() and "rejected" not in text.lower():
                    findings.append(self.finding(
                        severity=Severity.HIGH,
                        url=surface.url, method="POST", param=surface.name,
                        payload=f"upload {filename} as {ctype}",
                        evidence={"filename": filename, "content_type": ctype, "status": r.status_code},
                        confidence="low",
                        note="upload accepted, verify shell execution",
                    ))
                    break
        return findings
