from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from icescan import __version__
from icescan.core.types import ScanContext


def write_json(ctx: ScanContext, path: Path, scan_id: str) -> None:
    data = {
        "scan_id": scan_id,
        "tool": "icescan",
        "version": __version__,
        "target": ctx.cfg.target,
        "level": ctx.cfg.level,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "requests": ctx.client.requests_sent,
            "errors": ctx.client.errors,
            "findings": len(ctx.findings),
            "surfaces": len(ctx.surfaces),
            "crawled_urls": len(ctx.crawled_urls),
        },
        "recon": {
            "tech": ctx.recon.get("tech", []),
            "waf": ctx.recon.get("waf"),
            "headers": ctx.recon.get("headers", {}),
        },
        "findings": [
            {
                "check": f.check,
                "category": f.category,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "url": f.url,
                "method": f.method,
                "param": f.param,
                "payload": f.payload,
                "dbms": f.dbms,
                "note": f.note,
                "evidence": f.evidence,
                "timestamp": f.timestamp,
            }
            for f in ctx.findings
        ],
    }
    path.write_text(json.dumps(data, indent=2, default=str))
