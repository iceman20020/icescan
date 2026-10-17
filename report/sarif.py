from __future__ import annotations

import json
from pathlib import Path

from icescan import __version__
from icescan.core.types import ScanContext, Severity


_SEV_TO_SARIF = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def write_sarif(ctx: ScanContext, path: Path) -> None:
    rules = {}
    results = []

    for f in ctx.findings:
        rule_id = f.check
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.check,
                "shortDescription": {"text": f"{f.category} check"},
                "properties": {"category": f.category, "tags": [f.category]},
            }

        results.append({
            "ruleId": rule_id,
            "level": _SEV_TO_SARIF.get(f.severity, "warning"),
            "message": {"text": f"{f.severity.value}: {f.check} at {f.url}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.url},
                },
            }],
            "properties": {
                "severity": f.severity.value,
                "confidence": f.confidence,
                "param": f.param,
                "payload": f.payload,
                "evidence": f.evidence,
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "icescan",
                    "version": __version__,
                    "informationUri": "https://github.com/iceman/icescan",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
        }],
    }
    path.write_text(json.dumps(sarif, indent=2, default=str))
