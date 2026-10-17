from __future__ import annotations

import json
import time
from pathlib import Path


class Checkpoint:
    def __init__(self, path: Path | None):
        self.path = path
        self.data: dict = {"started": time.time(), "completed_checks": [], "surfaces": [], "findings": []}
        if path and path.exists():
            try:
                self.data = json.loads(path.read_text())
            except Exception:
                pass

    def is_done(self, key: str) -> bool:
        return key in self.data.get("completed_checks", [])

    def mark_done(self, key: str) -> None:
        self.data.setdefault("completed_checks", []).append(key)
        self._flush()

    def add_finding(self, finding_dict: dict) -> None:
        self.data.setdefault("findings", []).append(finding_dict)
        self._flush()

    def _flush(self) -> None:
        if not self.path:
            return
        try:
            self.path.write_text(json.dumps(self.data, indent=2))
        except Exception:
            pass

    def reset(self) -> None:
        self.data = {"started": time.time(), "completed_checks": [], "surfaces": [], "findings": []}
        self._flush()
