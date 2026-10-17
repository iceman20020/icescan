from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]


class SurfaceKind(str, Enum):
    QUERY = "query"
    BODY_FORM = "body_form"
    BODY_JSON = "body_json"
    BODY_XML = "body_xml"
    COOKIE = "cookie"
    HEADER = "header"
    PATH = "path"


@dataclass
class Surface:
    url: str
    method: str
    kind: SurfaceKind
    name: str
    original_value: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def label(self) -> str:
        return f"{self.method} {self.url} [{self.kind.value}:{self.name}]"


@dataclass
class Finding:
    check: str
    category: str
    severity: Severity
    url: str
    method: str
    param: str | None
    payload: str | None
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: str = "medium"
    dbms: str | None = None
    note: str | None = None
    timestamp: float = 0.0

    def key(self) -> tuple:
        return (self.check, self.url, self.method, self.param or "")


@dataclass
class ScanContext:
    cfg: Any
    client: Any
    console: Any
    baseline: Any
    detector: Any
    findings: list[Finding] = field(default_factory=list)
    visited_urls: set[str] = field(default_factory=set)
    crawled_urls: list[str] = field(default_factory=list)
    surfaces: list[Surface] = field(default_factory=list)
    recon: dict[str, Any] = field(default_factory=dict)
    dbms_hint: str | None = None
    waf_detected: str | None = None
    oob_server: Any = None
    start_time: float = 0.0
    stats: dict[str, Any] = field(default_factory=dict)

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)
