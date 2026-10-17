from __future__ import annotations

import json
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None


def _split_csv(s: str | None) -> list[str]:
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]


def _parse_auth(s: str | None) -> tuple[str, str] | None:
    if not s:
        return None
    if ":" not in s:
        raise ValueError("basic-auth must be user:pass")
    u, p = s.split(":", 1)
    return (u, p)


@dataclass
class Config:
    target: str = ""
    output: Path = Path("report")
    formats: list[str] = field(default_factory=lambda: ["json", "html"])

    level: int = 1
    tests: list[str] = field(default_factory=lambda: ["all"])
    exclude: list[str] = field(default_factory=list)

    crawl: bool = False
    depth: int = 2
    max_urls: int = 500
    subdomains: bool = False
    respect_robots: bool = False

    threads: int = 20
    rate: float = 10.0
    timeout: float = 15.0
    retries: int = 2
    proxy: str | None = None

    cookie: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    basic_auth: tuple[str, str] | None = None
    bearer: str | None = None

    waf_evade: bool = False
    stacked: bool = False

    oob_listen: bool = False
    oob_host: str | None = None
    oob_port: int = 8443

    second_order_url: str | None = None
    baseline: Path | None = None
    record: Path | None = None
    checkpoint: Path | None = None

    quiet: bool = False
    no_color: bool = False
    json_stream: bool = False
    plain: bool = False

    @classmethod
    def from_sources(cls, args) -> "Config":
        cfg = cls()

        if args.config:
            file_data = _load_file(args.config)
            cfg = _merge_from_dict(cfg, file_data)

        cfg.target = args.target or cfg.target
        cfg.output = args.output
        cfg.formats = _split_csv(args.format) or cfg.formats
        cfg.level = args.level
        cfg.tests = _split_csv(args.tests) or cfg.tests
        cfg.exclude = _split_csv(args.exclude)

        cfg.crawl = args.crawl or cfg.crawl
        cfg.depth = args.depth
        cfg.max_urls = args.max_urls
        cfg.subdomains = args.subdomains or cfg.subdomains
        cfg.respect_robots = args.respect_robots or cfg.respect_robots

        cfg.threads = args.threads
        cfg.rate = args.rate
        cfg.timeout = args.timeout
        cfg.retries = args.retries
        cfg.proxy = args.proxy or cfg.proxy

        cfg.cookie = args.cookie or cfg.cookie
        cfg.headers = dict(cfg.headers)
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                cfg.headers[k.strip()] = v.strip()
        cfg.basic_auth = _parse_auth(args.basic_auth) or cfg.basic_auth
        cfg.bearer = args.bearer or cfg.bearer

        cfg.waf_evade = args.waf_evade or cfg.waf_evade
        cfg.stacked = args.stacked or cfg.stacked

        cfg.oob_listen = args.oob_listen or cfg.oob_listen
        cfg.oob_host = args.oob_host or cfg.oob_host
        cfg.oob_port = args.oob_port

        cfg.second_order_url = args.second_order_url or cfg.second_order_url
        cfg.baseline = args.baseline or cfg.baseline
        cfg.record = args.record or cfg.record
        cfg.checkpoint = args.checkpoint or cfg.checkpoint

        cfg.quiet = args.quiet
        cfg.no_color = args.no_color
        cfg.json_stream = args.json_stream
        cfg.plain = args.plain

        _validate(cfg)
        return cfg

    def to_dict(self) -> dict[str, Any]:
        out = {}
        for f in fields(self):
            v = getattr(self, f.name)
            if isinstance(v, Path):
                v = str(v)
            out[f.name] = v
        return out

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2))


def _load_file(path: Path) -> dict[str, Any]:
    text = path.read_text()
    if path.suffix in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError("pyyaml not installed, cannot read yaml config")
        return yaml.safe_load(text) or {}
    if path.suffix == ".json":
        return json.loads(text)
    raise ValueError(f"unknown config format: {path.suffix}")


def _merge_from_dict(cfg: Config, data: dict[str, Any]) -> Config:
    for k, v in data.items():
        if not hasattr(cfg, k):
            continue
        if k == "output" and isinstance(v, str):
            v = Path(v)
        if k == "baseline" and isinstance(v, str):
            v = Path(v)
        if k == "record" and isinstance(v, str):
            v = Path(v)
        if k == "checkpoint" and isinstance(v, str):
            v = Path(v)
        if k == "basic_auth" and isinstance(v, (list, tuple)) and len(v) == 2:
            v = (v[0], v[1])
        if k == "formats" and isinstance(v, str):
            v = _split_csv(v)
        if k == "tests" and isinstance(v, str):
            v = _split_csv(v)
        if k == "exclude" and isinstance(v, str):
            v = _split_csv(v)
        setattr(cfg, k, v)
    return cfg


def _validate(cfg: Config) -> None:
    if not cfg.target and not cfg.crawl:
        raise ValueError("no target given")
    if cfg.level not in (1, 2, 3):
        raise ValueError("level must be 1, 2, or 3")
    if cfg.threads < 1:
        raise ValueError("threads must be >= 1")
    if cfg.rate <= 0:
        raise ValueError("rate must be > 0")
    if cfg.depth < 0:
        raise ValueError("depth must be >= 0")
    if cfg.oob_listen and cfg.oob_host:
        raise ValueError("use either --oob-listen or --oob-host, not both")
