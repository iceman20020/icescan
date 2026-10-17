from __future__ import annotations

import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from icescan.core.types import Surface, SurfaceKind


def build_surfaces(crawled_urls: list[str], crawler_surfaces: list[Surface]) -> list[Surface]:
    seen = set()
    out: list[Surface] = []

    for s in crawler_surfaces:
        key = (s.url, s.method, s.kind.value, s.name)
        if key in seen:
            continue
        seen.add(key)
        out.append(s)

    for url in crawled_urls:
        for s in _surfaces_from_url(url):
            key = (s.url, s.method, s.kind.value, s.name)
            if key in seen:
                continue
            seen.add(key)
            out.append(s)

    return out


def _surfaces_from_url(url: str) -> list[Surface]:
    u = urlparse(url)
    out: list[Surface] = []
    if u.query:
        for name, vals in parse_qs(u.query).items():
            out.append(
                Surface(
                    url=url, method="GET", kind=SurfaceKind.QUERY,
                    name=name, original_value=vals[0] if vals else "",
                )
            )
    return out


def inject_into_url(url: str, param: str, value: str) -> str:
    u = urlparse(url)
    q = parse_qs(u.query, keep_blank_values=True)
    q[param] = [value]
    new_q = urlencode(q, doseq=True)
    return urlunparse((u.scheme, u.netloc, u.path, u.params, new_q, u.fragment))


def inject_into_form(all_fields: list[str], param: str, value: str) -> dict[str, str]:
    return {f: ("test" if f != param else value) for f in all_fields}


def inject_into_json(body: dict, param: str, value: str) -> dict:
    out = dict(body or {})
    out[param] = value
    return out
