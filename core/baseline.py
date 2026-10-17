from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from icescan.core.surfaces import inject_into_url, inject_into_form
from icescan.core.types import Surface, SurfaceKind


@dataclass
class BaselineEntry:
    url: str
    method: str
    kind: str
    param: str
    status: int
    length: int
    body_hash: str
    similarity_body: str


class BaselineCache:
    def __init__(self, client):
        self.client = client
        self._cache: dict[tuple, BaselineEntry] = {}
        self._soft_404: dict[str, str] = {}

    async def get(self, surface: Surface) -> BaselineEntry:
        key = (surface.url, surface.method, surface.kind.value, surface.name)
        if key in self._cache:
            return self._cache[key]
        entry = await self._build(surface)
        self._cache[key] = entry
        return entry

    async def _build(self, surface: Surface) -> BaselineEntry:
        neutral = "icescan_neutral_" + hashlib.md5(
            f"{surface.url}{surface.name}".encode()
        ).hexdigest()[:6]

        if surface.kind == SurfaceKind.QUERY:
            url = inject_into_url(surface.url, surface.name, neutral)
            r = await self.client.get(url)
        elif surface.kind == SurfaceKind.BODY_FORM:
            fields = surface.extra.get("all_fields", [surface.name])
            data = inject_into_form(fields, surface.name, neutral)
            r = await self.client.request(surface.method, surface.url, data=data)
        else:
            return BaselineEntry(
                url=surface.url, method=surface.method, kind=surface.kind.value,
                param=surface.name, status=0, length=0, body_hash="", similarity_body="",
            )

        return BaselineEntry(
            url=surface.url,
            method=surface.method,
            kind=surface.kind.value,
            param=surface.name,
            status=r.status,
            length=r.length,
            body_hash=hashlib.md5((r.body or "").encode()).hexdigest(),
            similarity_body=(r.body or "")[:5000],
        )

    async def soft_404(self, base_url: str) -> str:
        if base_url in self._soft_404:
            return self._soft_404[base_url]
        rand = "icescan_404_" + hashlib.md5(base_url.encode()).hexdigest()[:8]
        test_url = base_url.rstrip("/") + "/" + rand
        r = await self.client.get(test_url)
        self._soft_404[base_url] = r.body[:5000] if not r.error else ""
        return self._soft_404[base_url]

    def clear(self) -> None:
        self._cache.clear()
        self._soft_404.clear()
