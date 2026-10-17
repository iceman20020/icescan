from __future__ import annotations

import re
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs

from icescan.core.types import Surface, SurfaceKind

LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)
ACTION_RE = re.compile(r'action=["\']([^"\']+)["\']', re.I)
FORM_RE = re.compile(r'<form\b[^>]*>(.*?)</form>', re.I | re.S)
INPUT_RE = re.compile(r'<input\b([^>]+)>', re.I)
JS_URL_RE = re.compile(r'["\'](https?://[^"\']+|/[a-zA-Z0-9_\-./?=&%]+)["\']')


def _same_domain(base: str, url: str, subdomains: bool) -> bool:
    b = urlparse(base).netloc.lower().split(":")[0]
    u = urlparse(url).netloc.lower().split(":")[0]
    if not u:
        return True
    if u == b:
        return True
    if subdomains and (u.endswith("." + b) or b.endswith("." + u)):
        return True
    return False


def _normalize(url: str) -> str:
    u = urlparse(url)
    path = u.path or "/"
    if u.query:
        return f"{u.scheme}://{u.netloc}{path}?{u.query}"
    return f"{u.scheme}://{u.netloc}{path}"


class Crawler:
    def __init__(self, cfg, client, console=None):
        self.cfg = cfg
        self.client = client
        self.console = console
        self.visited: set[str] = set()
        self.found_forms: list[Surface] = []
        self.found_query_surfaces: list[Surface] = []

    async def crawl(self, start_url: str) -> list[str]:
        base = start_url.rstrip("/")
        queue = deque([(base, 0)])
        urls: list[str] = []
        self.visited.add(_normalize(base))

        while queue and len(urls) < self.cfg.max_urls:
            url, depth = queue.popleft()
            r = await self.client.get(url)
            if r.error or r.status >= 400:
                continue
            urls.append(r.url)
            self._extract_query_surfaces(r.url)
            if depth >= self.cfg.depth:
                continue
            for link in self._extract_links(r.url, r.body):
                n = _normalize(link)
                if n in self.visited:
                    continue
                if not _same_domain(base, link, self.cfg.subdomains):
                    continue
                self.visited.add(n)
                queue.append((link, depth + 1))
            for form in self._extract_forms(r.url, r.body):
                self.found_forms.append(form)

        return urls

    def _extract_links(self, base_url: str, html: str) -> list[str]:
        out: list[str] = []
        for m in LINK_RE.finditer(html or ""):
            raw = m.group(1).strip()
            if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            out.append(urljoin(base_url, raw))
        return out

    def _extract_query_surfaces(self, url: str) -> None:
        u = urlparse(url)
        if not u.query:
            return
        for name, values in parse_qs(u.query).items():
            self.found_query_surfaces.append(
                Surface(
                    url=url,
                    method="GET",
                    kind=SurfaceKind.QUERY,
                    name=name,
                    original_value=values[0] if values else "",
                )
            )

    def _extract_forms(self, base_url: str, html: str) -> list[Surface]:
        out: list[Surface] = []
        for fm in FORM_RE.finditer(html or ""):
            block = fm.group(0)
            am = ACTION_RE.search(block)
            action = urljoin(base_url, am.group(1)) if am else base_url
            method = "POST"
            mm = re.search(r'method=["\'](\w+)["\']', block, re.I)
            if mm:
                method = mm.group(1).upper()
            names = []
            for im in INPUT_RE.finditer(block):
                attrs = im.group(1)
                nm = re.search(r'name=["\']([^"\']+)["\']', attrs, re.I)
                if nm:
                    names.append(nm.group(1))
            for name in names:
                out.append(
                    Surface(
                        url=action,
                        method=method,
                        kind=SurfaceKind.BODY_FORM,
                        name=name,
                        extra={"all_fields": names, "form_action": action},
                    )
                )
        return out

    def all_surfaces(self) -> list[Surface]:
        seen = set()
        out = []
        for s in self.found_query_surfaces + self.found_forms:
            key = (s.url, s.method, s.kind.value, s.name)
            if key in seen:
                continue
            seen.add(key)
            out.append(s)
        return out
