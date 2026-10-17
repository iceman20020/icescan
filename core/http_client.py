from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class Response:
    url: str
    method: str
    status: int
    headers: dict[str, str]
    body: str
    elapsed: float
    error: str | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 400

    @property
    def length(self) -> int:
        return len(self.body or "")

    def header(self, name: str, default: str = "") -> str:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default


class RateLimiter:
    def __init__(self, rate: float):
        self.rate = rate
        self._interval = 1.0 / rate
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            if now < self._next:
                await asyncio.sleep(self._next - now)
                now = time.monotonic()
            self._next = now + self._interval


class HttpClient:
    def __init__(self, cfg, console=None):
        self.cfg = cfg
        self.console = console
        self.requests_sent = 0
        self.errors = 0
        self.rate_limiter = RateLimiter(cfg.rate)
        self._client: httpx.AsyncClient | None = None
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> "HttpClient":
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; icescan/1.0; +https://github.com/iceman/icescan)",
            "Accept": "*/*",
        }
        headers.update(self.cfg.headers or {})
        if self.cfg.cookie:
            headers["Cookie"] = self.cfg.cookie
        if self.cfg.bearer:
            headers["Authorization"] = f"Bearer {self.cfg.bearer}"
        if self.cfg.basic_auth:
            auth = httpx.BasicAuth(*self.cfg.basic_auth)
        else:
            auth = None

        self._client = httpx.AsyncClient(
            headers=headers,
            auth=auth,
            timeout=self.cfg.timeout,
            follow_redirects=False,
            verify=False,
            proxy=self.cfg.proxy,
            limits=httpx.Limits(max_connections=self.cfg.threads * 2, max_keepalive_connections=self.cfg.threads),
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client:
            await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        json: Any = None,
        content: str | bytes | None = None,
        follow_redirects: bool = False,
        timeout: float | None = None,
    ) -> Response:
        await self.rate_limiter.wait()

        merged_headers = dict(headers or {})
        req_body = None
        if data:
            from urllib.parse import urlencode
            req_body = urlencode(data)
        elif json is not None:
            import json as _j
            req_body = _j.dumps(json)
        elif content is not None:
            req_body = content if isinstance(content, str) else content.decode("utf-8", "ignore")

        last_err = None
        for attempt in range(self.cfg.retries + 1):
            t0 = time.monotonic()
            try:
                r = await self._client.request(
                    method,
                    url,
                    headers=merged_headers or None,
                    params=params,
                    data=data,
                    json=json,
                    content=content,
                    follow_redirects=follow_redirects,
                    timeout=timeout or self.cfg.timeout,
                )
                elapsed = time.monotonic() - t0
                async with self._lock:
                    self.requests_sent += 1

                return Response(
                    url=str(r.url),
                    method=method,
                    status=r.status_code,
                    headers=dict(r.headers),
                    body=r.text if r.text else "",
                    elapsed=elapsed,
                    request_headers=dict(r.request.headers),
                    request_body=req_body,
                )
            except Exception as e:
                last_err = e
                if attempt < self.cfg.retries:
                    await asyncio.sleep(0.25 * (attempt + 1))
                    continue
                break

        async with self._lock:
            self.requests_sent += 1
            self.errors += 1

        return Response(
            url=url, method=method, status=0, headers={}, body="",
            elapsed=time.monotonic() - t0, error=str(last_err),
            request_headers=merged_headers, request_body=req_body,
        )

    async def get(self, url: str, **kw) -> Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> Response:
        return await self.request("POST", url, **kw)

    async def head(self, url: str, **kw) -> Response:
        return await self.request("HEAD", url, **kw)

    async def options(self, url: str, **kw) -> Response:
        return await self.request("OPTIONS", url, **kw)
