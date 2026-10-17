from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field


@dataclass
class OobHit:
    token: str
    remote: str
    path: str
    headers: dict
    timestamp: float


class OobListener:
    def __init__(self, host: str = "0.0.0.0", port: int = 8443):
        self.host = host
        self.port = port
        self.hits: list[OobHit] = []
        self._server: asyncio.AbstractServer | None = None
        self._pending: dict[str, str] = {}

    def new_token(self, label: str = "") -> str:
        tok = secrets.token_hex(6)
        self._pending[tok] = label
        return tok

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            data = await reader.read(8192)
            head = data.decode("utf-8", "ignore").split("\r\n\r\n", 1)[0]
            lines = head.split("\r\n")
            if not lines:
                return
            req_line = lines[0]
            parts = req_line.split()
            path = parts[1] if len(parts) > 1 else "/"
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            remote = writer.get_extra_info("peername")
            remote_s = f"{remote[0]}:{remote[1]}" if remote else "?"

            token = path.strip("/").split("/")[0]
            self.hits.append(OobHit(token, remote_s, path, headers, time.time()))

            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def was_hit(self, token: str) -> bool:
        return any(h.token == token for h in self.hits)

    def wait_for(self, token: str, timeout: float = 5.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.was_hit(token):
                return True
            time.sleep(0.1)
        return False

    async def wait_for_async(self, token: str, timeout: float = 5.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.was_hit(token):
                return True
            await asyncio.sleep(0.1)
        return False
