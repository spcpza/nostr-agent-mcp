"""Nostr relay pool — reused from nostr-dvm with minor cleanup."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import AsyncGenerator
from typing import Any

log = logging.getLogger(__name__)

try:
    import websockets
    _HAS_WEBSOCKETS = True
except ImportError:
    _HAS_WEBSOCKETS = False


class RelayPool:
    """Async context manager that maintains connections to multiple Nostr relays."""

    def __init__(self, urls: list[str]) -> None:
        self._urls = urls
        self._conns: list[Any] = []

    async def __aenter__(self) -> "RelayPool":
        if not _HAS_WEBSOCKETS:
            raise ImportError("websockets is required: pip install websockets")
        for url in self._urls:
            try:
                conn = await websockets.connect(url, ping_interval=20, open_timeout=5)
                self._conns.append(conn)
                log.debug("Connected to relay: %s", url)
            except Exception as exc:
                log.warning("Could not connect to relay %s: %s", url, exc)
        if not self._conns:
            raise RuntimeError(f"Could not connect to any relay: {self._urls}")
        return self

    async def __aexit__(self, *args) -> None:
        for conn in self._conns:
            try:
                await conn.close()
            except Exception:
                pass
        self._conns = []

    async def publish(self, event: dict) -> None:
        """Broadcast a signed Nostr event to all connected relays."""
        msg = json.dumps(["EVENT", event])
        for conn in self._conns:
            try:
                await conn.send(msg)
            except Exception as exc:
                log.warning("Failed to publish to relay: %s", exc)

    async def subscribe(
        self,
        filters: dict,
        *,
        timeout: float = 10.0,
    ) -> AsyncGenerator[dict, None]:
        """Subscribe to events matching filters. Yields event dicts."""
        if not self._conns:
            return

        sub_id = str(uuid.uuid4())[:8]
        req = json.dumps(["REQ", sub_id, filters])

        for conn in self._conns:
            try:
                await conn.send(req)
            except Exception as exc:
                log.warning("Failed to subscribe on relay: %s", exc)

        queue: asyncio.Queue = asyncio.Queue()
        seen: set[str] = set()

        async def _reader(conn):
            try:
                async for raw in conn:
                    msg = json.loads(raw)
                    if msg[0] == "EVENT" and msg[1] == sub_id:
                        event = msg[2]
                        eid = event.get("id", "")
                        if eid not in seen:
                            seen.add(eid)
                            await queue.put(event)
                    elif msg[0] == "EOSE" and msg[1] == sub_id:
                        await queue.put(None)  # end of stored events
            except Exception:
                pass

        tasks = [asyncio.create_task(_reader(c)) for c in self._conns]

        try:
            eose_count = 0
            deadline = asyncio.get_event_loop().time() + timeout
            while True:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    break
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=min(remaining, 1.0))
                    if item is None:
                        eose_count += 1
                        if eose_count >= len(self._conns):
                            break
                    else:
                        yield item
                except asyncio.TimeoutError:
                    break
        finally:
            for t in tasks:
                t.cancel()
            close_msg = json.dumps(["CLOSE", sub_id])
            for conn in self._conns:
                try:
                    await conn.send(close_msg)
                except Exception:
                    pass
