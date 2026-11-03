"""A small in-memory result cache for the dashboards and the Overview.

Several tabs, devices or users looking at the same dashboard and period share one result instead of each running
every query again. Requests that arrive while it is being computed wait for that same computation. Results are kept
briefly, longer for long periods (a 30-day view hardly changes from one minute to the next).
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable


def ttl_for(hours: float) -> float:
    """Seconds a result stays valid: 30 s up to a day, 2 minutes up to a week, 5 minutes beyond."""
    return 30 if hours <= 24 else 120 if hours <= 168 else 300


class ResultCache:
    def __init__(self, max_items: int = 200) -> None:
        self.items: dict[Any, tuple[float, Any]] = {}
        self.running: dict[Any, asyncio.Future] = {}
        self.max_items = max_items

    async def get(self, key: Any, ttl: float, compute: Callable[[], Awaitable[Any]]) -> Any:
        hit = self.items.get(key)
        if hit and time.monotonic() - hit[0] < ttl:
            return hit[1]
        fut = self.running.get(key)
        if fut is None:
            fut = asyncio.ensure_future(compute())
            self.running[key] = fut

            def done(f: asyncio.Future, key: Any = key) -> None:
                # stored when it finishes, even if the browser that asked for it has gone (the next one gets it)
                self.running.pop(key, None)
                if not f.cancelled() and f.exception() is None:
                    self.items[key] = (time.monotonic(), f.result())
                    if len(self.items) > self.max_items:
                        oldest = sorted(self.items, key=lambda k: self.items[k][0])[: len(self.items) - self.max_items]
                        for k in oldest:
                            self.items.pop(k, None)

            fut.add_done_callback(done)
        return await asyncio.shield(fut)

    def clear(self) -> None:
        self.items.clear()
