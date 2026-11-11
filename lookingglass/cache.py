"""A small in-memory result cache for the dashboards and the Overview.

Several tabs, devices or users looking at the same dashboard and period share one result instead of each running
every query again. Requests that arrive while it is being computed wait for that same computation. Results are kept
briefly, longer for long periods (a 30-day view hardly changes from one minute to the next).

A result that has expired a little while ago is still shown right away (``stale``) while a new one is computed in the
background: counting 30 days of events takes a while, and nobody should wait for that when the previous result is a
few minutes old. ``refreshing`` tells the page to ask again shortly, it then gets the new result.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Awaitable, Callable

log = logging.getLogger(__name__)


def ttl_for(hours: float) -> float:
    """Seconds a result stays valid: 30 s up to a day, 2 minutes up to a week, 5 minutes beyond."""
    return 30 if hours <= 24 else 120 if hours <= 168 else 300


def stale_for(hours: float) -> float:
    """Seconds after it expired that a result is still shown while the new one is computed: 5 minutes up to a day,
    6 hours beyond - the page says when the shown numbers were counted, and shows the new ones within a minute or so."""
    return 300 if hours <= 24 else 6 * 3600


class ResultCache:
    def __init__(self, max_items: int = 200) -> None:
        self.items: dict[Any, tuple[float, Any]] = {}
        self.running: dict[Any, asyncio.Future] = {}
        self.max_items = max_items

    def _start(self, key: Any, compute: Callable[[], Awaitable[Any]]) -> asyncio.Future:
        fut = self.running.get(key)
        if fut is not None:
            return fut
        fut = asyncio.ensure_future(compute())
        self.running[key] = fut

        def done(f: asyncio.Future, key: Any = key) -> None:
            # stored when it finishes, even if the browser that asked for it has gone (the next one gets it)
            self.running.pop(key, None)
            if f.cancelled():
                return
            if (exc := f.exception()) is not None:
                log.warning("computing %s failed: %s", key, exc)
                return
            self.items[key] = (time.monotonic(), f.result())
            if len(self.items) > self.max_items:
                oldest = sorted(self.items, key=lambda k: self.items[k][0])[: len(self.items) - self.max_items]
                for k in oldest:
                    self.items.pop(k, None)

        fut.add_done_callback(done)
        return fut

    async def get(self, key: Any, ttl: float, compute: Callable[[], Awaitable[Any]], stale: float = 0) -> Any:
        """The result for ``key``: cached when younger than ``ttl``; up to ``ttl + stale`` old it is returned at once
        and a new one is computed in the background; otherwise computed (or the running computation awaited)."""
        hit = self.items.get(key)
        age = time.monotonic() - hit[0] if hit else None
        if hit and age < ttl:
            return hit[1]
        fut = self._start(key, compute)
        if hit and age < ttl + stale:
            return hit[1]
        return await asyncio.shield(fut)

    def refreshing(self, key: Any) -> bool:
        """A new result for ``key`` is being computed."""
        return key in self.running

    def clear(self) -> None:
        self.items.clear()
