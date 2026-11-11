"""A small in-memory result cache for the dashboards and the Overview.

Several tabs, devices or users looking at the same dashboard and period share one result instead of each running
every query again. Requests that arrive while it is being computed wait for that same computation. Results are kept
briefly, longer for long periods (a 30-day view hardly changes from one minute to the next).

Switching periods is instant for a period shown not long ago: a result that has expired but is not too old
(``stale_for``) is answered right away and computed again in the background; the page then picks up the new one.

A computation that nobody waits for any more (every browser that asked has gone: another period was picked, the tab
was closed) is cancelled, and with it its database queries. Otherwise clicking through 1h / 24h / 7d / 30d a few times
queued dozens of long 30-day queries that kept the database busy - and every page waiting - for half an hour.
A background refresh is never cancelled that way (nobody waits for it by design); there is one per key at most.

The first switch to a period is instant too, most of the time: when a page is loaded, the other periods of that page
are computed ahead of time (``warm``), one after the other, at low priority - their queries run one at a time in a
slot of their own (db.Priority) and never hold up a page. A page that asks for such a period while it is being
computed waits for that same computation, which then continues at normal priority. A period computed ahead of time
is computed again at most every ``stale_for / 2`` (30-day view: every 30 minutes while the page is open).
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Awaitable, Callable

from . import db

log = logging.getLogger(__name__)


def ttl_for(hours: float) -> float:
    """Seconds a result stays valid: 30 s up to a day, 2 minutes up to a week, 5 minutes beyond."""
    return 30 if hours <= 24 else 120 if hours <= 168 else 300


def stale_for(hours: float) -> float:
    """Seconds an expired result may still be shown while a new one is computed: 5 % of the period (a 30-day chart
    an hour old looks the same), at least its ``ttl_for``, at most an hour."""
    return min(3600.0, max(ttl_for(hours), hours * 3600 * 0.05))


class ResultCache:
    def __init__(self, max_items: int = 200) -> None:
        self.items: dict[Any, tuple[float, float, Any]] = {}  # key -> (monotonic, wall clock, result)
        self.running: dict[Any, asyncio.Future] = {}
        self.waiters: dict[Any, int] = {}
        self.background: set[asyncio.Future] = set()
        self.priority: dict[asyncio.Future, db.Priority] = {}  # computations started ahead of time
        self.queue: dict[Any, tuple[float, Callable[[], Awaitable[Any]]]] = {}  # key -> (stale, compute)
        self.worker: asyncio.Task | None = None
        self.max_items = max_items

    def _start(self, key: Any, compute: Callable[[], Awaitable[Any]]) -> asyncio.Future:
        fut = self.running.get(key)
        if fut is not None:
            return fut
        fut = asyncio.ensure_future(compute())
        self.running[key] = fut

        def done(f: asyncio.Future, key: Any = key) -> None:
            self.background.discard(f)
            self.priority.pop(f, None)
            if self.running.get(key) is f:
                self.running.pop(key, None)
            if not f.cancelled() and f.exception() is None:
                self.items[key] = (time.monotonic(), time.time(), f.result())
                if len(self.items) > self.max_items:
                    oldest = sorted(self.items, key=lambda k: self.items[k][0])[: len(self.items) - self.max_items]
                    for k in oldest:
                        self.items.pop(k, None)

        fut.add_done_callback(done)
        return fut

    async def fetch(self, key: Any, ttl: float, compute: Callable[[], Awaitable[Any]],
                    stale: float = 0) -> tuple[Any, float, bool]:
        """(result, wall-clock time it was computed, stale). ``stale``: seconds an expired result may still be
        answered while a new one is computed in the background."""
        hit = self.items.get(key)
        if hit:
            age = time.monotonic() - hit[0]
            if age < ttl:
                return hit[2], hit[1], False
            if age < stale:
                fut = self._start(key, compute)
                if fut not in self.background and not self.waiters.get(key):
                    self.background.add(fut)
                if prio := self.priority.get(fut):
                    prio.low = False  # someone looks at the old result meanwhile
                return hit[2], hit[1], True
        fut = self._start(key, compute)
        if prio := self.priority.get(fut):
            prio.low = False  # computed ahead of time, and now a page waits for it: full speed
        self.waiters[key] = self.waiters.get(key, 0) + 1
        try:
            return await asyncio.shield(fut), time.time(), False
        finally:
            left = self.waiters[key] = self.waiters.get(key, 1) - 1
            if left <= 0:
                self.waiters.pop(key, None)
                # the last one waiting for it has gone: stop the queries (a background refresh runs on)
                if not fut.done() and fut not in self.background:
                    fut.cancel()
                    if self.running.get(key) is fut:
                        self.running.pop(key, None)

    def warm(self, key: Any, compute: Callable[[], Awaitable[Any]], stale: float) -> None:
        """Compute ``key`` ahead of time, in the background at low priority, unless a result younger than half of
        ``stale`` is there or it is being computed already."""
        hit = self.items.get(key)
        if (hit and time.monotonic() - hit[0] < stale / 2) or key in self.running or key in self.queue:
            return
        self.queue[key] = (stale, compute)
        if self.worker is None or self.worker.done():
            self.worker = asyncio.ensure_future(self._work())

    async def _work(self) -> None:
        while self.queue:
            key = next(iter(self.queue))
            stale, compute = self.queue.pop(key)
            hit = self.items.get(key)
            if (hit and time.monotonic() - hit[0] < stale / 2) or key in self.running:
                continue
            prio = db.Priority()
            fut = self._start(key, lambda prio=prio, compute=compute: db.run_low(prio, compute()))
            self.priority[fut] = prio
            self.background.add(fut)
            try:
                await asyncio.shield(fut)
            except asyncio.CancelledError:
                if not fut.cancelled():
                    raise  # this worker itself is cancelled (shut down)
            except Exception:  # the page computes it itself when asked
                log.debug("computing %s ahead of time failed", key, exc_info=True)

    async def get(self, key: Any, ttl: float, compute: Callable[[], Awaitable[Any]], stale: float = 0) -> Any:
        return (await self.fetch(key, ttl, compute, stale))[0]

    def clear(self) -> None:
        self.items.clear()
