"""7 / 30 day results of the Overview and the dashboards: counted on a schedule, never when a page asks.

Counting 7 or 30 days of events takes the database seconds to minutes per page. Doing that whenever someone switched
to such a period (and ahead of time for every other page and tab) kept the database busy enough that even logging in
slowed down. Instead:

- a page asking for a long period gets the stored result at once (``period_results``, so it survives a restart), with
  the time it was counted; nothing is counted for it;
- one background worker counts the long periods again when they are older than Settings › Data & detection ›
  "7-day / 30-day views: count again every …", one after the other, each query at low priority (one at a time, in a
  slot of its own - see db.Priority), so pages, logins and log ingest keep their share of the database;
- the refresh button on a page (``refresh``) puts that period at the front of the queue;
- a period never counted before (the first look after an update) is counted right away, also in the background - the
  page says so and asks again until it is there;
- periods nobody looked at for a week are no longer counted.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from . import db

log = logging.getLogger(__name__)

SHORT_HOURS = 24  # periods up to this are counted live (cheap); longer ones come from here
KEEP_DAYS = 7  # a period not looked at for this long is no longer refreshed
VIEW_WRITE_S = 300  # "looked at" is written at most this often per period


def is_long(hours: float) -> bool:
    return hours > SHORT_HOURS


def key_of(kind: str, *args: Any) -> str:
    """The stored key; the last argument is the period in hours (720 and 720.0 are one key)."""
    return json.dumps([kind, *args[:-1], float(args[-1])])


class Periods:
    def __init__(self, settings, computers: dict[str, Callable[..., Awaitable[Any]]]) -> None:
        """``computers``: kind -> async function(*args) giving the result of ``key_of(kind, *args)``; its last
        argument is always the period in hours."""
        self.settings = settings
        self.computers = computers
        self.memory: dict[str, tuple[datetime, Any, str | None]] = {}  # key -> (counted at, result, last error)
        self.viewed: dict[str, float] = {}  # key -> monotonic time "looked at" was last written
        self.urgent: list[str] = []  # counted next: refresh button, never counted before
        self.current: str | None = None
        self.current_since: float | None = None
        self.wake = asyncio.Event()

    def interval_s(self, hours: float) -> float:
        minutes = self.settings.long_refresh_7d if hours <= 168 else self.settings.long_refresh_30d
        return max(10, int(minutes or 60)) * 60

    # ------------------------------------------------------------------ pages ---
    async def get(self, kind: str, *args: Any) -> dict[str, Any]:
        """The stored result: {"data": ..., "as_of": epoch | None, "refreshing": bool, "next": epoch | None,
        "error": str | None}. ``data`` is None when it was never counted (it is being counted now)."""
        key, hours = key_of(kind, *args), float(args[-1])
        await self._viewed(key, hours)
        hit = self.memory.get(key)
        if hit is None:
            row = await db.pool().fetchrow("SELECT computed_at, data, error FROM period_results WHERE key = $1", key)
            if row and row["computed_at"] is not None:
                hit = self.memory[key] = (row["computed_at"], row["data"], row["error"])
        if hit is None:
            self.refresh(key)
            return {"data": None, "as_of": None, "refreshing": True, "next": None, "error": None}
        counted, data, error = hit
        if (datetime.now(timezone.utc) - counted).total_seconds() > self.interval_s(hours) and key not in self.urgent:
            self.wake.set()  # due (e.g. the interval was shortened): the worker picks it up
        return {"data": data, "as_of": counted.timestamp(), "refreshing": self.busy(key),
                "next": counted.timestamp() + self.interval_s(hours), "error": error}

    def busy(self, key: str) -> bool:
        return key == self.current or key in self.urgent

    def refresh(self, key: str) -> None:
        """Count ``key`` next (refresh button)."""
        if key != self.current and key not in self.urgent:
            self.urgent.append(key)
        self.wake.set()

    def status(self) -> dict[str, Any]:
        return {"current": json.loads(self.current) if self.current else None,
                "running_s": round(time.monotonic() - self.current_since) if self.current_since else None,
                "queued": [json.loads(k) for k in self.urgent]}

    def forget(self) -> None:
        """The stored results were deleted (Settings › purge events)."""
        self.memory.clear()
        self.urgent.clear()

    async def _viewed(self, key: str, hours: float) -> None:
        now = time.monotonic()
        if now - self.viewed.get(key, -VIEW_WRITE_S) < VIEW_WRITE_S:
            return
        self.viewed[key] = now
        await db.pool().execute(
            "INSERT INTO period_results (key, hours, viewed_at) VALUES ($1, $2, now()) "
            "ON CONFLICT (key) DO UPDATE SET viewed_at = now()", key, hours)

    # ----------------------------------------------------------------- worker ---
    async def _next(self) -> str | None:
        if self.urgent:
            return self.urgent.pop(0)
        rows = await db.pool().fetch(
            "SELECT key, hours, computed_at FROM period_results WHERE viewed_at > now() - make_interval(days => $1) "
            "ORDER BY computed_at NULLS FIRST", KEEP_DAYS)
        now = datetime.now(timezone.utc)
        for r in rows:
            if r["computed_at"] is None or (now - r["computed_at"]).total_seconds() >= self.interval_s(r["hours"]):
                return r["key"]
        return None

    async def count(self, key: str) -> None:
        """Count one period and store it. An error is stored with it; the previous result stays."""
        kind, *args = json.loads(key)
        compute = self.computers.get(kind)
        if compute is None:  # an older / unknown kind: no longer counted
            await db.pool().execute("DELETE FROM period_results WHERE key = $1", key)
            return
        self.current, self.current_since = key, time.monotonic()
        started = time.monotonic()
        try:
            prio = db.Priority()  # one query at a time, in the low slot: never holds up pages or logins
            data = await db.run_low(prio, compute(*args))
            data = json.loads(json.dumps(data, default=str))  # what is stored is what is served
            counted = await db.pool().fetchval(
                "INSERT INTO period_results (key, hours, computed_at, data, error) VALUES ($1, $2, now(), $3, NULL) "
                "ON CONFLICT (key) DO UPDATE SET computed_at = now(), data = EXCLUDED.data, error = NULL "
                "RETURNING computed_at", key, float(args[-1]), data)
            self.memory[key] = (counted, data, None)
            log.info("counted %s in %.0f s", key, time.monotonic() - started)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"[:500]
            log.warning("counting %s failed: %s", key, error)
            # keep the previous result; computed_at moves on so a broken query does not run again right away
            counted = await db.pool().fetchval(
                "INSERT INTO period_results (key, hours, computed_at, error) VALUES ($1, $2, now(), $3) "
                "ON CONFLICT (key) DO UPDATE SET computed_at = now(), error = EXCLUDED.error RETURNING computed_at",
                key, float(args[-1]), error)
            old = self.memory.get(key)
            if old is not None and old[1] is not None:
                self.memory[key] = (counted, old[1], error)
            else:
                row = await db.pool().fetchrow("SELECT data FROM period_results WHERE key = $1", key)
                self.memory[key] = (counted, row["data"] if row else None, error)
        finally:
            self.current = self.current_since = None

    async def run(self) -> None:
        """The worker: counts what is due, one period at a time, until the end."""
        await asyncio.sleep(20)  # let the start-up work (rollup catch-up, first polls) go first
        while True:
            try:
                key = await self._next()
            except Exception as exc:  # noqa: BLE001 - database busy / restarting: try again shortly
                log.warning("long periods: reading what is due failed: %s", exc)
                key = None
            if key is not None:
                await self.count(key)
                await asyncio.sleep(1)  # a breather for the database between two long counts
                continue
            self.wake.clear()
            try:
                await asyncio.wait_for(self.wake.wait(), 60)
            except asyncio.TimeoutError:
                pass
