"""PostgreSQL access: connection pool, schema bootstrap and small helpers."""
from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import math
from pathlib import Path
from typing import Any

import asyncpg

log = logging.getLogger(__name__)

_pool: asyncpg.Pool | None = None

# dashboard / report queries that count many events run at most this many at a time (all panels of a page at once
# took every CPU core of the database server for a moment); the rest wait their turn - on a 4-8 core server a page
# loads about as fast. Short periods (up to a day: cheap) have a queue of their own, so switching to 1h / 24h never
# waits behind the queries of a 7- or 30-day view.
HEAVY_PARALLEL = 3
LOW_PAUSE = 0.5  # seconds between two queries of background work (Priority low)
SHORT_HOURS = 24
_heavy: tuple[asyncio.AbstractEventLoop, asyncio.Semaphore, asyncio.Semaphore, asyncio.Semaphore] | None = None


class Priority:
    """Work done ahead of time (cache.py: the other periods of a page, loaded in the background). ``low`` while
    nobody waits for it: its queries then run one at a time in a slot of their own and never hold up a page.
    Set to False when a page starts waiting for it: its remaining queries join the normal queues."""

    def __init__(self) -> None:
        self.low = True


_priority: contextvars.ContextVar[Priority | None] = contextvars.ContextVar("lg_priority", default=None)


def run_low(prio: Priority, coro):
    """Run ``coro`` (and the tasks it starts) as ``prio``."""
    async def runner():
        _priority.set(prio)
        return await coro
    return runner()


class _Slot:
    def __init__(self, hours: float | None, sems: tuple[asyncio.Semaphore, asyncio.Semaphore, asyncio.Semaphore]):
        self.hours, self.sems, self.sem = hours, sems, None

    async def __aenter__(self):
        short, long_, low = self.sems
        prio = _priority.get()
        while prio is not None and prio.low:
            if not low.locked():
                await low.acquire()
                self.sem = low
                return self
            await asyncio.sleep(0.2)  # the low slot is busy: wait, unless a page starts waiting for this work
        self.sem = short if self.hours is not None and self.hours <= SHORT_HOURS else long_
        await self.sem.acquire()
        return self

    async def __aexit__(self, *exc) -> None:
        try:
            if self.sem is self.sems[2] and LOW_PAUSE:
                # background work (7 / 30 day counts): a short gap after each query, so it never runs back to back
                await asyncio.sleep(LOW_PAUSE)
        finally:
            self.sem.release()


def heavy(hours: float | None = None) -> _Slot:
    """``async with db.heavy(hours):`` around a query that counts many events over ``hours``. One set of queues per
    event loop (a semaphore belongs to the loop it was first used in)."""
    global _heavy
    loop = asyncio.get_running_loop()
    if _heavy is None or _heavy[0] is not loop:
        _heavy = (loop, asyncio.Semaphore(HEAVY_PARALLEL), asyncio.Semaphore(HEAVY_PARALLEL), asyncio.Semaphore(1))
    return _Slot(hours, (_heavy[2], _heavy[1], _heavy[3]))

# per connection: JIT compiling costs more CPU than it saves on these aggregate queries (measured: 15-25 % slower
# with it on 7 / 30 day windows); a bit more memory per sort / hash keeps large GROUP BYs off the disk.
# No parallel workers: with them a count of the distinct blocked source addresses over 30 days (millions of
# addresses) now and then ran for minutes instead of seconds (measured: 5 of 6 runs > 15 s, without them 3.4 s every
# time), and three such queries at once with 2 workers each took every core - logins and log ingest stalled.
# Without them the pages load about as fast: they already run 3 queries side by side.
SERVER_SETTINGS = {"jit": "off", "work_mem": "16MB", "max_parallel_workers_per_gather": "0"}

EVENT_COLUMNS = (
    "ts", "source", "host", "program", "severity", "action", "src_ip", "src_port",
    "dst_ip", "dst_port", "proto", "interface", "direction", "username", "domain",
    "src_country", "dst_country", "message", "data", "uid",
)


async def _init_conn(conn: asyncpg.Connection) -> None:
    # binary codecs so that COPY (binary protocol) works too; jsonb binary = version byte 1 + JSON text
    await conn.set_type_codec("jsonb", schema="pg_catalog", format="binary",
                              encoder=lambda v: b"\x01" + json.dumps(v, default=str).encode(),
                              decoder=lambda b: json.loads(b[1:]))
    await conn.set_type_codec("json", schema="pg_catalog", format="binary",
                              encoder=lambda v: json.dumps(v, default=str).encode(), decoder=json.loads)


# the database went away while connecting (restarting, shutting down, starting up): worth trying again
_DB_GONE = (OSError, asyncio.TimeoutError, asyncpg.InterfaceError, asyncpg.PostgresConnectionError,
            asyncpg.OperatorInterventionError)


async def _create_schema(p: asyncpg.Pool) -> None:
    schema = (Path(__file__).parent / "schema.sql").read_text()
    async with p.acquire() as conn:
        # serialize schema creation between replicas
        await conn.execute("SELECT pg_advisory_lock(424242)")
        try:
            await conn.execute(schema)
        finally:
            try:
                await conn.execute("SELECT pg_advisory_unlock(424242)")
            except _DB_GONE:  # the connection is gone, and with it the lock: keep the original error
                pass


async def connect(dsn: str | None = None, *, retry: bool = True, **kwargs: Any) -> asyncpg.Pool:
    """Open the pool (``dsn`` or asyncpg keyword arguments) and create the schema. ``retry=False`` raises instead.

    Also retries when the database goes away halfway (e.g. its container restarts together with Looking Glass)."""
    global _pool
    delay = 1.0
    while True:
        try:
            _pool = await asyncpg.create_pool(dsn, min_size=2, max_size=15, init=_init_conn, command_timeout=120,
                                              timeout=15, server_settings=SERVER_SETTINGS, **kwargs)
        except (OSError, asyncpg.PostgresError, asyncio.TimeoutError) as exc:
            if not retry:
                raise
            if isinstance(exc, (asyncpg.InvalidPasswordError, asyncpg.InvalidAuthorizationSpecificationError)):
                log.error("database login refused (%s). Wrong user/password? To enter the connection again run: "
                          "docker exec looking-glass python -m lookingglass.cli setup-database  (then restart)", exc)
            log.warning("database not reachable yet (%s), retrying in %.0fs", exc, delay)
        else:
            try:
                await _create_schema(_pool)
                break
            except _DB_GONE as exc:
                _pool.terminate()
                _pool = None
                if not retry:
                    raise
                log.warning("database connection lost while preparing the database (%s), retrying in %.0fs",
                            exc, delay)
        await asyncio.sleep(delay)
        delay = min(delay * 2, 30)
    log.info("database ready")
    return _pool


def pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("database not initialised")
    return _pool


async def close(timeout: float = 10) -> None:
    """Close the pool. Queries still running after ``timeout`` seconds (a 30-day dashboard query can take minutes) are
    cut off instead of holding up the shutdown."""
    global _pool
    if _pool is not None:
        p, _pool = _pool, None
        try:
            await asyncio.wait_for(p.close(), timeout)
        except Exception:  # noqa: BLE001 - incl. the timeout
            p.terminate()


# Indexes for the dashboards that take a minute or more to build on a large events table: built in the background
# after the start (CONCURRENTLY: events keep being written meanwhile), not in schema.sql, which would hold up the start
# and block every insert while it builds. name -> definition.
BACKGROUND_INDEXES = {
    # events per source and time, with the columns most dashboard queries group by: those read this narrow index alone
    # (index-only scan) instead of the whole wide rows with their message and JSON data. Replaces the plain
    # events_source_ts_idx (same key; dropped once this one is there): only a few hundred MB larger
    "events_source_ts_cover_idx": "ON events (source, ts DESC) "
                                  "INCLUDE (action, src_ip, dst_ip, dst_port, proto, direction, src_country, domain)",
    # the firewall log lines of blocklist rules (CrowdSec, Q-Feeds ... data.blocklist): a small part of the firewall
    # lines. Without it every Q-Feeds / CrowdSec panel reads the JSON of every firewall line of the period (30 days:
    # minutes instead of seconds)
    "events_blocklist_idx": "ON events (lower(data->>'blocklist'), ts) "
                            "WHERE source = 'firewall' AND data->>'blocklist' IS NOT NULL",
    # CrowdSec rule lines stored before they were tagged with data.blocklist (dashboards.CS_FW)
    "events_cs_label_idx": "ON events (ts) WHERE source = 'firewall' AND data->>'label' LIKE 'CrowdSec (%'",
    # blocked traffic with the columns the "top blocked ..." tables and tiles group by: they read this narrow index
    # (index-only scan) instead of the whole wide rows - about a tenth of the data
    "events_block_idx": "ON events (ts) INCLUDE (source, action, src_ip, dst_ip, dst_port, proto, src_country, direction) "
                        "WHERE action IN ('block', 'drop')",
}
# indexes a BACKGROUND_INDEXES one makes unnecessary: dropped once that one is built
REPLACED_INDEXES = {"events_source_ts_cover_idx": "events_source_ts_idx"}


async def build_background_indexes() -> None:
    """Create the missing BACKGROUND_INDEXES, one at a time. One that an interruption left unfinished (invalid) is built
    again. Several Looking Glass instances on one database: only one builds."""
    async with pool().acquire() as conn:
        if not await conn.fetchval("SELECT pg_try_advisory_lock(424243)"):
            return
        try:
            for name, definition in BACKGROUND_INDEXES.items():
                valid = await conn.fetchval("SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass($1)", name)
                if not valid:
                    if valid is False:
                        await conn.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {name}", timeout=3600)
                    log.info("building index %s for the dashboards (once; may take a few minutes on a large database)",
                             name)
                    started = asyncio.get_running_loop().time()
                    await conn.execute(f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {name} {definition}", timeout=6 * 3600)
                    log.info("index %s built in %.0f s", name, asyncio.get_running_loop().time() - started)
                if old := REPLACED_INDEXES.get(name):
                    await conn.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {old}", timeout=3600)
        finally:
            await conn.execute("SELECT pg_advisory_unlock(424243)")


async def background_indexes_loop() -> None:
    """build_background_indexes, retried every 10 minutes until it succeeds (e.g. the database restarted halfway)."""
    await asyncio.sleep(30)  # let the start (rollup catch-up, first polls) settle first
    while True:
        try:
            await build_background_indexes()
            return
        except Exception:  # noqa: BLE001
            log.exception("building the dashboard indexes failed, trying again in 10 minutes")
        await asyncio.sleep(600)


def _row(ev: dict[str, Any]) -> tuple:
    return tuple(ev.get(c) for c in EVENT_COLUMNS)


async def copy_events(events: list[dict[str, Any]]) -> None:
    """Bulk insert (COPY) events that have no dedupe uid."""
    if not events:
        return
    async with pool().acquire() as conn:
        await conn.copy_records_to_table("events", records=[_row(e) for e in events], columns=EVENT_COLUMNS)


async def insert_events_dedup(events: list[dict[str, Any]]) -> int:
    """Insert events carrying a ``uid``; duplicates are silently ignored. Returns rows inserted."""
    if not events:
        return 0
    cols = ", ".join(EVENT_COLUMNS)
    params = ", ".join(f"${i}" for i in range(1, len(EVENT_COLUMNS) + 1))
    sql = f"INSERT INTO events ({cols}) VALUES ({params}) ON CONFLICT (uid) WHERE uid IS NOT NULL DO NOTHING"
    inserted = 0
    async with pool().acquire() as conn:
        for ev in events:
            status = await conn.execute(sql, *_row(ev))
            inserted += int(status.rsplit(" ", 1)[-1])
    return inserted


async def set_snapshot(key: str, data: Any) -> None:
    await pool().execute(
        "INSERT INTO snapshots (key, ts, data) VALUES ($1, now(), $2) "
        "ON CONFLICT (key) DO UPDATE SET ts = now(), data = EXCLUDED.data",
        key, data,
    )


async def get_snapshot(key: str) -> Any:
    row = await pool().fetchrow("SELECT data FROM snapshots WHERE key = $1", key)
    return row["data"] if row else None


async def kv_get(key: str, default: Any = None) -> Any:
    row = await pool().fetchrow("SELECT value FROM kv WHERE key = $1", key)
    return row["value"] if row else default


async def kv_set(key: str, value: Any) -> None:
    await pool().execute(
        "INSERT INTO kv (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        key, value,
    )


async def add_metrics(rows: list[tuple[str, str, float]]) -> None:
    # one bad row (no label, NaN, None) must not lose the whole batch: labels default to '', unusable values are skipped
    rows = [(n, "" if lab is None else str(lab), float(v)) for n, lab, v in rows
            if isinstance(v, (int, float)) and math.isfinite(v)]
    if not rows:
        return
    async with pool().acquire() as conn:
        await conn.executemany("INSERT INTO metrics (name, labels, value) VALUES ($1, $2, $3)", rows)


def jsonable(value: Any) -> Any:
    """Convert asyncpg record values (datetime, inet, Decimal) into JSON friendly ones."""
    import datetime
    import decimal
    import ipaddress

    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    if isinstance(value, (datetime.datetime, datetime.date)):
        return value.isoformat()
    if isinstance(value, decimal.Decimal):
        return float(value)
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address,
                          ipaddress.IPv4Network, ipaddress.IPv6Network,
                          ipaddress.IPv4Interface, ipaddress.IPv6Interface)):
        return str(value)
    return value


def records(rows: list[asyncpg.Record]) -> list[dict[str, Any]]:
    return [jsonable(dict(r)) for r in rows]
