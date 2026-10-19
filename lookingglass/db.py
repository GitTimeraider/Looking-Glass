"""PostgreSQL access: connection pool, schema bootstrap and small helpers."""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import asyncpg

log = logging.getLogger(__name__)

_pool: asyncpg.Pool | None = None

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


async def connect(dsn: str | None = None, *, retry: bool = True, **kwargs: Any) -> asyncpg.Pool:
    """Open the pool (``dsn`` or asyncpg keyword arguments) and create the schema. ``retry=False`` raises instead."""
    global _pool
    delay = 1.0
    while True:
        try:
            _pool = await asyncpg.create_pool(dsn, min_size=2, max_size=15, init=_init_conn, command_timeout=120,
                                              timeout=15, **kwargs)
            break
        except (OSError, asyncpg.PostgresError, asyncio.TimeoutError) as exc:
            if not retry:
                raise
            if isinstance(exc, (asyncpg.InvalidPasswordError, asyncpg.InvalidAuthorizationSpecificationError)):
                log.error("database login refused (%s). Wrong user/password? To enter the connection again run: "
                          "docker exec looking-glass python -m lookingglass.cli setup-database  (then restart)", exc)
            log.warning("database not reachable yet (%s), retrying in %.0fs", exc, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30)
    schema = (Path(__file__).parent / "schema.sql").read_text()
    async with _pool.acquire() as conn:
        # serialize schema creation between replicas
        await conn.execute("SELECT pg_advisory_lock(424242)")
        try:
            await conn.execute(schema)
        finally:
            await conn.execute("SELECT pg_advisory_unlock(424242)")
    log.info("database ready")
    return _pool


def pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("database not initialised")
    return _pool


async def close() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


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
