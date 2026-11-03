"""Hourly event counts for the dashboards.

Counting raw events over 7 or 30 days on every refresh costs seconds of database CPU per panel. Panels that only count
events per source / action / protocol / interface / direction / port / country / severity read ``event_rollup``
instead: one row per hour and combination, kept up to date every minute from the NEW events only (by event id).

Exact, not an estimate: ``rollup_relation`` combines the hourly counts with the raw events they do not cover yet (the
first, partial hour of the window and the newest events since the last run), so a panel shows the same numbers as
when it counts the raw events.
"""
from __future__ import annotations

import asyncio
import logging

from . import db

log = logging.getLogger(__name__)

BATCH = 500_000  # event ids per step: a large backlog (first start) is counted in slices, not in one heavy query
MIN_HOURS = 48  # windows from this length use the hourly counts (shorter ones: raw events are cheap and finer)

# the event's hour; a time stamp in the future (wrong time zone) counts at its receive time - the hourly repair in
# housekeeping sets ts = received_at for those, so the hour stays the same afterwards
_BUCKET = ("date_trunc('hour', CASE WHEN ts > received_at + interval '2 minutes' THEN received_at ELSE ts END)")
_DIMS = "source, action, proto, interface, direction, dst_port, src_country, severity"

COUNT_SQL = f"""
INSERT INTO event_rollup (bucket, {_DIMS}, n)
SELECT {_BUCKET}, source, coalesce(action, ''), coalesce(proto, ''), coalesce(interface, ''), coalesce(direction, ''),
       coalesce(dst_port, -1), coalesce(src_country, ''), severity, count(*)
FROM events WHERE id > $1 AND id <= $2
GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9
ON CONFLICT (bucket, {_DIMS}) DO UPDATE SET n = event_rollup.n + EXCLUDED.n
"""

_COLS = "ts, source, action, proto, interface, direction, dst_port, src_country, severity"
_START = "now() - make_interval(secs => $1)"
_FIRST_FULL = f"(date_trunc('hour', {_START}) + interval '1 hour')"
# the events of the window ($1 = seconds) as (ts, source, action, ..., n): n events per row. Panels use sum(n) where
# they would use count(*). {upto} is filled in as a number: with a sub-select the planner cannot know how few events
# are newer than it and reads the whole table.
RELATION = f"""(
SELECT bucket AS ts, source, nullif(action, '') AS action, nullif(proto, '') AS proto, nullif(interface, '') AS interface,
       nullif(direction, '') AS direction, nullif(dst_port, -1) AS dst_port, nullif(src_country, '') AS src_country,
       severity, n
  FROM event_rollup WHERE bucket >= {_FIRST_FULL}
UNION ALL
SELECT {_COLS}, 1 FROM events WHERE ts > {_START} AND ts < {_FIRST_FULL} AND id <= {{upto}}
UNION ALL
SELECT {_COLS}, 1 FROM events WHERE id > {{upto}} AND ts > {_START}
) AS e"""


def convert(sql: str, upto: int) -> str:
    """A panel query over raw events, rewritten for the hourly counts: ``FROM events`` -> the combined relation,
    ``count(*)`` -> ``sum(n)`` (also with FILTER). ``upto`` must be read in the same snapshot as the query runs in
    (``fetch``), or events counted in the meantime would be counted twice."""
    return sql.replace("FROM events", "FROM " + RELATION.replace("{upto}", str(int(upto)))).replace("count(*)", "sum(n)")


async def fetch(conn, sql: str, *args):
    """Run a panel query (written for raw events) on the hourly counts, in one consistent snapshot."""
    async with conn.transaction(isolation="repeatable_read", readonly=True):
        upto = await conn.fetchval("SELECT upto FROM event_rollup_state") or 0
        return await conn.fetch(convert(sql, upto), *args)


async def step(batch: int = BATCH, backlog_only: bool = False) -> int:
    """Count the next slice of new events into the hourly table; returns how many event ids it covered.

    Events are counted up to the newest id seen at the PREVIOUS minute's run, never up to the newest one: a batch
    that is still being written (ids taken, not yet committed) is never skipped. ``backlog_only`` (the quick catch-up
    steps between two minutes) only counts full slices below that mark and leaves the mark alone."""
    async with db.pool().acquire() as conn, conn.transaction():
        state = await conn.fetchrow("SELECT upto, seen FROM event_rollup_state FOR UPDATE")  # one runner at a time
        upto, seen = state["upto"], state["seen"]
        if upto == 0:  # first run: start at the oldest event
            upto = (await conn.fetchval("SELECT min(id) - 1 FROM events")) or 0
        new_upto = min(seen, upto + batch)
        if backlog_only and new_upto < upto + batch:
            return 0
        if new_upto > upto:
            await conn.execute(COUNT_SQL, upto, new_upto)
        if not backlog_only:
            seen = await conn.fetchval("SELECT coalesce(max(id), 0) FROM events")
        await conn.execute("UPDATE event_rollup_state SET upto = $1, seen = $2", max(upto, new_upto), max(seen, state["seen"]))
        return max(0, new_upto - upto)


async def prune(retention_days: int) -> None:
    """Hours older than the events themselves are dropped (housekeeping)."""
    await db.pool().execute("DELETE FROM event_rollup WHERE bucket < now() - make_interval(days => $1) - interval '1 hour'",
                            retention_days)


async def loop() -> None:
    """Every minute: count the new events. A backlog (the first start after an update) is worked off in slices with a
    pause in between, so it never takes the whole CPU."""
    while True:
        try:
            await step()
            while await step(backlog_only=True):
                await asyncio.sleep(2)
        except Exception:  # noqa: BLE001
            log.exception("event rollup failed")
        await asyncio.sleep(60)
