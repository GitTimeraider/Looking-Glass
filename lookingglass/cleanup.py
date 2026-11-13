"""One-time cleanup of stored events, run once in the background after an upgrade (a kv key marks it done).

configd (OPNsense's backend) logs a line for every backend action it runs: "[uuid] action allowed system.status for
user root" - about a million a day, filed under "auth" by older versions. New ones are no longer stored
(parsers.security.is_noise) and configd's other lines are "system" events now. This removes the stored ones (from
"auth" and "system": the first version of this cleanup recognised them only at the start of the line and moved the
others - which could be all of them - to "system") and moves configd's other lines, and corrects the hourly counts they
are in (event_rollup for the dashboards, hourly_stats for the hour-of-week baselines), so 7 / 30 day views show the
same as the raw events.

Temporary: remove this module (and its line in main.py) once it has run on the installation.
"""
from __future__ import annotations

import asyncio
import logging

from . import db
from .rollup import _BUCKET

log = logging.getLogger(__name__)

DONE_KEY = "cleanup:configd_noise_v2"  # v1 matched too little: runs again
BATCH = 500_000  # event ids per step (range scan on the primary key, one short transaction each)
START_DELAY = 300  # after the start: the hourly counts catch up first, the start itself is not slowed down
# the same lines as parsers.security._CONFIGD_ROUTINE (PostgreSQL regex, case-insensitive with ~*)
ROUTINE = r"(^|[^[:alnum:]_])action allowed [^[:space:]]+ for user [^[:space:]]+"
_CONFIGD = "source = 'auth' AND program ILIKE 'configd%'"
_STORED = "source IN ('auth', 'system') AND program ILIKE 'configd%'"
_RET = "id, ts, received_at, source, action, proto, interface, direction, dst_port, src_country, severity"
# the counted events of a CTE ($4 = event_rollup_state.upto: newer ones are counted later, as they are now)
_COUNTS = (f"SELECT {_BUCKET} bucket, {{src}} source, coalesce(action, '') action, coalesce(proto, '') proto, "
           "coalesce(interface, '') interface, coalesce(direction, '') direction, coalesce(dst_port, -1) dst_port, "
           "coalesce(src_country, '') src_country, severity, count(*)::int n FROM {cte} WHERE id <= $4 "
           "GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9")
_MATCH = ("r.bucket = c.bucket AND r.source = c.source AND r.action = c.action AND r.proto = c.proto "
          "AND r.interface = c.interface AND r.direction = c.direction AND r.dst_port = c.dst_port "
          "AND r.src_country = c.src_country AND r.severity = c.severity")
_HOURS = "SELECT 'source:' || {src} metric, date_trunc('hour', ts) AS hour, count(*) n FROM {cte} GROUP BY 1, 2"

DELETE_SQL = f"""
WITH d AS (DELETE FROM events WHERE id > $1 AND id <= $2 AND {_STORED} AND message ~* $3 RETURNING {_RET}),
c AS ({_COUNTS.format(cte="d", src="source")}),
r AS (UPDATE event_rollup r SET n = r.n - c.n FROM c WHERE {_MATCH} RETURNING 1),
h AS ({_HOURS.format(cte="d", src="source")}),
s AS (UPDATE hourly_stats x SET value = greatest(0, x.value - h.n) FROM h
      WHERE x.metric = h.metric AND x.hour = h.hour RETURNING 1)
SELECT count(*) FROM d
"""

MOVE_SQL = f"""
WITH m AS (UPDATE events SET source = 'system' WHERE id > $1 AND id <= $2 AND {_CONFIGD} AND NOT message ~* $3
           RETURNING {_RET}),
c AS ({_COUNTS.format(cte="m", src="'auth'::text")}),  -- RETURNING has the new source: counted under auth
r AS (UPDATE event_rollup r SET n = r.n - c.n FROM c WHERE {_MATCH} RETURNING 1),
a AS (INSERT INTO event_rollup (bucket, source, action, proto, interface, direction, dst_port, src_country, severity, n)
      SELECT bucket, 'system', action, proto, interface, direction, dst_port, src_country, severity, n FROM c
      ON CONFLICT (bucket, source, action, proto, interface, direction, dst_port, src_country, severity)
      DO UPDATE SET n = event_rollup.n + EXCLUDED.n RETURNING 1),
h AS ({_HOURS.format(cte="m", src="'auth'::text")}),
s AS (UPDATE hourly_stats x SET value = greatest(0, x.value - h.n) FROM h
      WHERE x.metric = h.metric AND x.hour = h.hour RETURNING 1),
t AS (INSERT INTO hourly_stats (metric, hour, value) SELECT 'source:system', hour, n FROM h
      ON CONFLICT (metric, hour) DO UPDATE SET value = hourly_stats.value + EXCLUDED.value RETURNING 1)
SELECT count(*) FROM m
"""


async def step(lo: int, hi: int) -> tuple[int, int]:
    """Clean events with lo < id <= hi: (deleted, moved). One transaction; it holds the hourly count runner's lock, so
    the events it counted (id <= upto) and the counts are corrected together."""
    async with db.pool().acquire() as conn, conn.transaction():
        upto = await conn.fetchval("SELECT upto FROM event_rollup_state FOR UPDATE") or 0
        deleted = await conn.fetchval(DELETE_SQL, lo, hi, ROUTINE, upto)
        moved = await conn.fetchval(MOVE_SQL, lo, hi, ROUTINE, upto)
        return deleted or 0, moved or 0


async def configd_noise(delay: float = START_DELAY, pause: float = 0.2) -> dict | None:
    """Run the cleanup once (``None`` when it has run before). Resumes where it stopped after a restart."""
    state = await db.kv_get(DONE_KEY) or {}
    if state.get("done"):
        return None
    await asyncio.sleep(delay)
    pool = db.pool()
    bounds = await pool.fetchrow("SELECT min(id) lo, max(id) hi FROM events")
    lo = max(int(state.get("at") or 0), (bounds["lo"] or 1) - 1)
    end = int(state.get("end") or bounds["hi"] or 0)  # newer events are already stored the new way
    deleted, moved = int(state.get("deleted") or 0), int(state.get("moved") or 0)
    if lo < end:
        log.info("one-time cleanup: removing OPNsense configd's routine 'action allowed' lines from the stored events "
                 "(event ids %s-%s, in the background)", lo + 1, end)
    steps = 0
    while lo < end:
        hi = min(lo + BATCH, end)
        d, m = await step(lo, hi)
        deleted, moved, lo, steps = deleted + d, moved + m, hi, steps + 1
        await db.kv_set(DONE_KEY, {"at": lo, "end": end, "deleted": deleted, "moved": moved})
        if steps % 20 == 0:
            log.info("one-time cleanup: %s of %s event ids done, %s lines removed", lo, end, deleted)
        await asyncio.sleep(pause)
    await pool.execute("DELETE FROM event_rollup WHERE n <= 0")
    # the stored 7 / 30 day views (periods.py) are counted again next
    await pool.execute("UPDATE period_results SET computed_at = NULL")
    result = {"done": True, "deleted": deleted, "moved": moved}
    await db.kv_set(DONE_KEY, result)
    log.info("one-time cleanup done: %s configd 'action allowed' lines removed, %s other configd lines moved from "
             "auth to system", deleted, moved)
    return result
