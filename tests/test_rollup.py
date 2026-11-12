import asyncio
import os

import pytest

from lookingglass import cache, db, rollup
from lookingglass.dashboards import DASHBOARDS, ROLLUP_PANELS, step_for
from lookingglass.reports import QUERIES, ROLLUP_QUERIES

DSN = os.environ.get("TEST_DATABASE_URL")

# events over 4 days: several sources / actions, missing values (NULL proto, port, country, action), a time stamp in the
# future (wrong time zone: counted at its receive time) and the window edges
SEED = """
INSERT INTO events (ts, received_at, source, action, proto, interface, direction, dst_port, src_country, severity, src_ip)
SELECT now() - (i * interval '97 seconds'), now() - (i * interval '97 seconds'),
       (ARRAY['firewall','firewall','unbound','nginx','suricata','vpn','unifi','system','auth'])[1 + i % 9],
       (ARRAY['block','pass','query','http_404','block','vpn_connect','client_roam',NULL,'login_failed'])[1 + i % 9],
       CASE WHEN i % 7 = 0 THEN NULL ELSE (ARRAY['tcp','udp','icmp'])[1 + i % 3] END,
       (ARRAY['igb0','igb1',NULL])[1 + i % 3], (ARRAY['in','out'])[1 + i % 2],
       CASE WHEN i % 5 = 0 THEN NULL ELSE (ARRAY[22, 443, 53, 8080])[1 + i % 4] END,
       CASE WHEN i % 4 = 0 THEN NULL ELSE (ARRAY['NL','US','CN'])[1 + i % 3] END,
       (i % 8)::smallint, ('45.0.' || (i % 200) || '.' || (i % 31))::inet
FROM generate_series(1, 3600) i;
INSERT INTO events (ts, received_at, source, action, proto, dst_port, src_country)
VALUES (now() + interval '3 hours', now() - interval '20 hours', 'firewall', 'block', 'tcp', 22, 'NL');
INSERT INTO events (ts, received_at, source, action, interface, src_country, severity)
SELECT now() - (i * interval '1031 seconds'), now() - (i * interval '1031 seconds'), 'suricata',
       (ARRAY['alert','drop','blocked','reject','other'])[1 + i % 5], (ARRAY['igb0',NULL])[1 + i % 2],
       CASE WHEN i % 3 = 0 THEN NULL ELSE (ARRAY['NL','RU'])[1 + i % 2] END, 3
FROM generate_series(1, 400) i;
"""


def same(a, b):
    norm = lambda rows: sorted(tuple(str(v) for v in r.values()) for r in rows)  # noqa: E731
    return norm(a) == norm(b)


async def compare_all(conn) -> int:
    """Every rollup panel: raw events vs hourly counts, in one snapshot (same now()). An event with a future time
    stamp is counted at its receive time right away; the raw events only after the hourly repair (housekeeping) - run
    here first, as it is within the hour."""
    await conn.execute("UPDATE events SET ts = received_at WHERE ts > received_at + interval '2 minutes'")
    checked = 0
    for hours in (48, 168, 720):
        secs, step = hours * 3600, step_for(hours)
        for name, pid in sorted(ROLLUP_PANELS):
            sql = next(p["sql"] for p in DASHBOARDS[name]["panels"] if p["id"] == pid)
            args = [secs, step] if "$2" in sql else [secs]
            async with conn.transaction(isolation="repeatable_read", readonly=True):
                upto = await conn.fetchval("SELECT upto FROM event_rollup_state")
                raw, fast = await conn.fetch(sql, *args), await conn.fetch(rollup.convert(sql, upto), *args)
            assert same(raw, fast), (hours, name, pid)
            checked += 1
        for name in sorted(ROLLUP_QUERIES):
            async with conn.transaction(isolation="repeatable_read", readonly=True):
                upto = await conn.fetchval("SELECT upto FROM event_rollup_state")
                raw = await conn.fetch(QUERIES[name], secs)
                fast = await conn.fetch(rollup.convert(QUERIES[name], upto), secs)
            assert raw and same(raw, fast), (hours, name)
            checked += 1
        # a count with nothing to count gives 0, as on the raw events (sum gives NULL): sources without blocks
        sql = ("SELECT source, count(*) n, count(*) FILTER (WHERE action = 'block' AND proto IN ('tcp')) blocked "
               "FROM events WHERE ts > now() - make_interval(secs => $1) GROUP BY 1")
        async with conn.transaction(isolation="repeatable_read", readonly=True):
            upto = await conn.fetchval("SELECT upto FROM event_rollup_state")
            raw, fast = await conn.fetch(sql, secs), await conn.fetch(rollup.convert(sql, upto), secs)
        assert any(r["blocked"] == 0 for r in raw) and same(raw, fast), hours
    return checked


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_hourly_counts_give_the_same_numbers_as_raw_events():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, event_rollup")
            await pool.execute("UPDATE event_rollup_state SET upto = 0, seen = 0")
            await pool.execute(SEED)
            total = await pool.fetchval("SELECT count(*) FROM events")
            async with pool.acquire() as conn:
                # nothing counted yet: everything comes from the raw events - same numbers
                assert await compare_all(conn) == 3 * (len(ROLLUP_PANELS) + len(ROLLUP_QUERIES))
                await pool.execute("INSERT INTO events (ts, received_at, source, action) VALUES "
                                   "(now() + interval '3 hours', now() - interval '20 hours', 'firewall', 'block')")
                total += 1
                # first run only notes the newest id; the next one counts up to there (never the very newest)
                assert await rollup.step() == 0
                await pool.execute(SEED)  # more events arrive in between: not counted yet, still shown
                assert await rollup.step() > 0
                assert await pool.fetchval("SELECT sum(n) FROM event_rollup") == total
                # the event with a future time stamp counts at its receive time (as the hourly repair will set it)
                assert await pool.fetchval("SELECT count(*) FROM event_rollup WHERE bucket > now()") == 0
                await compare_all(conn)
                await rollup.step()
                assert await pool.fetchval("SELECT sum(n) FROM event_rollup") == await pool.fetchval("SELECT count(*) FROM events")  # each once
                await compare_all(conn)
                # a backlog is worked off in slices
                await pool.execute("TRUNCATE event_rollup")
                await pool.execute("UPDATE event_rollup_state SET upto = 0")
                slices = 0
                while await rollup.step(batch=1000, backlog_only=True):
                    slices += 1
                await rollup.step(batch=10 ** 9)
                assert slices >= 6 and await pool.fetchval("SELECT sum(n) FROM event_rollup") == await pool.fetchval("SELECT count(*) FROM events")
                await compare_all(conn)
            # old hours are dropped with the events
            await pool.execute("INSERT INTO event_rollup VALUES (now() - interval '40 days', 'firewall', 'block', '', '', '', -1, '', 6, 5)")
            await rollup.prune(30)
            assert await pool.fetchval("SELECT count(*) FROM event_rollup WHERE bucket < now() - interval '31 days'") == 0
            await pool.execute("TRUNCATE events, event_rollup")
        finally:
            await db.close()

    asyncio.run(main())


class StillThere:
    """A request whose browser stays connected."""

    async def is_disconnected(self) -> bool:
        return False


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_dashboard_and_overview_use_the_hourly_counts_from_two_days():
    from lookingglass.config import Settings
    from lookingglass.dashboards import run_dashboard
    from lookingglass.reports import timeline
    from lookingglass.web.app import create_app

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, event_rollup")
            await pool.execute(SEED)
            await rollup.step()
            await rollup.step()
            for hours in (24, 168):
                d = await run_dashboard("firewall", hours)
                assert not [p for p in d["panels"] if p.get("error")]
                assert d["step"] == step_for(hours)
                tl = await timeline(hours)
                assert tl["series"] and (tl["step"] % 3600 == 0) == (hours >= 48)
            app = create_app(Settings(secret_key="x" * 40), None)
            ov = next(r.endpoint for r in app.routes if getattr(r, "path", "") == "/api/overview")
            await pool.execute("TRUNCATE period_results")
            for hours in (24, 168):
                out = await ov(request=StillThere(), hours=hours)
                if hours == 168:  # 7 days: never counted when asked - counted in the background (periods.py)
                    assert out["pending"] and out["refreshing"]
                    periods = app.state.periods
                    await periods.count(periods.urgent.pop(0))
                    out = await ov(request=StillThere(), hours=hours)
                    assert out["long"] and out["as_of"] and not out["refreshing"]
                kpi = out["kpi"]
                raw = await pool.fetchrow(
                    "SELECT count(*) total, count(DISTINCT src_ip) FILTER (WHERE action IN ('block', 'drop')) ips "
                    "FROM events WHERE ts > now() - make_interval(secs => $1)", hours * 3600)
                assert kpi["total"] == raw["total"] and kpi["blocked_ips"] == raw["ips"]
                assert isinstance(kpi["login_failed"], int)
            await pool.execute("TRUNCATE events, event_rollup")
        finally:
            await db.close()

    asyncio.run(main())


def test_chart_steps_are_whole_hours_from_two_days():
    assert [step_for(h) for h in (1, 6, 24)] == [60, 360, 1440]
    assert [step_for(h) for h in (48, 168, 720)] == [3600, 10800, 43200]


def test_result_cache_shares_one_computation():
    async def main():
        c = cache.ResultCache()
        calls = []

        async def compute():
            calls.append(1)
            await asyncio.sleep(0.05)
            return {"n": len(calls)}

        # three tabs at once: one computation
        out = await asyncio.gather(*(c.get("k", 30, compute) for _ in range(3)))
        assert calls == [1] and out == [{"n": 1}] * 3
        assert await c.get("k", 30, compute) == {"n": 1}  # within its time: no new computation
        assert await c.get("k", 0, compute) == {"n": 2}  # expired
        # an error is not kept: the next request tries again
        async def broken():
            raise RuntimeError("db down")
        with pytest.raises(RuntimeError):
            await c.get("x", 30, broken)
        assert await c.get("x", 30, compute) == {"n": 3}
        assert cache.ttl_for(24) == 30 and cache.ttl_for(168) == 120 and cache.ttl_for(720) == 300

    asyncio.run(main())


def test_result_cache_stops_work_nobody_waits_for():
    """Picking another period while a long one loads must stop its queries, not queue them up (that kept the database
    busy - and every page waiting - for half an hour)."""
    async def main():
        c = cache.ResultCache()
        state = []

        async def slow():
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                state.append("cancelled")
                raise
            return 1

        a = asyncio.ensure_future(c.get("y", 30, slow))
        b = asyncio.ensure_future(c.get("y", 30, slow))  # a second tab waits for the same computation
        await asyncio.sleep(0.01)
        a.cancel()
        await asyncio.sleep(0.01)
        assert state == [] and "y" in c.running  # still wanted by the second one
        b.cancel()
        await asyncio.sleep(0.01)
        assert state == ["cancelled"] and "y" not in c.running and "y" not in c.items

        async def quick():
            return 2
        assert await c.get("y", 30, quick) == 2  # the next request starts afresh

    asyncio.run(main())


def test_result_cache_answers_a_recent_result_at_once_and_refreshes_it():
    async def main():
        c = cache.ResultCache()
        calls = []

        async def compute():
            calls.append(1)
            await asyncio.sleep(0.05)
            return len(calls)

        assert (await c.fetch("k", 30, compute, stale=60))[::2] == (1, False)
        c.items["k"] = (c.items["k"][0] - 40, *c.items["k"][1:])  # expired 10 s ago, still within "stale"
        value, _, stale = await c.fetch("k", 30, compute, stale=60)
        assert (value, stale) == (1, True)  # at once, not after the computation
        assert "k" in c.running
        # someone waiting on it and leaving does not stop the background refresh
        await asyncio.sleep(0.1)
        assert c.items["k"][2] == 2 and calls == [1, 1]
        assert (await c.fetch("k", 30, compute, stale=60))[::2] == (2, False)
        # too old: waits for a new one
        c.items["k"] = (c.items["k"][0] - 100, *c.items["k"][1:])
        assert (await c.fetch("k", 30, compute, stale=60))[::2] == (3, False)
        assert cache.stale_for(1) == 180 and cache.stale_for(720) == 3600 and cache.stale_for(0.1) == 30

    asyncio.run(main())


def test_a_dashboard_request_stops_when_the_browser_has_gone():
    from lookingglass.web.app import ClientGone, until_disconnected

    class Leaves:
        def __init__(self):
            self.asked = 0

        async def is_disconnected(self) -> bool:
            self.asked += 1
            return self.asked > 1

    async def main():
        c = cache.ResultCache()
        state = []

        async def slow():
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                state.append("cancelled")
                raise

        with pytest.raises(ClientGone):
            await until_disconnected(Leaves(), c.get("k", 30, slow), poll=0.01)
        await asyncio.sleep(0.01)
        assert state == ["cancelled"] and not c.running
        assert await until_disconnected(StillThere(), asyncio.sleep(0.02, "ok"), poll=0.01) == "ok"

    asyncio.run(main())


def test_other_periods_are_computed_ahead_of_time_at_low_priority():
    async def main():
        c = cache.ResultCache()
        seen = []

        async def compute(tag):
            async with db.heavy(720) as slot:
                seen.append((tag, slot.sem is db._heavy[3]))  # the low-priority slot?
                await asyncio.sleep(0.05)
            return tag

        c.warm("a", lambda: compute("a"), stale=60)
        c.warm("b", lambda: compute("b"), stale=60)
        c.warm("a", lambda: compute("a"), stale=60)  # already queued: once
        await c.worker
        assert seen == [("a", True), ("b", True)] and c.items["a"][2] == "a"
        c.warm("a", lambda: compute("again"), stale=60)  # fresh enough: not again
        assert not c.queue

        # a page asking for a period that is being computed ahead of time: same computation, now at full speed
        async def two_queries():
            for i in range(2):
                async with db.heavy(720) as slot:
                    seen.append(("c", slot.sem is db._heavy[3]))
                    await asyncio.sleep(0.05)
            return "c"

        seen.clear()
        c.warm("c", two_queries, stale=60)
        await asyncio.sleep(0.01)
        assert await c.get("c", 30, two_queries) == "c"
        assert seen == [("c", True), ("c", False)]

        # work ahead of time never holds up a page: its slot is apart from the normal queues
        hold = asyncio.Event()

        async def busy():
            async with db.heavy(720):
                await hold.wait()

        c.warm("d", busy, stale=60)
        await asyncio.sleep(0.01)
        async with db.heavy(720) as slot:
            assert slot.sem is db._heavy[1]
        hold.set()
        await c.worker

    asyncio.run(main())


def test_counts_are_rewritten_with_zero_for_nothing_counted():
    """count(*) gives 0 where nothing matches, sum(n) NULL: the rewrite keeps the 0 (also with FILTER)."""
    sql = ("SELECT count(*) n, count(*) FILTER (WHERE x LIKE 'Crowd (%' OR y IN (1, 2)) c, count(*)::bigint m, "
           "count(DISTINCT src_ip) d FROM events")
    out = rollup.convert(sql, 5)
    assert "event_rollup" in out and "id <= 5" in out
    assert out.startswith("SELECT coalesce(sum(n), 0) n, coalesce(sum(n) FILTER (WHERE x LIKE 'Crowd (%' OR y IN (1, 2)), 0) c, "
                          "coalesce(sum(n), 0)::bigint m, count(DISTINCT src_ip) d FROM ")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_dashboard_indexes_are_built_in_the_background():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            valid = "SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass($1)"
            for name in db.BACKGROUND_INDEXES:
                await pool.execute(f"DROP INDEX IF EXISTS {name}")
            await pool.execute("CREATE INDEX IF NOT EXISTS events_source_ts_idx ON events (source, ts DESC)")
            # one left unfinished (invalid) by an interrupted build
            await pool.execute("CREATE INDEX events_block_idx ON events (ts)")
            await pool.execute("UPDATE pg_index SET indisvalid = false WHERE indexrelid = 'events_block_idx'::regclass")
            await db.build_background_indexes()
            for name in db.BACKGROUND_INDEXES:
                assert await pool.fetchval(valid, name) is True, name
            assert "INCLUDE" in await pool.fetchval("SELECT pg_get_indexdef('events_block_idx'::regclass)")
            # the plain (source, ts) index is replaced by the covering one
            assert await pool.fetchval("SELECT to_regclass('events_source_ts_idx')") is None
            await db.build_background_indexes()  # all there: nothing to do
            # the dashboard queries over blocklist lines can use their index: on a small test table the planner may
            # as well pick any other index or read it whole, so (in a transaction that is rolled back) the other indexes
            # are dropped and a sequential scan is ruled out - it must then use this one
            async with pool.acquire() as conn:
                tr = conn.transaction()
                await tr.start()
                try:
                    for (other,) in await conn.fetch(
                            "SELECT c.relname FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
                            "WHERE i.indrelid = 'events'::regclass AND NOT i.indisprimary "
                            "AND c.relname <> 'events_blocklist_idx'"):
                        await conn.execute(f'DROP INDEX "{other}"')
                    await conn.execute("SET LOCAL enable_seqscan = off")
                    plan = "\n".join(r[0] for r in await conn.fetch(
                        "EXPLAIN SELECT count(*) FROM events WHERE source = 'firewall' "
                        "AND lower(data->>'blocklist') = 'q-feeds' AND ts > now() - interval '1 day'"))
                finally:
                    await tr.rollback()
            assert "events_blocklist_idx" in plan, plan
            assert await pool.fetchval(valid, "events_block_idx") is True  # rolled back: all still there
        finally:
            await db.close()

    asyncio.run(main())
