"""7 / 30 day views: counted on a schedule in the background, served from the stored result (periods.py)."""
import asyncio
import os

import pytest

from lookingglass import db
from lookingglass.config import Settings
from lookingglass.periods import Periods, is_long, key_of

DSN = os.environ.get("TEST_DATABASE_URL")


def test_only_periods_over_a_day_are_scheduled():
    assert not is_long(1) and not is_long(24) and is_long(168) and is_long(720)
    s = Settings(secret_key="x" * 40)
    p = Periods(s, {})
    assert p.interval_s(168) == s.long_refresh_7d * 60 and p.interval_s(720) == s.long_refresh_30d * 60


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_long_periods_are_counted_in_the_background_and_served_from_the_store():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE period_results")
            calls = []
            fail = {"on": False}

            async def overview(hours):
                calls.append(hours)
                if fail["on"]:
                    raise RuntimeError("query timed out")
                return {"n": len(calls), "hours": hours}

            s = Settings(secret_key="x" * 40)
            p = Periods(s, {"overview": overview})
            k30 = key_of("overview", 720.0)

            # never counted: nothing is counted on the request, it is queued
            got = await p.get("overview", 720.0)
            assert got["data"] is None and got["refreshing"] and calls == [] and p.urgent == [k30]
            assert await p._next() == k30
            await p.count(k30)
            got = await p.get("overview", 720.0)
            assert got["data"] == {"n": 1, "hours": 720.0} and not got["refreshing"] and got["as_of"]
            assert got["next"] - got["as_of"] == pytest.approx(s.long_refresh_30d * 60)
            # asking again counts nothing: the stored result, also after a restart (new instance, empty memory)
            p2 = Periods(s, {"overview": overview})
            assert (await p2.get("overview", 720.0))["data"] == {"n": 1, "hours": 720.0} and calls == [720.0]
            assert await p2._next() is None  # not due yet

            # due once older than the interval
            await pool.execute("UPDATE period_results SET computed_at = now() - interval '7 hours' WHERE key = $1", k30)
            assert await p2._next() == k30
            # the refresh button jumps the queue (and is not queued twice)
            k7 = key_of("overview", 168.0)
            p2.refresh(k7)
            p2.refresh(k7)
            assert p2.urgent == [k7] and (await p2.get("overview", 168.0))["refreshing"]
            assert await p2._next() == k7

            # a failing count keeps the previous result and reports the error; it is not retried right away
            fail["on"] = True
            await p2.count(k30)
            got = await p2.get("overview", 720.0)
            assert got["data"] == {"n": 1, "hours": 720.0} and "timed out" in got["error"]
            assert await p2._next() == k7  # the 30 days not again right away; the 7 days (never counted) is due
            fail["on"] = False

            # not looked at for over a week: no longer counted
            await pool.execute("UPDATE period_results SET computed_at = now() - interval '2 days', "
                               "viewed_at = now() - interval '8 days'")
            assert await p2._next() is None
            # a kind that no longer exists is dropped
            await pool.execute("INSERT INTO period_results (key, hours) VALUES ($1, 720)", '["gone", 720.0]')
            await p2.count('["gone", 720.0]')
            assert not await pool.fetchval("SELECT count(*) FROM period_results WHERE key LIKE '%gone%'")
            await pool.execute("TRUNCATE period_results")
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_dashboard_long_period_and_refresh_button():
    from fastapi import HTTPException

    from lookingglass.web.app import create_app

    class StillThere:
        async def is_disconnected(self):
            return False

    async def main():
        await db.connect(DSN)
        try:
            await db.pool().execute("TRUNCATE period_results")
            app = create_app(Settings(secret_key="x" * 40), None)
            ep = {r.path: r.endpoint for r in app.routes if hasattr(r, "endpoint")}
            dash, refresh = ep["/api/dash/{name}"], ep["/api/periods/refresh"]
            p = app.state.periods
            out = await dash(request=StillThere(), name="threats", hours=720, tab=None)
            assert out["pending"]
            # no tab and the first tab are one stored result
            assert p.urgent == [key_of("dash", "threats", "main", 720.0)]
            await p.count(p.urgent.pop(0))
            out = await dash(request=StillThere(), name="threats", hours=720, tab="main")
            assert out["long"] and out["panels"] is not None and not out["refreshing"]
            # refresh button
            await refresh(payload={"kind": "dash", "name": "threats", "tab": None, "hours": 720})
            assert p.urgent == [key_of("dash", "threats", "main", 720.0)]
            for bad in ({"kind": "dash", "name": "threats", "hours": 24}, {"kind": "dash", "name": "nope", "hours": 720},
                        {"kind": "x", "hours": 720}, {"kind": "overview"}):
                with pytest.raises(HTTPException):
                    await refresh(payload=bad)
            # short periods are still counted live
            out = await dash(request=StillThere(), name="threats", hours=24, tab=None)
            assert "long" not in out and "panels" in out
            await db.pool().execute("TRUNCATE period_results")
        finally:
            await db.close()

    asyncio.run(main())
