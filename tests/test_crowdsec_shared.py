"""OPNsense's CrowdSec plugin using the Docker CrowdSec's Local API: recognised, each alert stored and counted once."""
import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest

from lookingglass import crowdsec_shared, db, rollup
from lookingglass.config import Settings
from lookingglass.crowdsec_lapi import alert_events
from lookingglass.parsers.security import crowdsec_alert_from_api, crowdsec_decision_from_api

DSN = os.environ.get("TEST_DATABASE_URL")
BOTH = dict(opnsense_url="https://fw.test", opnsense_api_key="k", opnsense_api_secret="s",
            crowdsec_lapi_url="http://cs:8080", crowdsec_lapi_machine="lg", crowdsec_lapi_password="pw")


def lapi_alert(aid, ip, did, scenario="crowdsecurity/http-probing", ts=None):
    ts = (ts or datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    return {"id": aid, "scenario": scenario, "created_at": ts, "start_at": ts, "events_count": 5,
            "source": {"ip": ip, "scope": "Ip", "value": ip, "cn": "NL"},
            "decisions": [{"id": did, "type": "ban", "scope": "Ip", "value": ip, "origin": "crowdsec", "duration": "4h"}]}


def plugin_rows(aid, ip, did, scenario="crowdsecurity/http-probing"):
    """The same alert and decision as the OPNsense plugin lists them (cscli on OPNsense against that Local API)."""
    ts = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    return (crowdsec_alert_from_api({"id": aid, "value": f"Ip:{ip}", "reason": scenario, "created": ts}),
            crowdsec_decision_from_api({"id": did, "scope_value": f"Ip:{ip}", "reason": scenario, "action": "ban",
                                        "source": "crowdsec", "expiration": "3h59m"}))


def test_event_key_matches_both_sides():
    a, d = plugin_rows(41, "203.0.113.7", 90)
    assert crowdsec_shared.event_key(a) == "a|41|203.0.113.7" and crowdsec_shared.event_key(d) == "d|90|203.0.113.7"
    assert crowdsec_shared.mode(Settings(crowdsec_shared_lapi="YES")) == "yes"
    assert not crowdsec_shared.possible(Settings(opnsense_url="https://fw.test", opnsense_api_key="k", opnsense_api_secret="s"))


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_shared_local_api_is_recognised_and_counted_once():
    from lookingglass.dashboards import run_dashboard

    async def main():
        await db.connect(DSN)
        pool = db.pool()
        try:
            await pool.execute("TRUNCATE events, alerts, event_rollup")
            await pool.execute("DELETE FROM snapshots WHERE key = $1", crowdsec_shared.KEY)
            await pool.execute("UPDATE event_rollup_state SET upto = 0, seen = 0")
            pairs = [(41, "203.0.113.7", 90), (42, "198.51.100.8", 91), (43, "192.0.2.9", 92)]
            lapi = [ev for aid, ip, did in pairs for ev in alert_events(lapi_alert(aid, ip, did))]
            plugin = [ev for aid, ip, did in pairs for ev in plugin_rows(aid, ip, did)]
            # before it was recognised: the plugin's copies were stored too, and already counted hourly
            await db.copy_events(lapi + plugin)
            while await rollup.step():
                pass
            await rollup.step()
            before = await pool.fetchval("SELECT sum(n) FROM event_rollup WHERE source = 'crowdsec'")
            assert before == 12
            settings = Settings(**BOTH)
            assert not await crowdsec_shared.is_shared(settings)
            # a pull of the plugin: the same ids for the same addresses -> one Local API, the copies go
            assert await crowdsec_shared.sync(settings, plugin)
            assert await crowdsec_shared.is_shared(settings)
            left = await pool.fetch("SELECT program, count(*) n FROM events WHERE source = 'crowdsec' GROUP BY 1")
            assert {r["program"]: r["n"] for r in left} == {"crowdsec-lapi": 6}
            assert await pool.fetchval("SELECT sum(n) FROM event_rollup WHERE source = 'crowdsec'") == 6
            state = await db.get_snapshot(crowdsec_shared.KEY)
            assert state["shared"] and state["matched"] == 6 and state["removed"] == 6 and state["cleaned"]
            # later pulls: still shared, nothing more to remove
            assert await crowdsec_shared.sync(settings, plugin)
            # the Threats › CrowdSec page reads the Local API's events, each alert once
            thr = {p["id"]: p for p in (await run_dashboard("threats", 24, tab="crowdsec", shared_cs=True))["panels"]}
            assert not [p["error"] for p in thr.values() if p.get("error")]
            assert thr["cs_kpi"]["rows"][0]["Alerts"] == 3
            assert "not_program" not in thr["cs_kpi"]["drill"]["tiles"]["Alerts"]
            # switched off: kept apart again (and the Threats page reads only the plugin's events - none now)
            assert not await crowdsec_shared.is_shared(Settings(**BOTH, crowdsec_shared_lapi="no"))
            thr = {p["id"]: p for p in (await run_dashboard("threats", 24, tab="crowdsec"))["panels"]}
            assert thr["cs_kpi"]["rows"][0]["Alerts"] == 0
        finally:
            await pool.execute("TRUNCATE events, alerts, event_rollup")
            await pool.execute("DELETE FROM snapshots WHERE key = $1", crowdsec_shared.KEY)
            await db.close()
    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_two_separate_crowdsecs_stay_apart():
    async def main():
        await db.connect(DSN)
        pool = db.pool()
        try:
            await pool.execute("TRUNCATE events, alerts")
            await pool.execute("DELETE FROM snapshots WHERE key = $1", crowdsec_shared.KEY)
            # each numbers its alerts itself: id 41 here is another address there
            lapi = [ev for i in range(25) for ev in alert_events(lapi_alert(100 + i, f"203.0.113.{i + 1}", 500 + i))]
            await db.copy_events(lapi)
            plugin = [ev for i in range(25) for ev in plugin_rows(100 + i, f"198.51.100.{i + 1}", 500 + i)]
            settings = Settings(**BOTH)
            assert not await crowdsec_shared.sync(settings, plugin)
            assert (await db.get_snapshot(crowdsec_shared.KEY))["shared"] is False
            # yes: forced, whatever the ids say
            assert await crowdsec_shared.sync(Settings(**BOTH, crowdsec_shared_lapi="yes"), plugin)
        finally:
            await pool.execute("TRUNCATE events, alerts")
            await pool.execute("DELETE FROM snapshots WHERE key = $1", crowdsec_shared.KEY)
            await db.close()
    asyncio.run(main())
