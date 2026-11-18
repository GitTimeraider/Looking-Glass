import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest

from lookingglass import db, timeline, wan
from lookingglass.config import Settings
from lookingglass.parsers.common import event

DSN = os.environ.get("TEST_DATABASE_URL")


def test_wan_judge():
    s = Settings()
    cur = {"n_delay": 1000, "n_loss": 1000, "p50": 30.0, "loss": 0.1}
    assert wan.judge(s, cur, 12.0, 7)["latency"]  # 2.5x and 18 ms above
    assert not wan.judge(s, {**cur, "p50": 20.0}, 12.0, 7)["latency"]  # < 2x
    assert not wan.judge(s, {**cur, "p50": 5.0}, 2.0, 7)["latency"]  # 2.5x but only 3 ms: fibre jitter
    assert not wan.judge(s, cur, 12.0, 2)["latency"]  # too little history
    assert not wan.judge(s, {**cur, "n_delay": 5}, 12.0, 7)["latency"]
    v = wan.judge(s, {**cur, "loss": 3.0}, 12.0, 7)
    assert v["loss"] and v["loss_severity"] == "low"
    assert wan.judge(s, {**cur, "loss": 25.0}, 12.0, 7)["loss_severity"] == "medium"
    assert not wan.judge(Settings(wan_loss_pct=0), {**cur, "loss": 50.0}, 12.0, 7)["loss"]


def test_gateway_prefs_and_monitoring():
    p = wan.clean_prefs({"order": ["B", "A", "B"], "hidden": ["A", "C"], "ignored": ["C"]})
    assert p == {"order": ["B", "A"], "hidden": ["A"], "ignored": ["C"]}
    with pytest.raises(ValueError):
        wan.clean_prefs({"order": "A"})
    assert wan.monitored({"delay": "12.1 ms", "loss": "0.0 %"})
    assert not wan.monitored({"delay": "~", "loss": "~", "status": "none"})  # VPN gateway without monitoring
    assert wan.monitored({"delay": "~", "loss": "~", "status": "down"})


def test_timeline_steps_and_span():
    assert timeline.step_for(1) == 60 and timeline.step_for(24) == 600 and timeline.step_for(168) == 3600
    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    t0, t1 = timeline.span(24, now=now)
    assert t1 - t0 == timedelta(hours=24)
    t0, t1 = timeline.span(None, "2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z")
    assert t1 - t0 == timedelta(hours=timeline.MAX_HOURS)
    with pytest.raises(ValueError):
        timeline.span(None, "2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_wan_rollup_and_alerts():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE metrics, wan_daily, alerts")
            await pool.execute("DELETE FROM snapshots WHERE key = 'gateways'")
            await pool.execute("DELETE FROM kv WHERE key = 'wan_gateways'")
            now = datetime.now(timezone.utc)
            rows = []
            # 10 days of 10 ms, then the last 24 hours 40 ms with 5 % loss and a short outage
            for h in range(240, 0, -1):
                t = now - timedelta(hours=h)
                bad = h <= 23
                for m in range(0, 60, 10):
                    ts = t + timedelta(minutes=m)
                    rows += [(ts, "gateway_delay_ms", "WAN", 40.0 if bad else 10.0),
                             (ts, "gateway_loss_pct", "WAN", 5.0 if bad else 0.0),
                             (ts, "gateway_up", "WAN", 0.0 if bad and m == 0 and h == 5 else 1.0)]
            await pool.executemany("INSERT INTO metrics (ts, name, labels, value) VALUES ($1, $2, $3, $4)", rows)
            s = Settings(timezone="UTC")
            assert await wan.rollup(s, full=True) >= 10
            day = await pool.fetchrow("SELECT * FROM wan_daily WHERE day = (now() - interval '5 days')::date")
            assert day["delay_p50"] == 10.0 and day["samples"] == 144 and day["up_samples"] == 144
            await wan.check(s)
            al = {r["rule"]: r for r in await pool.fetch("SELECT rule, severity, status FROM alerts")}
            assert al["wan_latency"]["status"] == "open" and al["wan_loss"]["status"] == "open"
            ov = await wan.overview(s, 30)
            g = ov["gateways"][0]
            assert g["name"] == "WAN" and g["baseline"] == 10.0 and g["last24"]["down"] == 1
            assert g["p7"]["availability"] < 100
            # the line recovers: both close by themselves
            await pool.execute("UPDATE metrics SET value = CASE name WHEN 'gateway_delay_ms' THEN 10 ELSE 0 END "
                               "WHERE ts > now() - interval '24 hours' AND name <> 'gateway_up'")
            await wan.check(s)
            assert {r["status"] for r in await pool.fetch("SELECT status FROM alerts")} == {"closed"}
            await pool.execute("TRUNCATE metrics, wan_daily, alerts")
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_timeline_merges_alerts_events_and_blocks():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, alerts, devices, blocks, snoozes")
            await pool.execute("INSERT INTO devices (mac, ip, ips, hostname, first_seen) VALUES "
                               "('aa:bb:cc:dd:ee:ff', '192.168.1.20', '{192.168.1.20,192.168.20.5}', 'laptop', "
                               "now() - interval '2 hours')")
            now = datetime.now(timezone.utc)
            # the 50 lookups inside one 10-minute step (the timeline's step for 6 hours), whatever the clock says
            step = now.replace(minute=now.minute - now.minute % 10, second=0, microsecond=0) - timedelta(minutes=30)
            evs = [event(step + timedelta(minutes=1, seconds=i), "unbound", host="t", severity=6, action="query",
                         src_ip="192.168.1.20", domain="example.com") for i in range(50)]
            evs += [event(now - timedelta(minutes=20), "firewall", host="t", severity=6, action="block", direction="out",
                          src_ip="192.168.20.5", dst_ip="203.0.113.9", dst_port=4444, proto="tcp")]
            evs += [event(now - timedelta(minutes=10), "auth", host="t", severity=5, action="login_failed",
                          src_ip="203.0.113.50", dst_ip="192.168.1.20", username="root")]
            evs += [event(now - timedelta(minutes=10), "firewall", host="t", severity=6, action="block",
                          src_ip="192.168.1.99", dst_ip="8.8.8.8")]  # another device
            await db.copy_events(evs)
            await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint, src_ip) VALUES "
                               "('beaconing', 'medium', 'beacon', 'b', '192.168.20.5')")
            await pool.execute("INSERT INTO blocks (ip, created_by) VALUES ('203.0.113.9', 'me')")
            out = await timeline.build(mac="aa:bb:cc:dd:ee:ff", hours=6)
            assert out["ips"] == ["192.168.1.20", "192.168.20.5"] and out["device"]["hostname"] == "laptop"
            kinds = [(i["kind"], i["cat"]) for i in out["items"]]
            assert ("alert", "alert") in kinds and ("first_seen", "device") in kinds
            dns = [i for i in out["items"] if i["cat"] == "dns"]
            assert len(dns) == 1 and dns[0]["n"] == 50 and dns[0]["outgoing"]
            fw = [i for i in out["items"] if i["cat"] == "firewall"]
            assert len(fw) == 1 and fw[0]["peer"] == "203.0.113.9" and fw[0]["dst_port"] == 4444
            assert any(i["cat"] == "login" and not i["outgoing"] for i in out["items"])
            assert out["counts"]["dns"] == 50 and sum(c["n"] for c in out["chart"]) == 52
            assert not any(i["kind"] == "block" for i in out["items"])  # the block is for the remote side
            by_ip = await timeline.build(ip="203.0.113.9", hours=6)
            assert any(i["kind"] == "block" for i in by_ip["items"])
            await pool.execute("TRUNCATE events, alerts, devices, blocks")
        finally:
            await db.close()

    asyncio.run(main())



@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_ignored_gateways_are_not_collected_or_alerted():
    from lookingglass.detections import DetectionEngine
    from lookingglass.opnsense import Poller

    class Api:
        async def get(self, path):
            return {"items": [{"name": "WAN", "status": "none", "delay": "9 ms", "loss": "0 %", "stddev": "1 ms"},
                              {"name": "OLD", "status": "down", "status_translated": "Offline", "delay": "0 ms", "loss": "100 %"},
                              {"name": "VPN", "status": "none", "delay": "~", "loss": "~", "stddev": "~"}]}

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE metrics, alerts, wan_daily")
            await pool.execute("DELETE FROM kv WHERE key = 'wan_gateways'")
            poller = Poller.__new__(Poller)
            poller.api = Api()
            await poller.poll_gateways()
            await DetectionEngine(Settings()).system_health()
            got = {(r["name"], r["labels"]) for r in await pool.fetch("SELECT name, labels FROM metrics")}
            assert ("gateway_up", "OLD") in got and ("gateway_up", "WAN") in got
            assert not any(lbl == "VPN" for _, lbl in got)  # unmonitored: no made-up "up" samples
            assert await pool.fetchval("SELECT status FROM alerts WHERE rule = 'gateway_down'") == "open"
            await wan.save_prefs({"order": ["VPN", "WAN"], "ignored": ["OLD"], "hidden": ["VPN"]})
            assert await pool.fetchval("SELECT status FROM alerts WHERE rule = 'gateway_down'") == "closed"
            await pool.execute("TRUNCATE metrics, alerts")
            await poller.poll_gateways()
            await DetectionEngine(Settings()).system_health()
            assert not await pool.fetchval("SELECT count(*) FROM metrics WHERE labels = 'OLD'")
            assert not await pool.fetchval("SELECT count(*) FROM alerts")
            await db.set_snapshot("gateways", (await Api().get(""))["items"])
            ov = await wan.overview(Settings(), 30)
            names = [g["name"] for g in ov["gateways"]]
            assert names[:2] == ["VPN", "WAN"]
            by = {g["name"]: g for g in ov["gateways"]}
            assert by["OLD"]["ignored"] and by["VPN"]["hidden"] and by["VPN"]["unmonitored"] and not by["WAN"]["unmonitored"]
            await pool.execute("TRUNCATE metrics, alerts")
            await pool.execute("DELETE FROM kv WHERE key = 'wan_gateways'")
            await pool.execute("DELETE FROM snapshots WHERE key = 'gateways'")
        finally:
            await db.close()

    asyncio.run(main())
