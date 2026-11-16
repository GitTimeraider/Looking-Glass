"""Suspicious outbound port alerts: the firewall verdict of a NAT-only log line, which other alerts count as
corroboration, and repeats of an alert you closed as false positive."""
import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest

from lookingglass import db
from lookingglass.config import Settings, get_settings
from lookingglass.detections import DetectionEngine, raise_alert, verdict, was_blocked
from lookingglass.parsers.common import event

from test_behavior_intel import reset

DSN = os.environ.get("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
NOW = datetime.now(timezone.utc)
PC, IRC = "192.168.3.3", "45.79.152.218"


def run(coro_fn):
    async def main():
        await db.connect(DSN)
        try:
            await reset(db.pool())
            await coro_fn(db.pool())
            await reset(db.pool())
        finally:
            await db.close()
    asyncio.run(main())


def test_verdict_without_a_block_is_not_blocked():
    assert verdict(True) == "ALLOWED"
    assert verdict(False, 2, "Block LAN").startswith("blocked by the OPNsense firewall")
    assert verdict(False, 0).startswith("not blocked")
    assert was_blocked(False, 1) and not was_blocked(False, 0) and not was_blocked(True, 3)


async def alerts(pool):
    return [dict(r) for r in await pool.fetch("SELECT id, title, severity, status, close_reason, description, data "
                                               "FROM alerts WHERE rule = 'suspicious_outbound_port' ORDER BY id")]


def irc(minutes_ago=1, action="nat"):
    return event(NOW - timedelta(minutes=minutes_ago), "firewall", severity=6, action=action, src_ip=PC, dst_ip=IRC,
                 src_port=40796, dst_port=6697, proto="tcp", interface="pppoe0", direction="out",
                 data={"rulenr": "12", "tcpflags": "S"})


@needs_db
def test_outbound_nat_line_is_allowed_not_blocked():
    """'nat out on pppoe0' (outbound NAT rule 12, the only line logged) = the connection left: ALLOWED."""
    async def body(pool):
        await db.copy_events([irc()])
        await DetectionEngine(Settings()).suspicious_outbound_ports()
        [a] = await alerts(pool)
        assert a["title"].endswith("ALLOWED") and "blocked" not in a["title"]
        assert not a["data"].get("blocked") and "ALLOWED" in a["description"]
    run(body)


@needs_db
def test_unrelated_blocked_alert_does_not_corroborate():
    """A blocked threat-feed lookup of www.tiktok.com says nothing about an IRC connection of the same PC; a serious
    alert, or one about the same remote address, still does - and the reason names the alert."""
    async def body(pool):
        await raise_alert("threat_feed", "medium", f"{PC} looked up a known malicious domain: www.tiktok.com",
                          f"feed:{PC}:tiktok.com", src_ip=PC, blocked="the lookup was blocked")
        await db.copy_events([irc()])
        await DetectionEngine(Settings()).suspicious_outbound_ports()
        [a] = await alerts(pool)
        assert a["severity"] == "medium" and "also seen by other sources" not in a["description"]

        await reset(pool)
        await raise_alert("tor", "low", f"{PC} tries to connect to the Tor network", f"tor:{PC}", src_ip=PC, dst_ip=IRC,
                          blocked="the connection was blocked")
        await db.copy_events([irc()])
        await DetectionEngine(Settings()).suspicious_outbound_ports()
        [a] = await alerts(pool)
        tor_id = await pool.fetchval("SELECT id FROM alerts WHERE rule = 'tor'")
        assert a["severity"] == "high" and f"open alerts: tor #{tor_id}" in a["description"]
    run(body)


@needs_db
def test_repeat_of_false_positive_is_closed_unless_worse():
    async def body(pool):
        s = get_settings()
        old = s.fp_repeat
        try:
            # an earlier alert, closed as false positive, last seen 3 days ago
            await db.copy_events([irc()])
            eng = DetectionEngine(Settings())
            await eng.suspicious_outbound_ports()
            [first] = await alerts(pool)
            await pool.execute("UPDATE alerts SET status = 'closed', close_reason = 'false_positive', "
                               "last_seen = now() - interval '3 days', created_at = now() - interval '3 days'")
            # the same again: stored closed, pointing to the first one
            await db.copy_events([irc()])
            await eng.suspicious_outbound_ports()
            rep = (await alerts(pool))[-1]
            assert rep["status"] == "closed" and rep["close_reason"] == "known_false_positive"
            assert rep["data"]["repeat_of"]["id"] == first["id"] and f"#{first['id']}" in rep["description"]
            # and the chain continues from the repeat (origin stays the alert you closed)
            await pool.execute("UPDATE alerts SET last_seen = now() - interval '2 days' WHERE id = $1", rep["id"])
            await db.copy_events([irc()])
            await eng.suspicious_outbound_ports()
            rep2 = (await alerts(pool))[-1]
            assert rep2["close_reason"] == "known_false_positive" and rep2["data"]["repeat_of"]["id"] == first["id"]
            await pool.execute("UPDATE alerts SET last_seen = now() - interval '2 days' WHERE id = $1", rep2["id"])
            # another server on the same port: a different thing, raised as usual
            await db.copy_events([event(NOW, "firewall", severity=6, action="nat", src_ip=PC, dst_ip="203.0.113.5",
                                        dst_port=6697, direction="out")])
            await eng.suspicious_outbound_ports()
            other = (await alerts(pool))[-1]
            assert other["status"] == "open" and "repeat_of" not in other["data"]
            await pool.execute("DELETE FROM alerts WHERE id = $1", other["id"])
            # worse than when you closed it (a serious alert about the same server): raised as usual
            await raise_alert("threat_feed", "critical", f"{PC} → known malicious address {IRC}", f"feed:{PC}:{IRC}",
                              src_ip=PC, dst_ip=IRC)
            await db.copy_events([irc()])
            await eng.suspicious_outbound_ports()
            worse = (await alerts(pool))[-1]
            assert worse["status"] == "open" and worse["severity"] == "high"
            await pool.execute("DELETE FROM alerts WHERE id = $1 OR rule = 'threat_feed'", worse["id"])
            # 'info' keeps it open at info; 'off' raises it as usual
            s.fp_repeat = "info"
            await db.copy_events([irc()])
            await eng.suspicious_outbound_ports()
            low = (await alerts(pool))[-1]
            assert low["status"] == "open" and low["severity"] == "info"
            await pool.execute("DELETE FROM alerts WHERE id = $1", low["id"])
            s.fp_repeat = "off"
            await db.copy_events([irc()])
            await eng.suspicious_outbound_ports()
            plain = (await alerts(pool))[-1]
            assert plain["status"] == "open" and plain["severity"] == "medium"
        finally:
            s.fp_repeat = old
    run(body)
