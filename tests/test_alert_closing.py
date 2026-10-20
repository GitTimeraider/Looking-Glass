import asyncio
import os

import pytest

from lookingglass import db
from lookingglass.config import Settings
from lookingglass.detections import DetectionEngine

DSN = os.environ.get("TEST_DATABASE_URL")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_closed_alerts_stay_closed_unless_worse():
    from lookingglass.detections import raise_alert

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, devices")
            await raise_alert("beaconing", "low", "Beacon", "fp:1", src_ip="192.168.1.9")
            await pool.execute("UPDATE alerts SET status = 'closed', close_reason = 'resolved'")
            for _ in range(3):  # the condition still holds on the next runs: no new alert, the closed one counts
                await raise_alert("beaconing", "low", "Beacon", "fp:1", src_ip="192.168.1.9")
            rows = await pool.fetch("SELECT status, count FROM alerts")
            assert [(r["status"], r["count"]) for r in rows] == [("closed", 4)]
            await raise_alert("beaconing", "high", "Beacon", "fp:1", src_ip="192.168.1.9")  # worse: back to open
            row = await pool.fetchrow("SELECT status, severity, close_reason, description FROM alerts")
            assert row["status"] == "open" and row["severity"] == "high" and row["close_reason"] is None
            assert "Re-opened" in row["description"]
            # closed by a mute filter that has since been removed -> open again on the next sighting
            await pool.execute("TRUNCATE alerts")
            await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint, status, data) VALUES "
                               "('beaconing', 'low', 'B', 'fp:2', 'closed', $1)", {"filter": {"id": 1}})
            await raise_alert("beaconing", "low", "B", "fp:2")
            assert await pool.fetchval("SELECT status FROM alerts") == "open"
            # attack chain: a new device + ONE kind of signal is not a chain (that rule's own alert says it)
            await pool.execute("TRUNCATE alerts")
            await pool.execute("INSERT INTO devices (mac, ip, first_seen) VALUES ('00:11:22:33:44:07', '192.168.1.7', now())")
            await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint, src_ip) VALUES "
                               "('dns_bypass', 'low', 'd', 'c1', '192.168.1.7')")
            eng = DetectionEngine(Settings())
            await eng.attack_chains()
            assert not await pool.fetchval("SELECT count(*) FROM alerts WHERE rule = 'attack_chain'")
            # two kinds of signals: a chain; an untrusted new device makes it critical, a trusted one doesn't
            await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint, src_ip) VALUES "
                               "('lateral_movement', 'medium', 'l', 'c2', '192.168.1.7')")
            await eng.attack_chains()
            assert await pool.fetchval("SELECT severity FROM alerts WHERE rule = 'attack_chain'") == "critical"
            await pool.execute("DELETE FROM alerts WHERE rule = 'attack_chain'")
            await pool.execute("UPDATE devices SET trusted = true")
            await eng.attack_chains()
            row = await pool.fetchrow("SELECT severity, title FROM alerts WHERE rule = 'attack_chain'")
            assert row["severity"] == "high" and "New device" not in row["title"]
            await pool.execute("TRUNCATE alerts, devices")
        finally:
            await db.close()

    asyncio.run(main())
