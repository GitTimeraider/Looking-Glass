import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest

from lookingglass import db
from lookingglass.config import Settings
from lookingglass.detections import DetectionEngine, Rating, bump
from lookingglass.parsers.common import event

DSN = os.environ.get("TEST_DATABASE_URL")


def test_rating_steps_and_text():
    assert bump("low", 2) == "high" and bump("critical", 1) == "critical" and bump("info", -1) == "info"
    r = Rating("low", "blocked scan").up("allowed in").down("dropped")
    assert r.severity == "low" and r.text() == "Severity low: blocked scan; ↑ allowed in; ↓ dropped."


def scan(ip: str, ports: int, now: datetime) -> list[dict]:
    return [event(now - timedelta(seconds=i), "firewall", host="t", severity=6, action="block", direction="in",
                  src_ip=ip, dst_ip="198.51.100.1", dst_port=1000 + i, proto="tcp") for i in range(ports)]


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_scan_severity_depends_on_outcome_and_origin_not_size():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, alerts")
            now = datetime.now(timezone.utc)
            evs = scan("203.0.113.50", 20, now) + scan("203.0.113.51", 400, now) + scan("203.0.113.52", 20, now) \
                + scan("192.168.1.66", 20, now) + scan("192.168.1.67", 20, now)
            # .52 reached an open port (normal for a hosted service), .53 also logged in, .67 contacted a threat-intel IP
            evs += scan("203.0.113.53", 20, now)
            evs.append(event(now, "firewall", host="t", severity=6, action="pass", direction="in", src_ip="203.0.113.52",
                             dst_ip="192.168.1.10", dst_port=443))
            evs.append(event(now, "auth", host="t", severity=5, action="login_success", src_ip="203.0.113.53", username="root"))
            evs.append(event(now, "qfeeds", host="t", severity=4, action="block", src_ip="192.168.1.67", dst_ip="91.92.1.1",
                             uid="qf:t1"))
            await db.insert_events_dedup([e for e in evs if e.get("uid")])
            await db.copy_events([e for e in evs if not e.get("uid")])
            await DetectionEngine(Settings()).port_scan()
            sev = {r["src_ip"]: r["severity"] for r in
                   await pool.fetch("SELECT host(src_ip) src_ip, severity FROM alerts WHERE rule = 'port_scan'")}
            assert sev["203.0.113.50"] == "low" and sev["203.0.113.51"] == "low"  # 400 ports is still just noise
            assert sev["203.0.113.52"] == "low" and sev["203.0.113.53"] == "high"
            assert sev["192.168.1.66"] == "medium" and sev["192.168.1.67"] == "high"
            why = await pool.fetchval("SELECT description FROM alerts WHERE host(src_ip) = '203.0.113.52'")
            assert "reached an open port" in why and "Severity low" in why
            await pool.execute("TRUNCATE events, alerts")
        finally:
            await db.close()

    asyncio.run(main())


def test_dga_heuristic_and_ignore_list():
    from lookingglass.detections import dga_like, ignore_list, ignored_domain

    assert dga_like("kq3v9x7w2m8p4z1r.com")
    assert not dga_like("echo-prod-a8f3k2m9x1q7.cloud")  # named service + short id
    assert not dga_like("a.kq3v9x7w2m8p4z1r.example.com")  # deeper names: tunneling check
    ign = ignore_list("*.Atoma.cloud; example.net")
    assert ign == ["atoma.cloud", "example.net"]
    assert ignored_domain("echo-prod-1.atoma.cloud", ign) and ignored_domain("atoma.cloud.", ign)
    assert not ignored_domain("notatoma.cloud", ign)


def test_future_time_stamps_are_counted_per_source():
    from lookingglass.ingest import STATS, EventWriter

    w = EventWriter(enricher=None)
    STATS.future_by_source.clear()
    ev = event(datetime.now(timezone.utc) + timedelta(hours=1), "firewall", host="opn")
    w.put(ev)
    f = STATS.future_by_source["firewall"]
    assert f["n"] == 1 and 3500 < f["max_ahead"] <= 3600 and f["host"] == "opn"
    assert ev["ts"] <= datetime.now(timezone.utc)
