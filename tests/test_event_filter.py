import asyncio
import os
from datetime import datetime, timezone

import pytest

from lookingglass import db, event_filter
from lookingglass.parsers.common import event

DSN = os.environ.get("TEST_DATABASE_URL")


def test_ports_and_ranges():
    assert event_filter.ports("22, 80 8000-8100", "x") == ([22, 80], [(8000, 8100)])
    assert event_filter.ports("443-443", "x") == ([443], [])
    # ranges copied from documentation: en / em dash, minus sign, spaces around the dash
    for text in ("19294–19344", "19294—19344", "19294−19344", "19294 - 19344", "19294 –19344"):
        assert event_filter.ports(text, "x") == ([], [(19294, 19344)])
    assert event_filter.ports("22; 80 – 90", "x") == ([22], [(80, 90)])
    for bad in ("http", "70000", "90-80", "1-2-3"):
        with pytest.raises(ValueError, match="Destination port"):
            event_filter.build({"dport": bad})


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_port_filters_and_alert_ports():
    from lookingglass.detections import raise_alert

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, alerts")
            now = datetime.now(timezone.utc)
            await db.copy_events([event(now, "firewall", severity=6, action="block", src_ip="45.9.9.9", src_port=sp,
                                        dst_ip="192.168.1.2", dst_port=dp)
                                  for sp, dp in ((40001, 22), (40002, 22), (40003, 22), (40004, 3389), (40005, 8080))])

            async def search(**params):
                where, args = event_filter.build({"hours": 1, **params})
                return sorted(r["dst_port"] for r in await pool.fetch(f"SELECT dst_port FROM events WHERE {' AND '.join(where)}", *args))
            assert await search(dport="22") == [22, 22, 22]
            assert await search(dport="22, 8000-8100") == [22, 22, 22, 8080]
            assert await search(port="3389") == [3389]  # dashboard links
            assert await search(sport="40004-40005") == [3389, 8080]
            # an alert shows the most frequent ports of its events
            await raise_alert("port_scan", "medium", "Scan", "t:1", src_ip="45.9.9.9", events={"source": "firewall", "ip": "45.9.9.9"})
            ports = (await pool.fetchval("SELECT data FROM alerts"))["ports"]
            assert ports["dst"] == [22, 3389, 8080] and ports["dst_n"] == 3
            assert len(ports["src"]) == 5 and ports["src_n"] == 5
            # no address to tie the events to: no ports (nothing to look up cheaply)
            await raise_alert("arp_spoofing", "medium", "ARP", "t:2", events={"source": "arp"})
            assert "ports" not in await pool.fetchval("SELECT data FROM alerts WHERE fingerprint = 't:2'")
        finally:
            await db.pool().execute("TRUNCATE events, alerts")
            await db.close()
    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_events_endpoint_port_filters():
    from fastapi import HTTPException
    from starlette.requests import Request

    from lookingglass.config import Settings
    from lookingglass.web.app import create_app

    def req(qs: str) -> Request:
        return Request({"type": "http", "method": "GET", "path": "/api/events", "headers": [], "query_string": qs.encode()})

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events")
            now = datetime.now(timezone.utc)
            await db.copy_events([event(now, "firewall", severity=6, action="block", src_ip="45.9.9.9", src_port=40000 + i,
                                        dst_ip="192.168.1.2", dst_port=dp) for i, dp in enumerate((22, 443, 8080))])
            ep = next(r.endpoint for r in create_app(Settings(), None).routes if getattr(r, "path", "") == "/api/events")
            call = lambda qs: ep(req(qs), hours=24, limit=100, offset=0)  # noqa: E731
            assert sorted(r["dst_port"] for r in (await call("dport=22,8000-9000"))["rows"]) == [22, 8080]
            assert [r["dst_port"] for r in (await call("sport=40001&source=firewall"))["rows"]] == [443]
            assert [r["dst_port"] for r in (await call("port=443"))["rows"]] == [443]
            with pytest.raises(HTTPException) as exc:
                await call("dport=ssh")
            assert exc.value.status_code == 400 and "not a port" in exc.value.detail
        finally:
            await db.pool().execute("TRUNCATE events")
            await db.close()
    asyncio.run(main())
