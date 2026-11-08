import asyncio
import os

import pytest

from lookingglass import alert_filters, db
from lookingglass.config import Settings

DSN = os.environ.get("TEST_DATABASE_URL")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_alert_list_survives_odd_stored_alerts():
    """One alert with unexpected stored data or an unknown severity must not fail the whole list (HTTP 500)."""
    from lookingglass.web.app import create_app

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, alert_filters")
            await pool.execute("INSERT INTO alert_filters (name, enabled, max_severity, action) VALUES ('m', true, 'low', 'close')")
            alert_filters.invalidate()
            odd = [[1, 2], "text", {"device": "abc"}, {"severity_override": "x"},
                   {"severity_override": {"from": "low", "filter": "x"}}, None]
            for i, data in enumerate(odd):
                await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint, status, data) VALUES "
                                   "('r', 'low', 't', $1, 'closed', $2)", f"f{i}", data)
            await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint, status) VALUES ('r', 'warning', 't', 'w', 'closed')")
            ep = next(r.endpoint for r in create_app(Settings(), None).routes if getattr(r, "path", "") == "/api/alerts")
            for status in ("closed", "all"):
                out = await ep(status=status, hours=720, limit=500)
                assert len(out) == len(odd) + 1
            assert sum(1 for a in out if a["muted_by"]) == len(odd) + 1  # 'warning' is compared as info
            await pool.execute("TRUNCATE alerts, alert_filters")
            alert_filters.invalidate()
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_alert_list_sort_orders():
    """?sort= orders the list by priority (default), alert number (both ways) or latest activity; unknown = priority."""
    from lookingglass.web.app import create_app

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, alert_filters")
            alert_filters.invalidate()
            # id order: low (seen last), critical, medium (seen first)
            for fp, sev, ago in (("a", "low", 1), ("b", "critical", 5), ("c", "medium", 10)):
                await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint, status, last_seen) VALUES "
                                   "('r', $1, 't', $2, 'open', now() - make_interval(mins => $3))", sev, fp, ago)
            ep = next(r.endpoint for r in create_app(Settings(), None).routes if getattr(r, "path", "") == "/api/alerts")
            sevs = lambda out: [a["severity"] for a in out]  # noqa: E731
            assert sevs(await ep(status="open", hours=720, limit=500)) == ["critical", "medium", "low"]
            assert sevs(await ep(status="open", hours=720, limit=500, sort="bogus")) == ["critical", "medium", "low"]
            assert sevs(await ep(status="open", hours=720, limit=500, sort="number")) == ["medium", "critical", "low"]
            assert sevs(await ep(status="open", hours=720, limit=500, sort="number_asc")) == ["low", "critical", "medium"]
            assert sevs(await ep(status="open", hours=720, limit=500, sort="recent")) == ["low", "critical", "medium"]
            await pool.execute("TRUNCATE alerts, alert_filters")
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_device_limits_api():
    """Per-device alert limits: saved validated on the device, listed with it, {} = the global settings again."""
    from fastapi import HTTPException

    from lookingglass.web.app import create_app

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE devices")
            await pool.execute("INSERT INTO devices (mac, ip) VALUES ('aa:bb:cc:dd:ee:01', '192.168.1.30')")
            routes = {(getattr(r, "path", ""), next(iter(getattr(r, "methods", None) or {""}))): r.endpoint
                      for r in create_app(Settings(), None).routes if hasattr(r, "endpoint")}
            update, listing = routes[("/api/devices/{mac}", "POST")], routes[("/api/devices", "GET")]
            await update(mac="AA:BB:CC:DD:EE:01", payload={"limits": {"volume_factor": "30", "ml_sensitivity": "",
                                                                      "risk_threshold": 120}})
            dev = (await listing(hours=24))[0]
            assert dev["limits"] == {"volume_factor": 30, "risk_threshold": 120} and dev["risk_threshold"] == 120
            with pytest.raises(HTTPException):
                await update(mac="aa:bb:cc:dd:ee:01", payload={"limits": {"volume_factor": -1}})
            await update(mac="aa:bb:cc:dd:ee:01", payload={"limits": {}})
            dev = (await listing(hours=24))[0]
            assert dev["limits"] == {} and dev["risk_threshold"] == Settings().risk_threshold
            # a device type (also for a client without a MAC); empty = not set; its defaults are listed
            await pool.execute("INSERT INTO devices (mac, ip) VALUES ('ip:10.8.0.2', '10.8.0.2')")
            await update(mac="ip:10.8.0.2", payload={"device_type": "phone"})
            assert await pool.fetchval("SELECT device_type FROM devices WHERE mac = 'ip:10.8.0.2'") == "phone"
            with pytest.raises(HTTPException):
                await update(mac="ip:10.8.0.2", payload={"device_type": "toaster"})
            # merged into the device that now holds its IP: the type moves along
            from lookingglass.detections import merge_ip_duplicates
            await pool.execute("INSERT INTO devices (mac, ip, sources) VALUES ('aa:bb:cc:dd:ee:02', '10.8.0.2', '{arp}')")
            assert await merge_ip_duplicates() == 1
            assert await pool.fetchval("SELECT device_type FROM devices WHERE mac = 'aa:bb:cc:dd:ee:02'") == "phone"
            await update(mac="aa:bb:cc:dd:ee:02", payload={"device_type": ""})
            assert await pool.fetchval("SELECT device_type FROM devices WHERE mac = 'aa:bb:cc:dd:ee:02'") is None
            defaults = await routes[("/api/devices/limits", "GET")]()
            assert defaults["types"]["phone"]["limits"]["new_country"] == "silent" and defaults["new_country"] == "alert"
            assert defaults["volume_factor"] == Settings().behavior_volume_factor
            await pool.execute("TRUNCATE devices")
        finally:
            await db.close()

    asyncio.run(main())
