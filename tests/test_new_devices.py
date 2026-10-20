import asyncio
import os

import pytest

from lookingglass import db
from lookingglass.config import Settings
from lookingglass.detections import DetectionEngine, is_private_mac, track_devices

DSN = os.environ.get("TEST_DATABASE_URL")


def test_private_mac():
    assert is_private_mac("da:a1:19:00:00:01") and is_private_mac("02:00:00:00:00:01") and is_private_mac("A6-11-22-33-44-55")
    assert not is_private_mac("00:11:22:33:44:55") and not is_private_mac("f0:9f:c2:00:00:01") and not is_private_mac(None)


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_changed_private_mac_is_recognised():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE devices, alerts")
            await track_devices([{"mac": "00:11:22:33:44:01", "ip": "192.168.1.5", "hostname": "nas"}], origin="arp")  # first run
            await track_devices([{"mac": "da:a1:19:00:00:01", "ip": "192.168.1.40", "hostname": "Pixel-7"}], origin="dhcp")
            eng = DetectionEngine(Settings())
            await eng.new_devices()
            assert await pool.fetchval("SELECT count(*) FROM alerts WHERE rule = 'new_device'") == 1  # a new phone: alert
            await pool.execute("UPDATE devices SET trusted = true, notes = 'Jan''s phone' WHERE mac = 'da:a1:19:00:00:01'")
            await pool.execute("UPDATE alerts SET status = 'closed'")
            # the phone rotates its private MAC: same name -> same device, no alert, trusted mark + notes copied
            await track_devices([{"mac": "5e:11:22:33:44:55", "ip": "192.168.1.41", "hostname": "pixel-7"}], origin="dhcp")
            await eng.new_devices()
            assert await pool.fetchval("SELECT count(*) FROM alerts WHERE rule = 'new_device'") == 1
            row = await pool.fetchrow("SELECT same_as, trusted, notes, new_pending FROM devices WHERE mac = '5e:11:22:33:44:55'")
            assert row["same_as"] == "da:a1:19:00:00:01" and row["trusted"] and row["notes"] == "Jan's phone" and not row["new_pending"]
            # a private MAC without a name waits (up to 10 minutes) for DHCP to name it
            await track_devices([{"mac": "6a:00:00:00:00:09", "ip": "192.168.1.42"}], origin="arp")
            await eng.new_devices()
            assert await pool.fetchval("SELECT new_pending FROM devices WHERE mac = '6a:00:00:00:00:09'")
            await track_devices([{"mac": "6a:00:00:00:00:09", "ip": "192.168.1.42", "hostname": "Pixel-7"}], origin="dhcp")
            await eng.new_devices()
            assert await pool.fetchval("SELECT same_as FROM devices WHERE mac = '6a:00:00:00:00:09'") == "da:a1:19:00:00:01"
            assert await pool.fetchval("SELECT count(*) FROM alerts WHERE rule = 'new_device'") == 1
            # real hardware address: always alerted (unless off); no-random skips private ones
            await track_devices([{"mac": "00:11:22:33:44:99", "ip": "192.168.1.43", "hostname": "pixel-7"},
                                 {"mac": "ae:00:00:00:00:01", "ip": "192.168.1.44", "hostname": "guest"}], origin="dhcp")
            await DetectionEngine(Settings(new_device_alerts="no-random")).new_devices()
            titles = [r["title"] for r in await pool.fetch("SELECT title FROM alerts WHERE rule = 'new_device' AND status = 'open'")]
            assert titles == ["New device on network: 00:11:22:33:44:99 (pixel-7)"]
            await pool.execute("TRUNCATE devices, alerts")
        finally:
            await db.close()

    asyncio.run(main())
