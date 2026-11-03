import os

import pytest

from lookingglass import unifi

SW = {"mac": "F4:E2:C6:00:00:10", "name": "Office switch", "model": "USL16LP", "type": "usw", "state": 1,
      "system-stats": {"cpu": "12.0", "mem": "38.0"}, "uplink": {"tx_bytes-r": 1000, "rx_bytes-r": 500},
      "port_table": [{"port_idx": 3, "name": "NAS", "up": True, "speed": 1000, "rx_errors": 2, "tx_errors": 1, "poe_power": "4.5"}]}
AP = {"mac": "f4:e2:c6:00:00:01", "name": "Living room", "model": "U7PRO", "type": "uap", "state": 0, "num_sta": 3,
      "vap_table": [{"essid": "Home"}, {"essid": "IoT"}, {"essid": "Home"}],
      "radio_table_stats": [{"radio": "na", "channel": 44, "num_sta": 2}]}


def test_classic_devices():
    sw, ap = unifi.device_from_legacy(SW), unifi.device_from_legacy(AP)
    assert sw["mac"] == "f4:e2:c6:00:00:10" and sw["kind"] == "switch" and sw["state"] == "online"
    assert sw["cpu"] == 12.0 and sw["tx_bps"] == 8000 and sw["ports"][0]["errors"] == 3 and sw["ports"][0]["poe_w"] == 4.5
    assert ap["kind"] == "access point" and ap["state"] == "offline" and ap["ssids"] == ["Home", "IoT"]
    assert ap["radios"][0]["radio"] == "5 GHz"


def test_v1_device_and_client():
    d = unifi.device_from_v1({"id": "x", "macAddress": "AA:BB:CC:00:00:01", "name": "Attic", "model": "U6LR",
                              "state": "CONNECTION_INTERRUPTED", "features": ["accessPoint"], "firmwareUpdatable": True},
                             {"uptimeSec": 10, "cpuUtilizationPct": 3.5, "uplink": {"txRateBps": 800}})
    assert d["kind"] == "access point" and d["state"] == "connection interrupted" and d["tx_bps"] == 800 and d["upgradable"]
    c = unifi.client_from_v1({"type": "WIRELESS", "macAddress": "AA:AA:AA:AA:AA:01", "ipAddress": "192.168.1.5",
                              "name": "phone", "uplinkDeviceId": "x", "access": {"type": "GUEST"}}, {"x": d})
    # v1 "name" may just be the host name: it must not outrank names from DHCP reservations
    assert c["alias"] is None and c["hostname"] == "phone" and c["guest"] and c["ap"] == "Attic"


def test_classic_clients_and_where():
    devs = {"f4:e2:c6:00:00:01": unifi.device_from_legacy(AP), "f4:e2:c6:00:00:10": unifi.device_from_legacy(SW)}
    w = unifi.client_from_legacy({"mac": "AA:AA:AA:AA:AA:33", "ip": "192.168.1.33", "name": "Laptop", "hostname": "*",
                                  "is_wired": False, "essid": "Home", "ap_mac": "F4:E2:C6:00:00:01", "radio": "na",
                                  "signal": -54}, devs)
    assert w["alias"] == "Laptop" and w["hostname"] is None and w["signal"] == -54
    assert unifi.where(w) == "AP Living room · Home (5 GHz)"
    l = unifi.client_from_legacy({"mac": "aa:aa:aa:aa:aa:01", "is_wired": True, "sw_mac": "f4:e2:c6:00:00:10", "sw_port": 3,
                                  "wired-tx_bytes": 5, "tx_bytes": 1}, devs)
    assert unifi.where(l) == "Switch Office switch port 3" and l["tx_bytes"] == 5 and l["ssid"] is None


def test_events():
    e = unifi.event_from_legacy({"_id": "e1", "key": "EVT_WU_Roam", "user": "AA:AA:AA:AA:AA:33", "time": 1792400000000,
                                 "msg": "User[aa:aa:aa:aa:aa:33] roams from AP[f4:e2:c6:00:00:02] to AP[f4:e2:c6:00:00:01]"}, "default")
    assert e["action"] == "client_roam" and e["data"]["mac"] == "aa:aa:aa:aa:aa:33" and e["uid"].startswith("unifi:default:e1")
    assert e["ts"].year == 2026
    names = {"aa:aa:aa:aa:aa:33": "laptop", "f4:e2:c6:00:00:01": "Living room"}
    assert unifi.readable(e["message"], names) == \
        "User laptop (aa:aa:aa:aa:aa:33) roams from AP[f4:e2:c6:00:00:02] to AP Living room"
    assert unifi.event_from_legacy({"key": "EVT_SW_DetectRogueDHCP", "time": 1}, "s")["action"] == "rogue_dhcp"
    s = unifi.event_from_system_log({"id": "s1", "key": "DEVICE_OFFLINE", "severity": "HIGH", "title_raw": "Device Offline",
                                     "message_raw": "{device} is offline", "timestamp": 1792400000000,
                                     "parameters": {"device": {"name": "Attic"}}}, "default")
    assert s["action"] == "device_offline" and s["message"] == "Attic is offline" and s["severity"] == 3
    c = unifi.event_from_system_log({"id": "s2", "title_raw": "WiFi Client Connected", "timestamp": 1792400000000,
                                     "parameters": {"client": {"id": "AA:AA:AA:AA:AA:63", "type": "CLIENT", "ip": "192.168.1.63"}}}, "d")
    assert c["action"] == "client_connect" and c["src_ip"] == "192.168.1.63" and c["data"]["mac"] == "aa:aa:aa:aa:aa:63"


def test_v1_device_without_name_or_model_still_has_a_label():
    # a nameless device used to give a NULL metrics label: the insert failed and every UniFi chart stayed empty
    d = unifi.device_from_v1({"id": "x", "macAddress": "AA:BB:CC:00:00:09", "features": ["switching"]}, {"cpuUtilizationPct": 5})
    assert d["name"] == "aa:bb:cc:00:00:09"


DSN = os.environ.get("TEST_DATABASE_URL")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_offline_alerts_wait_for_the_grace_time_and_close_by_themselves():
    """A reboot of OPNsense / the controller / the AP itself stays quiet; a device that stays down is alerted once and
    the alert closes when it is back. The controller itself the same way."""
    import asyncio

    from lookingglass import alert_filters, db
    from lookingglass.config import Settings
    from lookingglass.unifi import UnifiPoller

    def ap(state):
        return [{"mac": "aa:bb:cc:00:00:01", "name": "AP Living", "kind": "access point", "model": "U6-Lite",
                 "state": state, "ip": "192.168.1.5"}]

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, alert_filters")
            alert_filters.invalidate()
            p = UnifiPoller(Settings(unifi_offline_grace=10), None)
            t = 1_000_000.0
            alerts = lambda: pool.fetch("SELECT rule, status, close_reason, description FROM alerts ORDER BY id")  # noqa: E731
            # OPNsense reboot: the AP is gone for 5 minutes - no alert
            await p.check_devices(ap("online"), now=t)
            await p.check_devices(ap("offline"), now=t + 60)
            await p.check_devices(ap("heartbeat missed"), now=t + 300)  # another down state: still the same outage
            await p.check_devices(ap("online"), now=t + 360)
            assert await alerts() == []
            # down for 10 minutes: one alert, saying how long
            await p.check_devices(ap("offline"), now=t + 1000)
            await p.check_devices(ap("offline"), now=t + 1599)
            assert await alerts() == []
            await p.check_devices(ap("offline"), now=t + 1600)
            await p.check_devices(ap("offline"), now=t + 1700)
            rows = await alerts()
            assert len(rows) == 1 and rows[0]["status"] == "open" and "for 10 minutes" in rows[0]["description"]
            assert await pool.fetchval("SELECT count FROM alerts") == 1  # not counted again every poll
            # back online: closed by itself
            await p.check_devices(ap("online"), now=t + 1800)
            row = (await alerts())[0]
            assert row["status"] == "closed" and row["close_reason"] == "resolved" and "online again" in row["description"]
            # down again for longer than the grace time: the alert opens again
            await p.check_devices(ap("offline"), now=t + 2000)
            await p.check_devices(ap("offline"), now=t + 2700)
            assert [r["status"] for r in await alerts()] == ["open"]
            # 0 = right away
            await pool.execute("TRUNCATE alerts")
            p = UnifiPoller(Settings(unifi_offline_grace=0), None)
            await p.check_devices(ap("offline"), now=t)
            assert [r["status"] for r in await alerts()] == ["open"]

            # the controller: unreachable while OPNsense reboots - quiet; longer - alerted, closed when it answers
            await pool.execute("TRUNCATE alerts")
            p = UnifiPoller(Settings(unifi_offline_grace=10), None)
            for i, dt in enumerate((0, 60, 120, 420)):
                p.failures = i + 1
                await p.controller_down("ConnectError", now=t + dt)
            await p.controller_back(now=t + 480)
            assert await alerts() == []
            for i, dt in enumerate((1000, 1060, 1120, 1420, 1720)):
                p.failures = i + 1
                await p.controller_down("ConnectError", now=t + dt)
            rows = await alerts()
            assert [(r["rule"], r["status"]) for r in rows] == [("unifi_unreachable", "open")]
            assert "No answer for 12 minutes" in rows[0]["description"]
            await p.controller_back(now=t + 1800)
            row = (await alerts())[0]
            assert row["status"] == "closed" and "unreachable for 13 minutes" in row["description"]
            await pool.execute("TRUNCATE alerts")
        finally:
            await db.close()

    asyncio.run(main())
