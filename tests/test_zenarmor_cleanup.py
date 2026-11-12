"""Zenarmor support was removed: what older versions stored for it is cleaned up (schema.sql + housekeeping)."""
import asyncio
import os

import pytest

from lookingglass import db
from lookingglass.config import Settings

DSN = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")


def test_stored_zenarmor_data_is_removed():
    from lookingglass.main import housekeeping

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, event_rollup, alerts, alert_filters, notification_rules, devices, "
                               "device_profile, device_hourly")
            await pool.execute("DELETE FROM app_settings WHERE key LIKE 'zenarmor%' OR key = 'ids_pull'")
            await pool.execute("INSERT INTO app_settings (key, value) VALUES ('zenarmor_es_user', '\"u\"'), "
                               "('zenarmor_enabled', 'true'), ('ids_pull', 'true')")
            await db.kv_set("wm:zenarmor", 5)
            await pool.execute("INSERT INTO events (ts, source, message) VALUES (now(), 'zenarmor', 'z'), (now(), 'zenarmor', 'z'), "
                               "(now(), 'firewall', 'f')")
            await pool.execute("INSERT INTO event_rollup VALUES (date_trunc('hour', now()), 'zenarmor', '', '', '', '', -1, '', 6, 2), "
                               "(date_trunc('hour', now()), 'firewall', '', '', '', '', -1, '', 6, 1)")
            await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint) VALUES "
                               "('zenarmor_threat', 'low', 'z', 'z1'), ('large_upload', 'low', 'u', 'u1'), ('port_scan', 'low', 'p', 'p1')")
            await pool.execute("INSERT INTO alert_filters (name, rules, contains) VALUES "
                               "('only zen', '{zenarmor_threat}', 'x'), ('mixed', '{zenarmor_threat,port_scan}', NULL), "
                               "('any rule', '{}', 'y')")
            await pool.execute("INSERT INTO notification_rules (name, recipients, rules) VALUES "
                               "('only upload', 'a@example.com', '{large_upload}'), ('mixed', 'a@example.com', '{large_upload,ids}')")
            await pool.execute(
                "INSERT INTO devices (mac, ip, hostname, name_source, name_rank, sources) VALUES "
                "('ip:10.8.0.2', '10.8.0.2', 'phone', 'zenarmor', 25, '{zenarmor}'), "        # Zenarmor's MAC-less client
                "('aa:00:00:00:00:01', '192.168.1.5', 'tv', 'zenarmor', 25, '{zenarmor}'), "  # only Zenarmor saw it
                "('aa:00:00:00:00:02', '192.168.1.6', 'pc', 'zenarmor', 25, '{arp,zenarmor}'), "
                "('aa:00:00:00:00:03', '192.168.1.7', 'nas', 'dhcp', 50, '{arp}'), "
                "('aa:00:00:00:00:04', '192.168.1.8', NULL, NULL, 0, '{}')")
            await pool.execute("INSERT INTO device_profile (key, kind, value) VALUES ('ip:10.8.0.2', 'port', '443'), "
                               "('aa:00:00:00:00:01', 'port', '443'), ('aa:00:00:00:00:03', 'port', '443')")

            await db._create_schema(pool)  # runs on every start
            assert {r["key"] for r in await pool.fetch("SELECT key FROM app_settings WHERE key LIKE 'zenarmor%' OR key = 'ids_pull'")} \
                == {"ids_pull"}
            assert await db.kv_get("wm:zenarmor") is None
            assert [r["rule"] for r in await pool.fetch("SELECT rule FROM alerts")] == ["port_scan"]
            # a filter made only for a removed rule goes (with no rules left it would match every alert)
            assert {r["name"]: r["rules"] for r in await pool.fetch("SELECT name, rules FROM alert_filters")} == \
                {"mixed": ["port_scan"], "any rule": []}
            assert {r["name"]: r["rules"] for r in await pool.fetch("SELECT name, rules FROM notification_rules")} == \
                {"mixed": ["ids"]}
            devs = {r["mac"]: dict(r) for r in await pool.fetch("SELECT mac, hostname, name_source, sources FROM devices")}
            assert set(devs) == {"aa:00:00:00:00:02", "aa:00:00:00:00:03", "aa:00:00:00:00:04"}
            assert devs["aa:00:00:00:00:02"] == {"mac": "aa:00:00:00:00:02", "hostname": None, "name_source": None,
                                                 "sources": ["arp"]}
            assert devs["aa:00:00:00:00:03"]["hostname"] == "nas"
            assert [r["key"] for r in await pool.fetch("SELECT key FROM device_profile")] == ["aa:00:00:00:00:03"]

            # housekeeping deletes the events and their hourly counts
            task = asyncio.create_task(housekeeping(Settings()))
            for _ in range(100):
                if not await pool.fetchval("SELECT count(*) FROM event_rollup WHERE source = 'zenarmor'"):
                    break
                await asyncio.sleep(0.05)
            task.cancel()
            assert [r["source"] for r in await pool.fetch("SELECT source FROM events")] == ["firewall"]
            assert [r["source"] for r in await pool.fetch("SELECT source FROM event_rollup")] == ["firewall"]
            await pool.execute("TRUNCATE events, event_rollup, alerts, alert_filters, notification_rules, devices, "
                               "device_profile, device_hourly")
        finally:
            await db.close()

    asyncio.run(main())
