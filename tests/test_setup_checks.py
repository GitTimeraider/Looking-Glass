import asyncio
import os

import pytest

from lookingglass import db, setup_checks
from lookingglass.config import Settings
from lookingglass.parsers.common import event

DSN = os.environ.get("TEST_DATABASE_URL")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_channels_and_duplicates():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events")  # test database: the check looks at all events of the last 24 hours
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            evs = [
                event(now, "unbound", host="setup-test", severity=6, program="unbound", action="query", domain="a.example", uid="dns:t1"),
                event(now, "unbound", host="setup-test", severity=6, program="unbound", action="query", domain="a.example"),  # syslog copy
                event(now, "nginx", host="setup-test", severity=6, program="nginx", action="http_200", uid="ngx:t1"),
                event(now, "suricata", host="setup-test", severity=6, program="suricata", action="alert", uid="ids:t1"),
            ]
            await db.insert_events_dedup([e for e in evs if e.get("uid")])
            await db.copy_events([e for e in evs if not e.get("uid")])
            # Zenarmor: a stream record stored before program "zenarmor-es" existed must not count as syslog ...
            await pool.execute("INSERT INTO events (ts, received_at, source, program, severity, host) VALUES "
                               "(now() - interval '2 hours', now() - interval '2 hours', 'zenarmor', 'zenarmor', 6, 'setup-test'), "
                               "(now() - interval '1 hour', now() - interval '1 hour', 'zenarmor', 'zenarmor-es', 6, 'setup-test')")
            await db.set_snapshot("poller_status", {"system": {"ok": True}, "nginx_logs": {"ok": True}, "ids": {"ok": True},
                                                    "crowdsec": {"ok": False, "forbidden": True, "error": "HTTP 403"}})
            res = await setup_checks.run(Settings(opnsense_url="http://x", opnsense_api_key="k", opnsense_api_secret="s"))
            by = {c["id"]: c for c in res["checks"]}
            assert by["dns"]["status"] == "duplicate" and set(by["dns"]["via"]) == {"API", "syslog"}
            assert by["nginx"]["status"] == "ok" and by["nginx"]["via"] == ["API"] and by["nginx"]["avoid"]
            assert by["ids"]["status"] == "ok" and by["ids"]["via"] == ["API"]
            assert by["crowdsec"]["status"] == "action" and "Privileges" in by["crowdsec"]["todo"][0]
            assert by["api"]["status"] == "info" and "crowdsec" in by["api"]["summary"]
            assert by["zenarmor"]["status"] == "ok" and by["zenarmor"]["via"] == ["ES stream"]
            # ... but a syslog record received after the stream started does
            await pool.execute("INSERT INTO events (ts, source, program, severity, host) VALUES (now(), 'zenarmor', 'zenarmor', 6, 'setup-test')")
            res = await setup_checks.run(Settings(opnsense_url="http://x", opnsense_api_key="k", opnsense_api_secret="s"))
            assert {c["id"]: c for c in res["checks"]}["zenarmor"]["status"] == "duplicate"
            # Unbound's own service messages via syslog are no query logging - no duplicate
            await pool.execute("DELETE FROM events WHERE host = 'setup-test' AND source = 'unbound' AND uid IS NULL")
            await db.copy_events([event(now, "unbound", host="setup-test", severity=6, program="unbound",
                                        message="[1234:0] info: start of service (unbound 1.22.0).")])
            res = await setup_checks.run(Settings(opnsense_url="http://x", opnsense_api_key="k", opnsense_api_secret="s"))
            assert {c["id"]: c for c in res["checks"]}["dns"]["status"] in ("ok", "info")
        finally:
            await db.pool().execute("DELETE FROM events WHERE host = 'setup-test'")
            await db.pool().execute("DELETE FROM snapshots WHERE key = 'poller_status'")
            await db.close()
    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_runs_with_every_integration_configured():
    """Setup & status must not crash whatever is configured (a name clash once broke it with UniFi + behaviour on)."""
    async def main():
        await db.connect(DSN)
        try:
            await db.pool().execute("INSERT INTO device_profile (key, kind, value, first_seen) VALUES ('aa:bb:cc:00:00:01', "
                                    "'country', 'NL', now() - interval '3 days') ON CONFLICT DO NOTHING")
            await db.set_snapshot("unifi:status", {"ok": True, "mode": "classic", "version": "10.0", "sections": {}})
            res = await setup_checks.run(Settings(
                opnsense_url="http://x", opnsense_api_key="k", opnsense_api_secret="s", unifi_url="http://u",
                unifi_api_key="k", ai_base_url="http://a/v1", ai_api_key="k", ai_model="m", smtp_host="m", smtp_from="a@b.c",
                canary_targets="192.168.1.1:23", behavior_enabled=True, exposure_watch=True))
            ids = {c["id"] for c in res["checks"]}
            assert {"behavior", "unifi", "canary"} <= ids
            assert "devices profiled" in next(c["summary"] for c in res["checks"] if c["id"] == "behavior")
            await db.pool().execute("DELETE FROM device_profile")
            await db.pool().execute("DELETE FROM snapshots WHERE key = 'unifi:status'")
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_crowdsec_check_names_the_missing_step():
    from datetime import datetime, timezone

    async def crowdsec(pool):
        res = await setup_checks.run(Settings(opnsense_url="http://x", opnsense_api_key="k", opnsense_api_secret="s"))
        return {c["id"]: c for c in res["checks"]}["crowdsec"]

    def snap(**kw):
        return {"crowdsec": {"name": "CrowdSec", "aliases": ["crowdsec_blocklists", "crowdsec6_blocklists"], "tables": {},
                             "size": 0, "rules": [], "rids": [], "packets": 0, "errors": {}, **kw}}

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events")
            await db.set_snapshot("poller_status", {"system": {"ok": True}, "crowdsec": {"ok": True}})
            await db.set_snapshot("rule_labels", {"a" * 32: "Allow LAN"})
            await db.set_snapshot("crowdsec_status", {"alerts": 0, "decisions": 0})
            await db.set_snapshot("blocklists", snap(tables={"crowdsec_blocklists": 0}))
            c = await crowdsec(pool)  # no rule uses the aliases, tables empty
            assert c["status"] == "action" and "Create blocklist rules" in c["todo"][0] and "empty" in c["todo"][1]
            assert "0 alerts" in c["summary"]
            rule = {"rid": "b" * 32, "rule": "block drop in log quick inet from <crowdsec_blocklists> to any", "packets": 7, "block": True}
            await db.set_snapshot("blocklists", snap(size=None, rules=[rule], packets=7, errors={"sizes": 403}))
            c = await crowdsec(pool)
            assert c["todo"] == [f"{setup_checks.PRIV}: add 'Firewall: Alias: Edit' to the API user, so the blocklist size can be read."]
            assert "1 rule(s) use crowdsec_blocklists, crowdsec6_blocklists, 7 packets blocked" in c["summary"]
            await db.set_snapshot("blocklists", snap(errors={"rules": 403}, size=18900, packets=None,
                                                     tables={"crowdsec_blocklists": 18000, "crowdsec6_blocklists": 900}))
            c = await crowdsec(pool)  # rule list not readable and no plugin rule by name
            assert "Diagnostics: Firewall statistics" in c["todo"][0]
            await db.set_snapshot("crowdsec_status", {"alerts": 2, "decisions": 1})
            await db.set_snapshot("blocklists", snap(size=18900, rules=[rule], packets=7,
                                                     tables={"crowdsec_blocklists": 18000, "crowdsec6_blocklists": 900}))
            now = datetime.now(timezone.utc)
            await db.copy_events([event(now, "firewall", host="setup-test", severity=6, action="block", src_ip="45.9.9.9",
                                        data={"label": ""})])
            c = await crowdsec(pool)  # rules + full tables, but no logged block
            assert "Enable log for rules" in c["todo"][0] and "no rule name" in c["todo"][1] and "18,900 addresses" in c["summary"]
            await db.copy_events([event(now, "firewall", host="setup-test", severity=6, action="block", src_ip="45.9.9.8",
                                        data={"label": "My own rule", "blocklist": "CrowdSec"})])
            c = await crowdsec(pool)
            assert c["status"] == "ok" and not c["todo"] and "1 blocks by these rules" in c["summary"]
        finally:
            await db.pool().execute("DELETE FROM events WHERE host = 'setup-test'")
            await db.pool().execute("DELETE FROM snapshots WHERE key IN ('poller_status', 'rule_labels', 'crowdsec_status', 'blocklists')")
            await db.close()
    asyncio.run(main())
