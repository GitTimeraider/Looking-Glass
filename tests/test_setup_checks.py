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
            await db.set_snapshot("poller_status", {"system": {"ok": True}, "nginx_logs": {"ok": True}, "ids": {"ok": True},
                                                    "crowdsec": {"ok": False, "forbidden": True, "error": "HTTP 403"}})
            res = await setup_checks.run(Settings(opnsense_url="http://x", opnsense_api_key="k", opnsense_api_secret="s"))
            by = {c["id"]: c for c in res["checks"]}
            assert by["dns"]["status"] == "duplicate" and set(by["dns"]["via"]) == {"API", "syslog"}
            assert by["nginx"]["status"] == "ok" and by["nginx"]["via"] == ["API"] and by["nginx"]["avoid"]
            assert by["ids"]["status"] == "ok" and by["ids"]["via"] == ["API"]
            assert by["crowdsec"]["status"] == "action" and "Privileges" in by["crowdsec"]["todo"][0]
            assert by["api"]["status"] == "info" and "crowdsec" in by["api"]["summary"]
        finally:
            await db.pool().execute("DELETE FROM events WHERE host = 'setup-test'")
            await db.pool().execute("DELETE FROM snapshots WHERE key = 'poller_status'")
            await db.close()
    asyncio.run(main())
