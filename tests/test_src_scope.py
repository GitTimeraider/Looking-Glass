"""Local / non-local source addresses: Event search (src_scope) and the From filter of the dashboards' live logs."""
import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest

from lookingglass import db, event_filter
from lookingglass.dashboards import DASHBOARDS, run_log
from lookingglass.parsers.common import event

DSN = os.environ.get("TEST_DATABASE_URL")


def test_src_scope_rejects_other_values():
    with pytest.raises(ValueError, match="local or public"):
        event_filter.build({"src_scope": "lan"})
    where, args = event_filter.build({"src_scope": "public"})
    assert any("NOT src_ip <<= ANY" in w for w in where) and event_filter.LOCAL_NETS in args


def test_every_live_log_can_be_filtered():
    for name, spec in DASHBOARDS.items():
        for p in spec["panels"]:
            if p["type"] == "log":
                assert p.get("where") and p.get("limit"), (name, p["id"])


ADDRS = {"local": ["192.168.1.20", "10.0.3.2", "172.20.0.5", "100.100.1.1", "127.0.0.1", "169.254.1.1", "fd00::5",
                   "fe80::1", "::1"],
         "public": ["45.9.9.9", "8.8.8.8", "172.32.0.1", "2001:db8::1", "100.128.0.1"]}


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_src_scope_search_and_live_log():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events")
            now = datetime.now(timezone.utc)
            rows = [event(now - timedelta(minutes=5), "nginx", severity=6, action="http_200", src_ip=ip, message=f"GET / {ip}")
                    for ips in ADDRS.values() for ip in ips]
            rows.append(event(now - timedelta(minutes=5), "nginx", severity=6, message="no address"))
            await db.copy_events(rows)

            async def search(**params):
                where, args = event_filter.build({"hours": 1, **params})
                return {r["ip"] for r in await pool.fetch(
                    f"SELECT host(src_ip) ip FROM events WHERE {' AND '.join(where)}", *args)}

            assert await search(src_scope="local") == set(ADDRS["local"])
            assert await search(src_scope="public") == set(ADDRS["public"])  # the event without an address: neither
            assert len(await search()) == len(ADDRS["local"]) + len(ADDRS["public"]) + 1

            # the live log holds only local sources (newest 150) - with local turned off it shows the older
            # non-local ones instead of an empty table
            await pool.execute("TRUNCATE events")
            await db.copy_events(
                [event(now - timedelta(hours=3, seconds=i), "nginx", program="swag", severity=6, action="http_404",
                       src_ip="45.9.9.9", message="GET /.env") for i in range(5)]
                + [event(now - timedelta(seconds=i), "nginx", program="swag", severity=6, action="http_200",
                         src_ip="192.168.1.20", message="GET /") for i in range(200)])
            web_log = next(p for p in DASHBOARDS["swag"]["panels"] if p["type"] == "log" and p.get("tab") == "web")
            unfiltered = await pool.fetch(web_log["sql"], 24 * 3600)
            assert {r["src_ip"] for r in unfiltered} == {"192.168.1.20"}
            public = await run_log("swag", web_log["id"], 24, "public")
            assert len(public) == 5 and {r["src_ip"] for r in public} == {"45.9.9.9"}
            local = await run_log("swag", web_log["id"], 24, "local")
            assert len(local) == web_log["limit"] and {r["src_ip"] for r in local} == {"192.168.1.20"}
            assert await run_log("swag", web_log["id"], 1, "public") == []  # the period still applies
            with pytest.raises(KeyError):
                await run_log("swag", "sw_kpi", 24, "public")  # only live logs
        finally:
            await db.pool().execute("TRUNCATE events")
            await db.close()

    asyncio.run(main())
