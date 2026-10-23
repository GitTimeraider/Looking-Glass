"""Integration test: every dashboard panel / report query must run on a real PostgreSQL.

Runs only when TEST_DATABASE_URL is set (CI provides a postgres service).
"""
import asyncio
import os

import pytest

from lookingglass import db
from lookingglass.dashboards import DASHBOARDS, run_dashboard
from lookingglass.reports import build_report, timeline

DSN = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")


def test_all_queries():
    async def main():
        await db.connect(DSN)
        try:
            for name in DASHBOARDS:
                for hours in (1, 168):
                    res = await run_dashboard(name, hours)
                    errors = [(p["id"], p["error"]) for p in res["panels"] if p.get("error")]
                    assert not errors, f"{name}: {errors}"
            rep = await build_report(24)
            assert "totals_by_source" in rep
            await timeline(24)
        finally:
            await db.close()
    asyncio.run(main())


def test_add_metrics_skips_bad_rows_instead_of_failing():
    async def main():
        await db.connect(DSN)
        try:
            await db.pool().execute("DELETE FROM metrics WHERE name LIKE 'test_%'")
            await db.add_metrics([("test_m", None, 1.0), ("test_m", "ok", float("nan")), ("test_m", "x", None), ("test_m", "y", 2)])
            rows = await db.pool().fetch("SELECT labels, value FROM metrics WHERE name = 'test_m' ORDER BY value")
            assert [(r["labels"], r["value"]) for r in rows] == [("", 1.0), ("y", 2.0)]
        finally:
            await db.close()
    asyncio.run(main())


def test_threats_dashboard_crowdsec_and_switched_off_sources():
    from datetime import datetime, timezone
    from lookingglass.parsers.common import event

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events")
            now = datetime.now(timezone.utc)
            await db.copy_events([
                event(now, "firewall", severity=6, action="block", src_ip="45.9.9.9", data={"label": "x", "blocklist": "CrowdSec"}),
                event(now, "qfeeds", severity=4, action="block", src_ip="45.9.9.8")])
            await db.set_snapshot("crowdsec_decisions", [{"id": 1}, {"id": 2}])  # active now, whatever their age
            res = await run_dashboard("threats", 24)
            by = {p["id"]: p for p in res["panels"]}
            kpi = by["kpi"]["rows"][0]
            assert kpi["Suricata events"] == 0 and kpi["CrowdSec active decisions"] == 2 and kpi["CrowdSec firewall blocks"] == 1
            assert {r["series"] for r in by["src"]["rows"]} == {"crowdsec", "qfeeds"}  # blocks count as CrowdSec
            assert by["src"]["drill"]["series_drill"]["crowdsec"] == {"source": "firewall", "d_blocklist": "CrowdSec"}
            assert "Suricata signatures" in {p.get("title") for p in res["panels"]}
            # Suricata switched off and without data: its tiles and panels are left out, the rest stays
            res = await run_dashboard("threats", 24, off={"suricata"})
            by = {p["id"]: p for p in res["panels"]}
            assert "cls" not in by and "sigs" not in by and "cs" in by
            assert "Suricata events" not in by["kpi"]["rows"][0] and "CrowdSec alerts" in by["kpi"]["rows"][0]
        finally:
            await db.pool().execute("TRUNCATE events")
            await db.pool().execute("DELETE FROM snapshots WHERE key = 'crowdsec_decisions'")
            await db.close()
    asyncio.run(main())


def test_crowdsec_alert_pulled_late_counts_in_the_period():
    from datetime import datetime, timedelta, timezone
    from lookingglass.parsers.common import event

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events")
            # CrowdSec detected it 12 days ago, Looking Glass received it 2 days ago
            old = datetime.now(timezone.utc) - timedelta(days=12)
            await db.copy_events([event(old, "crowdsec", severity=4, action="alert", src_ip="217.138.199.210",
                                        data={"scenario": "firewallservices/pf-scan-multi_ports"})])
            await pool.execute("UPDATE events SET received_at = now() - interval '2 days'")
            by = {p["id"]: p for p in (await run_dashboard("threats", 24 * 7))["panels"]}
            assert by["kpi"]["rows"][0]["CrowdSec alerts"] == 1
            assert by["cs"]["rows"][0]["scenario"] == "firewallservices/pf-scan-multi_ports"
            by = {p["id"]: p for p in (await run_dashboard("threats", 24))["panels"]}  # neither happened nor arrived today
            assert by["kpi"]["rows"][0]["CrowdSec alerts"] == 0 and not by["cs"]["rows"]
        finally:
            await db.pool().execute("TRUNCATE events")
            await db.close()
    asyncio.run(main())
