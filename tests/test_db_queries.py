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
            assert kpi["Suricata alerts"] == 0 and kpi["CrowdSec active decisions"] == 2 and kpi["CrowdSec firewall blocks"] == 1
            assert {r["series"] for r in by["src"]["rows"]} == {"crowdsec", "qfeeds"}  # blocks count as CrowdSec
            assert by["src"]["drill"]["series_drill"]["crowdsec"] == {"source": "firewall", "d_blocklist": "CrowdSec"}
            assert {r["label"]: r["v"] for r in by["blk"]["rows"]} == {"Suricata (dropped)": 0, "CrowdSec (firewall)": 1, "Q-Feeds": 1}
            # tabs: Main first, one per source; a tab only runs its own panels
            assert res["tab"] == "main" and [t["id"] for t in res["tabs"]] == ["main", "crowdsec", "qfeeds", "suricata"]
            assert all(p.get("tab") == "main" for p in res["panels"])
            cs = await run_dashboard("threats", 24, tab="crowdsec")
            by = {p["id"]: p for p in cs["panels"]}
            assert cs["source"] == "crowdsec" and by["cs_kpi"]["rows"][0]["Firewall blocks"] == 1 and by["csfw"]["rows"]
            # Active bans: from the decisions snapshot, the longest-running first; o_ip only for real addresses
            from lookingglass.parsers.security import crowdsec_ban_row
            await db.set_snapshot("crowdsec_decisions", [crowdsec_ban_row(r, now) for r in (
                {"id": 11, "scope_value": "Ip:203.0.113.5", "expiration": "1h0m0s", "action": "ban", "reason": "ssh-bf",
                 "source": "crowdsec", "country": "NL"},
                {"id": 12, "scope_value": "Country:XX", "expiration": "4h0m0s", "action": "ban"})])
            bans = {p["id"]: p for p in (await run_dashboard("threats", 24, tab="crowdsec"))["panels"]}["cs_bans"]
            assert not bans.get("error") and [r["id"] for r in bans["rows"]] == ["12", "11"]
            assert bans["rows"][1]["o_ip"] == "203.0.113.5" and bans["rows"][0]["o_ip"] is None and bans["rows"][1]["ends"]
            assert bans["order"] == {"k": "ends", "dir": -1}
            # CrowdSec switched off and without data: its tiles and tab are left out, the rest stays
            res = await run_dashboard("threats", 24, off={"crowdsec"}, tab="crowdsec")
            assert res["tab"] == "main" and "crowdsec" not in [t["id"] for t in res["tabs"]]
            kpi = {p["id"]: p for p in res["panels"]}["kpi"]["rows"][0]
            assert "CrowdSec alerts" not in kpi and "Q-Feeds hits" in kpi
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
            by = {p["id"]: p for p in (await run_dashboard("threats", 24))["panels"]}  # neither happened nor arrived today
            assert by["kpi"]["rows"][0]["CrowdSec alerts"] == 0
        finally:
            await db.pool().execute("TRUNCATE events")
            await db.close()
    asyncio.run(main())


def test_every_query_works_with_the_from_filter():
    """The All / Local / Non-local switch rewrites each events reference: every dashboard panel and report section must
    still be valid SQL (e.g. 'IS NOT DISTINCT FROM events.dst_ip' is a column, not the table)."""
    from lookingglass.event_filter import scoped_sql
    from lookingglass.reports import QUERIES

    async def main():
        await db.connect(DSN)
        try:
            queries = [(f"report {n}", q) for n, q in QUERIES.items()]
            queries += [(f"{d} {p['id']}", p["sql"]) for d, spec in DASHBOARDS.items() for p in spec["panels"]]
            broken = []
            async with db.pool().acquire() as conn:
                for name, q in queries:
                    for scope in ("local", "public"):
                        try:
                            await conn.prepare(scoped_sql(q, scope))
                        except Exception as exc:  # noqa: BLE001
                            broken.append((name, scope, str(exc)[:100]))
            assert not broken
        finally:
            await db.close()
    asyncio.run(main())


def test_opnsense_and_docker_crowdsec_stay_apart():
    """Threats (OPNsense) counts only the OPNsense CrowdSec plugin; SWAG & CrowdSec only CrowdSec in Docker
    (program crowdsec-lapi); alerts say which one; Event search can leave the Docker one out."""
    from datetime import datetime, timezone

    from lookingglass import event_filter
    from lookingglass.config import Settings
    from lookingglass.detections import DetectionEngine
    from lookingglass.parsers.common import event

    async def main():
        await db.connect(DSN)
        pool = db.pool()
        try:
            await pool.execute("TRUNCATE events, alerts")
            now = datetime.now(timezone.utc)
            await db.copy_events([
                event(now, "crowdsec", program="crowdsec", severity=4, action="alert", src_ip="45.9.9.9",
                      data={"scenario": "crowdsecurity/ssh-bf"}),
                event(now, "crowdsec", program="crowdsec-lapi", severity=4, action="alert", src_ip="45.8.8.8",
                      data={"scenario": "crowdsecurity/http-probing"})])
            await db.set_snapshot("crowdsec_decisions", [{"id": 1, "lg_value": "45.9.9.9"}])
            await db.set_snapshot("crowdsec_lapi_decisions", [{"id": 7, "value": "45.8.8.8"}, {"id": 8, "value": "45.7.7.7"}])
            thr = await run_dashboard("threats", 24, set(), "crowdsec")
            by = {p["id"]: p for p in thr["panels"]}
            assert (by["cs_kpi"]["rows"][0]["Alerts"], by["cs_kpi"]["rows"][0]["Active decisions"]) == (1, 1)
            assert {r["series"]: r["v"] for r in by["cs_time"]["rows"]} == {"alerts": 1}
            main = {p["id"]: p for p in (await run_dashboard("threats", 24))["panels"]}
            assert (main["kpi"]["rows"][0]["CrowdSec alerts"], main["kpi"]["rows"][0]["CrowdSec active decisions"]) == (1, 1)
            assert {r["ip"] for r in main["attackers"]["rows"]} == {"45.9.9.9"}
            swag = {p["id"]: p for p in (await run_dashboard("swag", 24, set(), "crowdsec"))["panels"]}
            assert swag["csl_kpi"]["rows"][0]["Active decisions"] == 2 and [r["value"] for r in swag["csl_active"]["rows"]]
            # Event search: the OPNsense one only
            where, args = event_filter.build({"source": "crowdsec", "not_program": "crowdsec-lapi", "hours": 24})
            ips = {r["ip"] for r in await pool.fetch(f"SELECT host(src_ip) ip FROM events WHERE {' AND '.join(where)}", *args)}
            assert ips == {"45.9.9.9"}
            # alerts: one each, saying which CrowdSec, each linking to its own events
            await db.kv_set("wm:crowdsec", 0)
            await DetectionEngine(Settings()).crowdsec_alerts()
            got = {r["title"]: r["fingerprint"] for r in await pool.fetch("SELECT title, fingerprint FROM alerts WHERE rule = 'crowdsec'")}
            assert got == {"CrowdSec (OPNsense): crowdsecurity/ssh-bf from 45.9.9.9": "crowdsec:45.9.9.9:crowdsecurity/ssh-bf",
                           "CrowdSec (SWAG): crowdsecurity/http-probing from 45.8.8.8": "crowdsec-lapi:45.8.8.8:crowdsecurity/http-probing"}
        finally:
            await pool.execute("TRUNCATE events, alerts")
            await pool.execute("DELETE FROM snapshots WHERE key IN ('crowdsec_decisions', 'crowdsec_lapi_decisions')")
            await db.close()
    asyncio.run(main())


def test_opnsense_pages_only_count_opnsense():
    """OPNsense security › Authentication leaves UniFi's (or any other product's) logins out; Threats' alert panels
    leave out the alerts of other products and of CrowdSec in Docker."""
    from datetime import datetime, timezone

    from lookingglass.detections import raise_alert
    from lookingglass.parsers.common import event

    async def main():
        await db.connect(DSN)
        pool = db.pool()
        try:
            await pool.execute("TRUNCATE events, alerts")
            now = datetime.now(timezone.utc)
            await db.copy_events([
                event(now, "auth", program="sshd", severity=4, action="login_failed", src_ip="45.1.1.1", username="root"),
                event(now, "unifi", program="unifi", severity=4, action="login_failed", src_ip="45.2.2.2", username="admin"),
                event(now, "unifi", program="unifi", severity=5, action="login_success", src_ip="192.168.1.9", username="me")])
            by = {p["id"]: p for p in (await run_dashboard("auth", 24))["panels"]}
            assert by["kpi"]["rows"][0]["Failed logins"] == 1 and by["kpi"]["rows"][0]["Successful logins"] == 0
            assert [r["ip"] for r in by["fails"]["rows"]] == ["45.1.1.1"] and by["ok"]["rows"] == []
            assert {r["label"] for r in by["users"]["rows"]} == {"root"}
            assert by["fails"]["drill"]["base"]["source"] == "auth,vpn,system"
            await raise_alert("ids", "high", "Suricata: x", "ids:x", src_ip="45.1.1.1")
            await raise_alert("honeypot", "high", "Honeypot touched by 127.0.0.1", "honeypot:127.0.0.1", src_ip="127.0.0.1")
            await raise_alert("crowdsec", "high", "CrowdSec (SWAG): a", "crowdsec-lapi:45.3.3.3:a", src_ip="45.3.3.3")
            await raise_alert("crowdsec", "high", "CrowdSec (OPNsense): b", "crowdsec:45.4.4.4:b", src_ip="45.4.4.4")
            thr = {p["id"]: p for p in (await run_dashboard("threats", 24))["panels"]}
            assert thr["kpi"]["rows"][0]["Open high/critical alerts"] == 2
            assert {r["label"]: r["v"] for r in thr["alerts"]["rows"]} == {"ids": 1, "crowdsec": 1}
            assert sum(r["v"] for r in thr["sev"]["rows"]) == 2
        finally:
            await pool.execute("TRUNCATE events, alerts")
            await db.close()
    asyncio.run(main())


def test_crowdsec_swag_alert_setting():
    """Settings › SWAG & CrowdSec › CrowdSec (SWAG) ban of an internet address: alert - off / info / low. Inside the
    network always high; the OPNsense plugin keeps its own (low)."""
    from datetime import datetime, timezone

    from lookingglass.config import Settings
    from lookingglass.detections import DetectionEngine
    from lookingglass.parsers.common import event

    async def run(level, rows):
        pool = db.pool()
        await pool.execute("TRUNCATE events")
        await db.copy_events(rows)
        await db.kv_set("wm:crowdsec", 0)
        await DetectionEngine(Settings(crowdsec_lapi_alerts=level)).crowdsec_alerts()
        return {r["fingerprint"]: (r["severity"], r["status"]) for r in await pool.fetch(
            "SELECT fingerprint, severity, status FROM alerts WHERE rule = 'crowdsec'")}

    async def main():
        await db.connect(DSN)
        try:
            await db.pool().execute("TRUNCATE events, alerts")
            now = datetime.now(timezone.utc)
            ev = lambda prog, ip, sc: event(now, "crowdsec", program=prog, severity=4, action="ban", src_ip=ip,  # noqa: E731
                                            data={"scenario": sc})
            got = await run("low", [ev("crowdsec-lapi", "45.8.8.8", "probing")])
            assert got == {"crowdsec-lapi:45.8.8.8:probing": ("low", "open")}
            # off: no new ones, the open one closed; inside the network still high; the OPNsense plugin unchanged
            got = await run("off", [ev("crowdsec-lapi", "45.7.7.7", "crawl"), ev("crowdsec-lapi", "192.168.1.5", "ssh-bf"),
                                    ev("crowdsec", "45.6.6.6", "ssh-bf")])
            assert got == {"crowdsec-lapi:45.8.8.8:probing": ("low", "closed"),
                           "crowdsec-lapi:192.168.1.5:ssh-bf": ("high", "open"),
                           "crowdsec:45.6.6.6:ssh-bf": ("low", "open")}
            got = await run("info", [ev("crowdsec-lapi", "45.5.5.5", "crawl")])
            assert got["crowdsec-lapi:45.5.5.5:crawl"] == ("info", "open")
        finally:
            await db.pool().execute("TRUNCATE events, alerts")
            await db.close()
    asyncio.run(main())


def test_crowdsec_opnsense_alert_setting():
    """Settings › OPNsense › CrowdSec (OPNsense) ban of an internet address: alert - off / info / low, like the SWAG
    one. Inside the network always high; CrowdSec in Docker (SWAG) keeps its own."""
    from datetime import datetime, timezone

    from lookingglass.config import Settings
    from lookingglass.detections import DetectionEngine
    from lookingglass.parsers.common import event

    async def run(level, rows):
        pool = db.pool()
        await pool.execute("TRUNCATE events")
        await db.copy_events(rows)
        await db.kv_set("wm:crowdsec", 0)
        await DetectionEngine(Settings(crowdsec_opnsense_alerts=level)).crowdsec_alerts()
        return {r["fingerprint"]: (r["severity"], r["status"]) for r in await pool.fetch(
            "SELECT fingerprint, severity, status FROM alerts WHERE rule = 'crowdsec'")}

    async def main():
        await db.connect(DSN)
        try:
            await db.pool().execute("TRUNCATE events, alerts")
            now = datetime.now(timezone.utc)
            ev = lambda prog, ip, sc: event(now, "crowdsec", program=prog, severity=4, action="ban", src_ip=ip,  # noqa: E731
                                            data={"scenario": sc})
            got = await run("low", [ev("crowdsec", "45.8.8.8", "probing")])
            assert got == {"crowdsec:45.8.8.8:probing": ("low", "open")}
            # off: no new ones, the open one closed; inside the network still high; the SWAG one unchanged
            got = await run("off", [ev("crowdsec", "45.7.7.7", "crawl"), ev("crowdsec", "192.168.1.5", "ssh-bf"),
                                    ev("crowdsec-lapi", "45.6.6.6", "ssh-bf")])
            assert got == {"crowdsec:45.8.8.8:probing": ("low", "closed"),
                           "crowdsec:192.168.1.5:ssh-bf": ("high", "open"),
                           "crowdsec-lapi:45.6.6.6:ssh-bf": ("low", "open")}
            got = await run("info", [ev("crowdsec", "45.5.5.5", "crawl")])
            assert got["crowdsec:45.5.5.5:crawl"] == ("info", "open")
        finally:
            await db.pool().execute("TRUNCATE events, alerts")
            await db.close()
    asyncio.run(main())
