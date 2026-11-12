import asyncio
import os
from datetime import date

import pytest

from lookingglass import app_config, db
from lookingglass.config import Settings
from lookingglass.reports import report_due

DSN = os.environ.get("TEST_DATABASE_URL")


def test_report_every_n_days():
    today = date(2026, 10, 27)
    assert report_due(None, today, 7) and report_due("garbage", today, 1)
    assert not report_due("2026-10-27", today, 1) and report_due("2026-10-26", today, 1)  # daily
    assert not report_due("2026-10-21", today, 7) and report_due("2026-10-20", today, 7)  # weekly
    assert report_due("2026-10-26", today, 0)  # 0 is treated as daily


def test_report_settings():
    by_key = {f.key: f for f in app_config.FIELDS}
    assert {by_key[k].group for k in ("ai_daily_report", "ai_daily_report_hour", "report_every_days", "report_mail_to")} == {"reports"}
    assert app_config._coerce(by_key["report_mail_to"], "a@example.com\nb@example.com") == "a@example.com, b@example.com"
    with pytest.raises(app_config.SettingsError, match="not a mail address"):
        app_config._coerce(by_key["report_mail_to"], "a@example.com, nope")
    with pytest.raises(app_config.SettingsError):
        app_config._coerce(by_key["report_every_days"], 0)


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_report_mail_and_mail_now(monkeypatch):
    from lookingglass import notify
    from lookingglass.reports import report_mail
    from lookingglass.web.app import create_app

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            data = {"alerts_by_severity": [{"severity": "high", "n": 2}, {"severity": "low", "n": 5}],
                    "alerts": [{"severity": "high", "title": "Brute force from 203.0.113.9"},
                               {"severity": "low", "title": "New device"}],
                    "firewall_actions": [{"action": "block", "n": 1234}, {"action": "pass", "n": 99}]}
            rid = await pool.fetchval("INSERT INTO reports (period_h, title, data, ai_summary) VALUES "
                                      "(168, 'Security report 2026-10-27 (7 days)', $1, '## Summary\nAll <quiet>.') RETURNING id", data)
            subject, text, body = await report_mail(rid, "http://lg.local:8080/")
            assert subject == "[Looking Glass] Security report 2026-10-27 (7 days): 2 high, 5 low"
            assert "last 7 days" in text and "Firewall blocks: 1234" in text and "[HIGH] Brute force" in text
            assert "New device" not in text  # only critical / high / medium are listed
            assert f"http://lg.local:8080/reports/{rid}" in text and "All <quiet>." in text
            assert "All &lt;quiet&gt;." in body and "Settings › Reports" in body
            assert await report_mail(999999) is None
            # "Email" on the report page: to the report recipients
            sent = []

            async def fake_send(s, to, subject, text, body):
                sent.append((to, subject))
            monkeypatch.setattr(notify, "send", fake_send)
            s = Settings(smtp_host="smtp.example.com", smtp_from="lg@example.com", report_mail_to="me@example.com")
            ep = next(r.endpoint for r in create_app(s, None).routes if getattr(r, "path", "") == "/api/reports/{report_id}/mail")
            assert (await ep(rid, {}))["to"] == ["me@example.com"] and sent[0][0] == ["me@example.com"]
            await pool.execute("DELETE FROM reports WHERE id = $1", rid)
        finally:
            await db.close()

    asyncio.run(main())


# ----------------------------------------------------------- categories ---
def test_report_categories():
    from lookingglass.reports import (CATEGORIES, alert_rules, category_label, parse_categories, report_title,
                                      sections_for)
    assert parse_categories(None) == parse_categories("") == parse_categories(["nope"]) == list(CATEGORIES)
    assert parse_categories("Backups, OPNsense") == ["opnsense", "backups"]  # names or keys, in a fixed order
    assert parse_categories(["unraid", "UniFi"]) == ["unifi", "unraid"]
    assert category_label(list(CATEGORIES)) == "" and category_label(["unifi", "unraid"]) == "UniFi + Unraid"
    assert report_title("Weekly", list(CATEGORIES)) == "Weekly security report"
    assert report_title("Daily", ["unraid"], "2026-11-12") == "Daily Unraid report 2026-11-12"
    # alerts: all = no filter; else the rule groups of Settings › Alert filters
    assert alert_rules(list(CATEGORIES)) is None
    unraid = alert_rules(["unraid"])
    assert "unraid_disk" in unraid and "backup_failed" not in unraid and "port_scan" not in unraid
    assert set(alert_rules(["backups"])) == {"backup_failed", "backup_warning", "backup_overdue", "backup_repo_problem",
                                             "backup_source_unreachable"}
    assert "new_device" in alert_rules(["unifi"]) and "new_device" in alert_rules(["opnsense"])
    assert "port_scan" in alert_rules(["opnsense"]) and "unifi_rogue_dhcp" not in alert_rules(["opnsense"])
    # sections: only those of the categories (+ totals and alerts in every report)
    b = sections_for(["backups"])
    assert set(b) == {"totals_by_source", "alerts_by_severity", "alerts", "backups"}
    u = sections_for(["unraid"])
    assert "unraid_storage" in u and "auth_failures" in u and "top_blocked_sources" not in u and "unifi_events" not in u
    assert {"top_blocked_sources", "dns_blocked", "unraid_storage", "unifi_clients", "backups"} <= set(sections_for(list(CATEGORIES)))


def test_report_ai_prompt_per_category():
    from lookingglass.ai import review_prompt
    full = review_prompt(24, None)
    assert "full security and health review" in full and "Unraid:" in full and "Backups:" in full
    only = review_prompt(168, ["unraid", "backups"])
    assert "Unraid + Backups only" in only and "leaves out OPNsense, UniFi" in only
    assert "Unraid:" in only and "Backups:" in only and "OPNsense:" not in only


def test_report_categories_setting():
    f = {f.key: f for f in app_config.FIELDS}["report_categories"]
    assert f.group == "reports" and Settings().report_categories == "OPNsense, UniFi, Unraid, Backups"
    assert app_config._coerce(f, ["backups", "Unraid"]) == "Unraid, Backups"
    assert app_config._coerce(f, "opnsense,unifi") == "OPNsense, UniFi"
    with pytest.raises(app_config.SettingsError, match="at least one"):
        app_config._coerce(f, [])
    with pytest.raises(app_config.SettingsError, match="unknown"):
        app_config._coerce(f, ["OPNsense", "Proxmox"])


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_report_per_category():
    from lookingglass.reports import QUERIES, build_report, report_mail
    from lookingglass.web.app import create_app

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            sid = await pool.fetchval("INSERT INTO unraid_servers (name, url, api_key) VALUES ('rtest-tower', 'http://x', 'k') "
                                      "RETURNING id")
            await pool.execute("INSERT INTO snapshots (key, data) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET data = $2, ts = now()",
                               f"unraid:{sid}:storage", {"state": "STARTED", "groups": [
                                   {"name": "array", "kind": "array", "used_pct": 71.5, "free": 1000, "disks": 4, "errors": 0,
                                    "max_temp": 38, "excluded": False},
                                   {"name": "skip", "kind": "pool", "excluded": True}]})
            await pool.executemany("INSERT INTO metrics (name, labels, value) VALUES ($1, $2, $3)",
                                   [("unraid_cpu_pct", str(sid), 10), ("unraid_cpu_pct", str(sid), 30), ("unraid_mem_pct", str(sid), 50)])
            ev = ("INSERT INTO events (ts, source, host, program, severity, action, src_ip, message, data) "
                  "VALUES (now(), $1, $2, $3, $4, $5, $6::inet, 'rtest', $7)")
            await pool.executemany(ev, [
                ("unraid", "rtest-tower", "notification", 2, "notification", None, {"importance": "ALERT", "subject": "rtest disk 3 hot"}),
                ("docker", "rtest-tower", "rtest-app", 3, "container_log", None, {}),
                ("docker", "rtest-tower", "rtest-app", 4, "container_log", None, {}),
                ("auth", "rtest-tower", "sshd", 4, "login_failed", "198.51.100.77", {}),  # an Unraid server's syslog
                ("auth", "rtest-fw", "sshd", 4, "login_failed", "198.51.100.78", {}),  # OPNsense
                ("unifi", "unifi", "unifi", 3, "device_offline", None, {"ap_name": "rtest-ap"}),
                ("unifi", "unifi", "unifi", 6, "client_roam", None, {"mac": "aa:bb:cc:00:00:01", "hostname": "rtest-phone"}),
                ("firewall", "rtest-fw", "filterlog", 6, "block", "198.51.100.79", {})])
            await pool.executemany("INSERT INTO alerts (rule, severity, title, fingerprint) VALUES ($1, $2, $3, $4)",
                                   [("unraid_disk_temp", "high", "rtest disk", "rtest:1"), ("port_scan", "medium", "rtest scan", "rtest:2"),
                                    ("backup_failed", "high", "rtest backup", "rtest:3")])

            # every query runs (build_report leaves a failing section empty: run them directly)
            from lookingglass.reports import _CATEGORY_PARAM, _RULE_PARAM
            for name, sql in QUERIES.items():
                args = [3600.0] + ([None] if name in _CATEGORY_PARAM | _RULE_PARAM else [])
                await pool.fetch(sql, *args)

            r = await build_report(1, ["unraid"])
            assert r["categories"] == ["unraid"] and "top_blocked_sources" not in r and "backups" not in r
            assert [g["grp"] for g in r["unraid_storage"] if g["server"] == "rtest-tower"] == ["array"]
            res = next(x for x in r["unraid_resources"] if x["server"] == "rtest-tower")
            assert res["cpu_avg"] == 20 and res["cpu_max"] == 30 and res["mem_max"] == 50
            assert any(n["subject"] == "rtest disk 3 hot" and n["importance"] == "ALERT" for n in r["unraid_notifications"])
            assert any(c["container"] == "rtest-app" and c["errors"] == 1 and c["warnings"] == 1 for c in r["unraid_container_logs"])
            assert {a["ip"] for a in r["auth_failures"]} >= {"198.51.100.77"} and "198.51.100.78" not in {a["ip"] for a in r["auth_failures"]}
            titles = {a["title"] for a in r["alerts"]}
            assert "rtest disk" in titles and not {"rtest scan", "rtest backup"} & titles
            assert set(r["totals"]) <= {"unraid", "docker"}

            r = await build_report(1, ["unifi"])
            assert any(d["device"] == "rtest-ap" and d["offline"] == 1 for d in r["unifi_devices"])
            assert any(c["client"] == "rtest-phone" and c["roams"] == 1 for c in r["unifi_clients"])
            assert "unraid_storage" not in r and set(r["totals"]) <= {"unifi"}

            r = await build_report(1)  # all: everything, alerts unfiltered
            assert {"rtest disk", "rtest scan", "rtest backup"} <= {a["title"] for a in r["alerts"]}
            assert {"198.51.100.77", "198.51.100.78"} <= {a["ip"] for a in r["auth_failures"]}

            # the API: title, the categories stored with the report and in the list; the mail leaves out the firewall
            app = create_app(Settings(), None)
            ep = lambda path, method: next(x.endpoint for x in app.routes  # noqa: E731
                                           if getattr(x, "path", "") == path and method in getattr(x, "methods", ()))
            rid = (await ep("/api/reports", "POST")({"hours": 1, "categories": ["backups", "unraid"]}))["id"]
            row = await pool.fetchrow("SELECT title, data FROM reports WHERE id = $1", rid)
            assert row["title"] == "1h Unraid + Backups report" and row["data"]["categories"] == ["unraid", "backups"]
            listed = next(x for x in await ep("/api/reports", "GET")() if x["id"] == rid)
            assert listed["categories"] == ["unraid", "backups"]
            subject, text, body = await report_mail(rid)
            assert "covers Unraid + Backups" in text and "Firewall blocks" not in text and "Firewall blocks" not in body
            with pytest.raises(Exception, match="categories"):
                await ep("/api/reports", "POST")({"hours": 1, "categories": ["proxmox"]})
            cats = await ep("/api/reports/categories", "GET")()
            assert [c["key"] for c in cats["categories"]] == ["opnsense", "unifi", "unraid", "backups"]
            assert next(c for c in cats["categories"] if c["key"] == "unraid")["configured"] is True
            await pool.execute("DELETE FROM reports WHERE id = $1", rid)
        finally:
            await pool.execute("DELETE FROM events WHERE message = 'rtest'")
            await pool.execute("DELETE FROM alerts WHERE fingerprint LIKE 'rtest:%'")
            await pool.execute("DELETE FROM metrics WHERE labels = (SELECT id::text FROM unraid_servers WHERE name = 'rtest-tower')")
            await pool.execute("DELETE FROM snapshots WHERE key LIKE 'unraid:' || (SELECT id FROM unraid_servers WHERE name = 'rtest-tower') || ':%'")
            await pool.execute("DELETE FROM unraid_servers WHERE name = 'rtest-tower'")
            await db.close()

    asyncio.run(main())
