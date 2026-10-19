import asyncio
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

import pytest

from lookingglass import db, notify
from lookingglass.config import Settings

DSN = os.environ.get("TEST_DATABASE_URL")


def test_clean_and_recipients():
    assert notify.recipients("a@x.org; b@y.com ,c@z.net") == ["a@x.org", "b@y.com", "c@z.net"]
    for bad in ({}, {"recipients": "nope"}, {"recipients": "a@x.org"},  # no condition: would mail everything
                {"recipients": "a@x.org", "min_severity": "huge"}):
        with pytest.raises(ValueError):
            notify.clean(bad)
    r = notify.clean({"recipients": "a@x.org", "min_severity": "high", "min_interval": "99999"})
    assert r["min_interval"] == 1440 and r["on_escalation"] and r["match_mode"] == "all"


def test_matching_and_due():
    rule = {"id": 7, "min_severity": "high", "on_escalation": True, "match_mode": "all"}
    a = {"rule": "port_scan", "severity": "high", "title": "t", "data": {}}
    assert notify._matches(rule, a) and not notify._matches(rule, {**a, "severity": "medium"})
    assert notify._matches(rule, {**a, "severity": "critical"})
    assert notify._due(rule, a)
    assert not notify._due(rule, {**a, "data": {"notified": {"7": "high"}}})
    assert notify._due(rule, {**a, "severity": "critical", "data": {"notified": {"7": "high"}}})  # escalated
    assert not notify._due({**rule, "on_escalation": False}, {**a, "severity": "critical", "data": {"notified": {"7": "high"}}})


def test_compose_bundles_worst_first():
    alerts = [{"id": 1, "severity": "medium", "title": "Scan <b>", "data": {}},
              {"id": 2, "severity": "critical", "title": "Login after attack", "data": {"severity_why": ["logged in"]},
               "src_ip": "203.0.113.9"}]
    subject, text, body = notify.compose({"id": 1, "name": "Mine"}, alerts, "https://lg.lan/")
    assert subject == "[Looking Glass] 2 alerts, worst critical: Login after attack"
    assert text.index("Login after attack") < text.index("Scan") and "https://lg.lan/alerts#2" in text
    assert "Scan &lt;b&gt;" in body and "Why: logged in" in body


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_notifier_sends_once_bundles_and_escalates(tmp_path):
    port = 25250
    srv = subprocess.Popen([sys.executable, "tools/mock_smtp.py", str(port), str(tmp_path)], stdout=subprocess.PIPE)
    time.sleep(0.7)
    s = Settings(smtp_host="127.0.0.1", smtp_port=port, smtp_security="none", smtp_username="u", smtp_password="p",
                 smtp_from="lg@example.org")

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, notification_rules")
            old = datetime.now(timezone.utc) - timedelta(hours=2)
            await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint, created_at, last_seen) "
                               "VALUES ('x', 'critical', 'from before the rule', 'f0', $1, $1)", old)
            await pool.execute("INSERT INTO notification_rules (recipients, min_severity) VALUES ('me@example.org', 'high')")
            await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint) VALUES "
                               "('port_scan', 'high', 'scan A', 'f1'), ('brute_force', 'critical', 'brute B', 'f2'), "
                               "('port_scan', 'low', 'scan low', 'f3')")
            assert await notify.run_once(s) == 1
            assert await notify.run_once(s) == 0  # nothing new
            mails = sorted(tmp_path.glob("*.eml"))
            assert len(mails) == 1
            m = mails[0].read_text()
            assert "brute B" in m and "scan A" in m and "scan low" not in m and "from before" not in m
            assert "2 alerts, worst critical" in m
            await pool.execute("UPDATE alerts SET severity = 'critical' WHERE fingerprint = 'f1'")  # escalation
            assert await notify.run_once(s) == 1
            await pool.execute("UPDATE notification_rules SET min_interval = 60")
            await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint) VALUES ('x', 'high', 'later', 'f4')")
            assert await notify.run_once(s) == 0  # throttled: waits for the interval
            row = await pool.fetchrow("SELECT sent_count, last_error FROM notification_rules")
            assert row["sent_count"] == 2 and row["last_error"] is None
            await pool.execute("UPDATE notification_rules SET min_interval = 0")
            bad = s.model_copy(update={"smtp_port": 1})
            assert await notify.run_once(bad) == 0
            assert await pool.fetchval("SELECT last_error FROM notification_rules")
            await pool.execute("TRUNCATE alerts, notification_rules")
        finally:
            await db.close()

    try:
        asyncio.run(main())
    finally:
        srv.terminate()
