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
