import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest

from lookingglass import db, notify, snooze
from lookingglass.detections import raise_alert

DSN = os.environ.get("TEST_DATABASE_URL")


def test_clean_and_match():
    now = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)
    v = snooze.clean({"minutes": 120, "networks": "192.168.1.20, 10.0.0.0/24", "rules": ["unraid_disk"]}, now=now)
    assert v["starts_at"] == now and v["ends_at"] == now + timedelta(hours=2)
    assert v["networks"] == "192.168.1.20/32, 10.0.0.0/24" and v["rules"] == ["unraid_disk"]
    for bad in ({}, {"minutes": 60 * 24 * 40}, {"ends_at": "2026-10-01T00:00:00Z"}, {"minutes": 5, "rules": ["nope"]},
                {"minutes": 5, "networks": "x"}):
        with pytest.raises(ValueError):
            snooze.clean(bad, now=now)
    sn = {**v, "_nets": None}
    inside = now + timedelta(minutes=5)
    assert snooze.matches(sn, "unraid_disk", None, "10.0.0.7", inside)
    assert not snooze.matches(sn, "port_scan", "192.168.1.20", None, inside)
    assert not snooze.matches(sn, "unraid_disk", "192.168.2.1", None, inside)
    assert not snooze.matches(sn, "unraid_disk", "192.168.1.20", None, now + timedelta(hours=3))
    everything = snooze.clean({"minutes": 30}, now=now)
    assert snooze.matches({**everything, "_nets": []}, "anything", None, None, inside)


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_snoozed_alerts_are_stored_silently_and_not_mailed():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, snoozes, alert_filters")
            # already open before the snooze
            await raise_alert("unraid_disk", "medium", "Disk 1 hot", "disk1", src_ip="192.168.1.20")
            await pool.execute("INSERT INTO snoozes (name, ends_at, networks, rules) VALUES "
                               "('parity check', now() + interval '1 hour', '192.168.1.20/32', '{}')")
            snooze.invalidate()
            await raise_alert("unraid_disk", "medium", "Disk 2 hot", "disk2", src_ip="192.168.1.20")
            await raise_alert("port_scan", "medium", "scan", "scan1", src_ip="192.168.1.99")
            rows = {r["fingerprint"]: r for r in await pool.fetch("SELECT fingerprint, status, close_reason, data FROM alerts")}
            assert rows["disk2"]["status"] == "closed" and rows["disk2"]["close_reason"] == "muted"
            assert rows["disk2"]["data"]["snoozed"]["name"] == "parity check"
            assert rows["disk1"]["status"] == "open" and rows["scan1"]["status"] == "open"
            assert await pool.fetchval("SELECT hits FROM snoozes") == 1
            alerts = [dict(r) for r in await pool.fetch(
                "SELECT id, rule, host(src_ip) src_ip, host(dst_ip) dst_ip FROM alerts WHERE status = 'open'")]
            covered = await snooze.covering(alerts)
            assert {a["id"] for a in alerts if a["id"] in covered} == {
                a["id"] for a in alerts if a["src_ip"] == "192.168.1.20"}
            # the notifier leaves the open, covered alert alone
            sent = []

            async def fake_send(s, to, subject, text, body=None):
                sent.append(subject)
            notify_send, notify.send = notify.send, fake_send
            try:
                from lookingglass.config import Settings
                await pool.execute("TRUNCATE notification_rules")
                await pool.execute("INSERT INTO notification_rules (recipients, min_severity, created_at) VALUES "
                                   "('a@example.com', 'info', now() - interval '1 day')")
                await notify.run_once(Settings(smtp_host="mail", smtp_from="lg@example.com"))
            finally:
                notify.send = notify_send
            assert len(sent) == 1 and "scan" in sent[0]
            await pool.execute("TRUNCATE alerts, snoozes, notification_rules")
            snooze.invalidate()
        finally:
            await db.close()

    asyncio.run(main())
