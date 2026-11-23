"""Settings › Alert filters › Recurring mute windows: categories muted at set days / times every week."""
from __future__ import annotations

import asyncio
import os

from datetime import datetime, timezone

import pytest

from lookingglass import alert_filters as af
from lookingglass import app_config, mute_schedule as ms

# 2026-11-10 is a Tuesday; the time zone is UTC unless a test says otherwise
TUE = lambda h, m=0: datetime(2026, 11, 10, h, m, tzinfo=timezone.utc)  # noqa: E731
MON = lambda h, m=0: datetime(2026, 11, 9, h, m, tzinfo=timezone.utc)  # noqa: E731


def muted(spec: str, rule: str, now: datetime, tz: str = "UTC"):
    return ms.covering(spec, tz, rule, now)


def test_rule_on_a_day_with_minutes():
    spec = "unraid_container_errors tue 01:30-04:00"
    assert muted(spec, "unraid_container_errors", TUE(1, 30))
    hit = muted(spec, "unraid_container_errors", TUE(3, 59))
    assert hit["until"] == TUE(4).isoformat() and hit["id"] is None and "tue 01:30-04:00" in hit["name"]
    assert not muted(spec, "unraid_container_errors", TUE(4))       # the end is not included
    assert not muted(spec, "unraid_container_errors", TUE(1, 29))
    assert not muted(spec, "unraid_container_errors", MON(2))       # another day
    assert not muted(spec, "unraid_container_down", TUE(2))         # another rule


def test_groups_star_and_every_day():
    assert muted("unraid tue 01-04", "unraid_container_down", TUE(2))
    assert not muted("unraid tue 01-04", "backup_failed", TUE(2))
    assert muted("backups 02-03", "backup_failed", MON(2)) and muted("backups 02-03", "backup_overdue", TUE(2))
    assert muted("* 04:00-04:15", "port_scan", TUE(4, 10)) and not muted("* 04:00-04:15", "port_scan", TUE(4, 15))


def test_whole_days_and_past_midnight():
    sunday = datetime(2026, 11, 15, 9, tzinfo=timezone.utc)
    hit = muted("backups sat+sun", "backup_failed", sunday)
    assert hit["until"] == datetime(2026, 11, 16, tzinfo=timezone.utc).isoformat()
    assert not muted("backups sat+sun", "backup_failed", TUE(9))
    spec = "unraid mon 22:00-06:00"
    assert muted(spec, "unraid_disk", MON(23))
    assert muted(spec, "unraid_disk", TUE(5))["until"] == TUE(6).isoformat()  # Monday night, after midnight
    assert not muted(spec, "unraid_disk", TUE(23)) and not muted(spec, "unraid_disk", MON(5))
    assert muted("* tue 20:00-24:00", "x", TUE(23, 59))


def test_local_time_zone():
    # 01:30 in Amsterdam (winter, UTC+1) is 00:30 UTC
    assert muted("unraid tue 01-02", "unraid_disk", TUE(0, 30), "Europe/Amsterdam")
    assert not muted("unraid tue 01-02", "unraid_disk", TUE(1, 30), "Europe/Amsterdam")


@pytest.mark.parametrize("bad", ["unraid", "nope tue 01-02", "unraid tuex 01-02", "unraid tue 01", "unraid 03-03",
                                 "unraid 25:00-26:00", "unraid 01:5-02:00", "unraid tue wed", "unraid 01-02 03-04"])
def test_unreadable_entries_are_refused(bad):
    with pytest.raises(ValueError):
        ms.parse(bad)


def test_settings_check_entries_and_bad_saved_lines_are_skipped():
    f = app_config.BY_KEY["mute_schedule"]
    assert app_config._coerce(f, "unraid tue 01-04\nbackups sun") == "unraid tue 01-04, backups sun"
    with pytest.raises(app_config.SettingsError, match="unknown category"):
        app_config._coerce(f, "unraid_containers tue 01-04")
    assert muted("garbage here, unraid tue 01-04", "unraid_disk", TUE(2))


def test_group_names_are_never_rule_names_and_cover_every_group():
    assert not set(ms.GROUPS) & af.RULE_NAMES
    assert set(ms.GROUPS.values()) == set(af.RULES)
    ref = ms.reference()
    assert {r["rule"] for g in ref["groups"] for r in g["rules"]} == af.RULE_NAMES
    for example, _ in ref["examples"]:
        ms.parse(example)


DSN = os.environ.get("TEST_DATABASE_URL")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_alerts_inside_a_window_are_stored_silently(monkeypatch):
    from lookingglass import db, snooze
    from lookingglass.config import get_settings
    from lookingglass.detections import raise_alert

    s = get_settings()
    monkeypatch.setattr(s, "mute_schedule", "unraid_container_errors 00:00-24:00")  # all day, every day

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, snoozes, alert_filters")
            await raise_alert("unraid_container_errors", "medium", "Errors in plex", "ce:plex")
            await raise_alert("unraid_container_down", "medium", "plex stopped", "cd:plex")
            rows = {r["rule"]: r for r in await pool.fetch("SELECT rule, status, close_reason, data FROM alerts")}
            muted_row = rows["unraid_container_errors"]
            assert muted_row["status"] == "closed" and muted_row["close_reason"] == "muted"
            assert muted_row["data"]["snoozed"]["recurring"] == "unraid_container_errors 00:00-24:00"
            assert rows["unraid_container_down"]["status"] == "open"
            # already open: not mailed while a window covers it
            monkeypatch.setattr(s, "mute_schedule", "unraid 00:00-24:00")
            alerts = [{"id": 1, "rule": "unraid_container_down"}, {"id": 2, "rule": "port_scan"}]
            assert set(await snooze.covering(alerts)) == {1}
        finally:
            await db.close()
    asyncio.run(main())
