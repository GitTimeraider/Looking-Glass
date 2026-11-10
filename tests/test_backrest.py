"""Backrest: API parsing (secrets never kept), schedules, run speed data, URL with port, and the backup alerts."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from lookingglass import app_config, backrest, backups
from lookingglass.app_config import SettingsError


def test_url_needs_a_port():
    f = app_config.BY_KEY["backrest_url"]
    assert app_config._coerce(f, "http://192.168.1.10:9898") == "http://192.168.1.10:9898"
    assert app_config._coerce(f, "https://backup.example.com:8443/backrest/") == "https://backup.example.com:8443/backrest/"
    assert app_config._coerce(f, "http://backrest:19898") == "http://backrest:19898"
    with pytest.raises(SettingsError, match="add the port"):
        app_config._coerce(f, "http://192.168.1.10")
    with pytest.raises(SettingsError, match="http://"):
        app_config._coerce(f, "192.168.1.10:9898")
    with pytest.raises(SettingsError, match="port"):
        app_config._coerce(f, "http://192.168.1.10:99999")
    assert app_config._coerce(f, "") == ""  # not set up


def test_config_drops_secrets():
    cfg = {"instance": "tower", "auth": {"disabled": False, "users": [{"name": "a", "passwordBcrypt": "$2a$HASH"}]},
           "repos": [{"id": "nas", "uri": "rest:https://restic:topsecret@nas:8000/x", "password": "REPOPASS",
                      "env": ["AWS_SECRET_ACCESS_KEY=SECRETKEY"], "flags": ["--limit-upload 100"],
                      "prunePolicy": {"schedule": {"maxFrequencyDays": 7}}}],
           "plans": [{"id": "docs", "repo": "nas", "paths": ["/data"], "excludes": ["*.tmp"], "iexcludes": ["*.BAK"],
                      "schedule": {"cron": "0 2 * * *"}, "retention": {"policyKeepLastN": 30},
                      "hooks": [{"actionWebhook": {"webhookUrl": "https://hook/SECRET"}}]}]}
    out = backrest.parse_config(cfg)
    text = repr(out)
    for secret in ("topsecret", "REPOPASS", "SECRETKEY", "HASH", "hook/SECRET", "limit-upload"):
        assert secret not in text
    assert out["repos"][0]["uri"] == "rest:https://restic:***@nas:8000/x" and out["repos"][0]["prune"] == "every 7 days"
    p = out["plans"][0]
    assert p["schedule"] == "cron 0 2 * * *" and p["gap_s"] == 86400 and not p["disabled"]
    assert p["retention"] == "keep last 30" and p["excludes"] == 2 and out["auth"] is True and out["instance"] == "tower"


def test_schedules():
    assert backrest.cron_max_gap("0 2 * * *") == 86400
    assert backrest.cron_max_gap("*/15 * * * *") == 900
    assert backrest.cron_max_gap("0 */6 * * *") == 6 * 3600
    assert backrest.cron_max_gap("0 2 * * 1-5") == 3 * 86400  # Friday to Monday
    assert backrest.cron_max_gap("30 1 * * sun") == 7 * 86400
    assert backrest.cron_max_gap("0 3 1,15 * *") == 17 * 86400  # 15th to the 1st (31-day month)
    assert backrest.cron_max_gap("@daily") == 86400
    assert backrest.cron_max_gap("0 0 1 1 *") is None  # months restricted: from history instead
    assert backrest.cron_max_gap("nonsense") is None
    assert backrest.schedule_info({"maxFrequencyHours": 6, "clock": "CLOCK_LAST_RUN_TIME"}) == \
        ("every 6 hours after the last run", 21600, False)
    assert backrest.schedule_info({"disabled": True})[2] is True
    assert backrest.schedule_info(None) == ("not scheduled", None, True)
    assert backrest.retention_text({"policyTimeBucketed": {"daily": 7, "weekly": 4, "keepLastN": 2}}) == "keep 7 daily, 4 weekly, last 2"
    assert backups.overdue_threshold(86400) == 86400 * 1.25 + 7200
    assert backups.overdue_threshold(86400, 48) == 48 * 3600
    assert backups.overdue_threshold(None) is None


def test_operations():
    ok = backrest.run_from_op({"id": "17", "planId": "docs", "repoId": "nas", "status": "STATUS_SUCCESS",
                               "unixTimeStartMs": "1792400000000", "unixTimeEndMs": "1792400100000",
                               "operationBackup": {"lastStatus": {"summary": {
                                   "filesNew": "3", "filesChanged": "2", "dataAdded": "5000000", "totalFilesProcessed": "900",
                                   "totalBytesProcessed": "4000000000", "totalDuration": 80.0, "snapshotId": "abcd"}}}})
    assert ok["kind"] == "backup" and ok["status"] == "success" and ok["ext_id"] == "17" and ok["job"] == "docs"
    assert ok["bytes_processed"] == 4_000_000_000 and ok["bytes_added"] == 5_000_000 and ok["duration_s"] == 80.0
    assert ok["snapshot_id"] == "abcd" and ok["files_total"] == 900 and ok["started"].year == 2026
    # proto field names (snake_case) are understood as well
    snake = backrest.run_from_op({"id": 3, "plan_id": "docs", "status": 4, "unix_time_start_ms": 1792400000000,
                                  "unix_time_end_ms": 1792400030000, "operation_backup": {}, "display_message": "locked"})
    assert snake["status"] == "error" and snake["message"] == "locked" and snake["duration_s"] == 30
    running = backrest.run_from_op({"id": "18", "planId": "docs", "status": "STATUS_INPROGRESS", "unixTimeStartMs": "1792400000000",
                                    "operationBackup": {"lastStatus": {"status": {"percentDone": 0.5, "bytesDone": "10", "totalBytes": "20"}}}})
    assert running["status"] == "running" and running["data"]["progress"]["percent"] == 0.5 and running["duration_s"] is None
    warn = backrest.run_from_op({"id": "19", "planId": "docs", "status": "STATUS_WARNING", "operationBackup": {
        "errors": [{"item": "/a", "message": "permission denied"}], "lastStatus": {"summary": {"totalDuration": 1}}}})
    assert warn["status"] == "warning" and warn["data"]["error_count"] == 1
    stats = backrest.run_from_op({"id": "20", "planId": "_system_", "repoId": "nas", "status": "STATUS_SUCCESS",
                                  "operationStats": {"stats": {"totalSize": "100", "compressionRatio": 1.5, "snapshotCount": "9"}}})
    assert stats["kind"] == "stats" and stats["job"] == "" and stats["data"]["stats"]["snapshot_count"] == 9
    assert backrest.run_from_op({"id": "21", "operationIndexSnapshot": {}}) is None
    assert backrest.run_from_op({"id": "22", "operationBackup": {"dryRun": True}})["kind"] == "dry-run"


DSN = os.environ.get("TEST_DATABASE_URL")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_backup_alerts_open_and_close_by_themselves():
    import asyncio

    from lookingglass import alert_filters, db

    now = datetime.now(timezone.utc)
    job = {"job": "docs", "repo": "nas", "schedule": "cron 0 2 * * *", "gap_s": 86400.0,
           "threshold_s": backups.overdue_threshold(86400.0), "disabled": False, "next_run": None}

    def run(i, status, hours_ago, msg=None):
        t = now - timedelta(hours=hours_ago)
        return {"ext_id": str(i), "kind": "backup", "job": "docs", "repo": "nas", "status": status, "started": t,
                "ended": t + timedelta(minutes=10), "duration_s": 600.0, "bytes_processed": 6_000_000_000,
                "bytes_added": 60_000_000, "files_new": 1, "files_changed": 1, "files_total": 10, "snapshot_id": None,
                "message": msg, "data": {}}

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, alert_filters, backup_runs")
            await pool.execute("DELETE FROM snapshots WHERE key LIKE 'backup_jobs:%' OR key LIKE 'backrest:%'")
            alert_filters.invalidate()
            alerts = lambda: pool.fetch("SELECT rule, status, severity, count FROM alerts ORDER BY id")  # noqa: E731
            await backups.store_runs("backrest", [run(1, "success", 50), run(2, "error", 26, "repository is locked")])
            await backups.check_jobs("backrest", "Backrest", [job], now=now)
            rows = await alerts()
            # failed, and the last good backup is 50 h old (a daily plan: overdue after 32 h)
            assert [(r["rule"], r["status"], r["severity"]) for r in rows] == [("backup_failed", "open", "medium"),
                                                                               ("backup_overdue", "open", "medium")]
            # polled again: not counted twice; failing again: more severe, count = failures in a row
            await backups.check_jobs("backrest", "Backrest", [job], now=now)
            assert (await alerts())[0]["count"] == 1
            await backups.store_runs("backrest", [run(3, "error", 2, "repository is locked")])
            await backups.check_jobs("backrest", "Backrest", [job], now=now)
            rows = await alerts()
            assert len(rows) == 2 and rows[0]["severity"] == "high" and rows[0]["count"] == 2
            assert rows[1]["rule"] == "backup_overdue" and rows[1]["status"] == "open"  # last good backup 50 h ago
            # the next one works: both close by themselves
            await backups.store_runs("backrest", [run(4, "success", 1)])
            await backups.check_jobs("backrest", "Backrest", [job], now=now)
            assert [r["status"] for r in await alerts()] == ["closed", "closed"]
            # a warning: low alert, closed by the next clean backup
            await backups.store_runs("backrest", [run(5, "warning", 0.5, "Partial backup, 1 errors")])
            await backups.check_jobs("backrest", "Backrest", [job], now=now)
            assert (await alerts())[-1]["rule"] == "backup_warning" and (await alerts())[-1]["severity"] == "low"
            await backups.check_jobs("backrest", "Backrest", [job], warnings=False, now=now)  # switched off: closed
            assert (await alerts())[-1]["status"] == "closed"
            await backups.store_runs("backrest", [run(6, "success", 0.2)])
            await backups.check_jobs("backrest", "Backrest", [job], now=now)
            assert all(r["status"] == "closed" for r in await alerts())
            # running and the stored row is updated in place
            r7 = run(7, "running", 0.1)
            await backups.store_runs("backrest", [r7])
            await backups.store_runs("backrest", [{**r7, "status": "success"}])
            assert await pool.fetchval("SELECT count(*) FROM backup_runs WHERE ext_id = '7' AND status = 'success'") == 1
            # repository check failed -> high, closed when the next check works
            t = now - timedelta(hours=3)
            check = {**run(8, "error", 3, "pack damaged"), "kind": "check", "job": ""}
            await backups.store_runs("backrest", [check])
            await backups.check_repos("backrest", "Backrest", ["nas"])
            row = (await alerts())[-1]
            assert (row["rule"], row["severity"], row["status"]) == ("backup_repo_problem", "high", "open")
            await backups.store_runs("backrest", [{**check, "ext_id": "9", "status": "success", "started": t + timedelta(hours=1)}])
            await backups.check_repos("backrest", "Backrest", ["nas"])
            assert (await alerts())[-1]["status"] == "closed"
            # the Main tab and the Backrest tab
            await db.set_snapshot("backup_jobs:backrest", {"label": "Backrest", "jobs": [job]})
            ov = await backups.overview(30)
            j = ov["jobs"][0]
            assert j["job"] == "docs" and j["state"] == "ok" and j["failed"] == 2 and j["ok"] == 4 and j["warned"] == 1
            assert ov["sources"][0]["source"] == "backrest" and sum(d["n"] for d in ov["daily"]) == 7
            detail = await backups.source_detail("backrest", 30)
            speeds = {r["ext_id"]: r["speed_bps"] for r in detail["runs"]}
            assert speeds["1"] == 10_000_000  # 6 GB in 600 s
            assert detail["per_job"][0]["added_bps"] == 100_000 and len(detail["maintenance"]) == 2
            # no successful backup for longer than the threshold -> overdue in the Main tab too
            late = now + timedelta(hours=40)
            assert backups.job_state({**j, "last_good": datetime.fromisoformat(j["last_good"])}, late) == "overdue"
        finally:
            await db.close()

    asyncio.run(main())
