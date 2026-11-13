"""Bichon: metrics parsing, sync runs from Bichon's history and from the metrics alone, Bichon's own backup, URL with
port, and the poller end to end (token refused for the history -> metrics, failed / partial / overdue alerts)."""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from lookingglass import app_config, backups, bichon
from lookingglass.app_config import SettingsError
from lookingglass.config import Settings

NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
T = NOW.timestamp()


def metrics_text(start=T - 600, succeeded=1, running=0, partial=0, failed_backups=0, emails=1200) -> str:
    """A metrics page as Bichon 2.4 writes it (prometheus TextEncoder)."""
    return f"""# HELP bichon_build_info Bichon build information.
# TYPE bichon_build_info gauge
bichon_build_info{{version="2.4.1"}} 1
# TYPE bichon_uptime_seconds gauge
bichon_uptime_seconds 86400.5
bichon_accounts_total{{type="imap"}} 2
bichon_accounts_total{{type="nosync"}} 1
bichon_accounts_total{{type="view"}} 0
bichon_users_total 2
bichon_account_mailbox_folders_total 14
bichon_emails_total 5200
bichon_attachments_total 830
bichon_storage_usage_bytes 7340032000
bichon_index_usage_bytes 524288000
bichon_account_info{{account_id="11",email="me@example.com",enabled="true",name="Me \\"work\\"",type="imap"}} 1
bichon_account_info{{account_id="12",email="old@example.com",enabled="false",name="old@example.com",type="imap"}} 1
bichon_account_info{{account_id="13",email="import@local",enabled="true",name="Imported",type="nosync"}} 1
bichon_account_sync_running{{account_id="11"}} {running}
bichon_account_last_sync_start_timestamp_seconds{{account_id="11"}} {start}
bichon_account_last_sync_success_timestamp_seconds{{account_id="11"}} {T - 590 if succeeded else T - 90000}
bichon_account_last_sync_succeeded{{account_id="11"}} {succeeded}
bichon_account_last_sync_duration_seconds{{account_id="11"}} 10.25
bichon_account_last_sync_errors{{account_id="11"}} {0 if succeeded else 3}
bichon_account_emails_total{{account_id="11"}} {emails}
bichon_account_emails_total{{account_id="12"}} 4000
bichon_account_emails_total{{account_id="13"}} 0
bichon_account_download_interval_minutes{{account_id="11"}} 30
bichon_account_download_interval_minutes{{account_id="12"}} 60
bichon_account_download_interval_minutes{{account_id="13"}} 0
bichon_account_last_gapfill_downloaded{{account_id="11"}} 5
bichon_account_last_gapfill_failed{{account_id="11"}} 1
bichon_sync_errors_total{{account_id="11",kind="auth"}} 2
bichon_sync_errors_total{{account_id="11",kind="network"}} 0
bichon_sync_sessions_total{{account_id="11",status="success",trigger="scheduled"}} 40
bichon_sync_sessions_total{{account_id="11",status="partial",trigger="scheduled"}} {partial}
bichon_sync_session_duration_seconds_bucket{{account_id="11",le="+Inf"}} 40
bichon_backup_runs_total{{outcome="success"}} 3
bichon_backup_runs_total{{outcome="failed"}} {failed_backups}
bichon_backup_duration_seconds_sum 900
bichon_backup_duration_seconds_count {3 + failed_backups}
bichon_backup_last_success_timestamp_seconds {T - 3600}
"""


def test_url_needs_a_port():
    f = app_config.BY_KEY["bichon_url"]
    assert app_config._coerce(f, "http://192.168.1.10:15630") == "http://192.168.1.10:15630"
    assert app_config._coerce(f, "https://mail.example.com:443/bichon") == "https://mail.example.com:443/bichon"
    with pytest.raises(SettingsError, match="15630"):
        app_config._coerce(f, "http://192.168.1.10")
    with pytest.raises(SettingsError, match="http://"):
        app_config._coerce(f, "192.168.1.10:15630")
    assert app_config._coerce(f, "") == ""
    assert "bichon_token" in app_config.SECRET_KEYS
    assert Settings(bichon_url="http://x:15630").bichon_enabled is False  # a token is needed too
    s = Settings(bichon_url="http://x:15630", bichon_token="t")
    assert s.bichon_enabled and s.backups_enabled


def test_parse_metrics():
    st = bichon.parse_metrics(metrics_text())
    assert st["version"] == "2.4.1" and st["totals"]["emails"] == 5200 and st["totals"]["storage_bytes"] == 7340032000
    assert st["totals"]["accounts"] == {"imap": 2, "nosync": 1, "view": 0}
    me = next(a for a in st["accounts"] if a["id"] == "11")
    assert me["name"] == 'Me "work"' and me["job"] == "me@example.com" and me["interval_min"] == 30 and me["enabled"]
    assert me["last_succeeded"] is True and me["last_duration"] == 10.25 and me["emails"] == 1200
    assert me["sync_errors"] == {"auth": 2} and me["gapfill_failed"] == 1
    assert next(a for a in st["accounts"] if a["id"] == "12")["enabled"] is False
    assert st["data_backup"]["seen"] and st["data_backup"]["success"] == 3
    assert st["sessions"]["11"] == {"success": 40, "partial": 0}
    with pytest.raises(bichon.BichonError, match="no Bichon metrics"):
        bichon.parse_metrics("<html>login</html>")


def test_jobs():
    st = bichon.parse_metrics(metrics_text())
    jobs = {j["job"]: j for j in bichon.jobs_of(st, Settings(bichon_backup_overdue_hours=26))}
    assert set(jobs) == {"me@example.com", "old@example.com", bichon.DATA_BACKUP_JOB}  # the nosync account syncs nothing
    me = jobs["me@example.com"]
    assert me["gap_s"] == 1800 and me["threshold_s"] == 1800 * 1.25 + 7200 and not me["disabled"]
    assert me["noun"] == "mail sync" and me["schedule"] == "every 30 min"
    assert jobs["old@example.com"]["disabled"] is True
    assert jobs[bichon.DATA_BACKUP_JOB]["threshold_s"] == 26 * 3600
    assert bichon.jobs_of(st, Settings())[-1]["disabled"] is True  # no overdue hours set: no overdue alert
    # two accounts with the same address get distinct jobs
    twice = metrics_text().replace('email="old@example.com"', 'email="me@example.com"')
    assert sorted(a["job"] for a in bichon.parse_metrics(twice)["accounts"]) == \
        ["import@local", "me@example.com (#11)", "me@example.com (#12)"]


def test_runs_from_bichon_history():
    acc = {"id": "11", "job": "me@example.com"}
    start = int(T * 1000) - 60_000
    ok = bichon.run_from_session(acc, {
        "start_time": start, "end_time": start + 30_000, "status": "Success", "trigger": "Scheduled",
        "folder_details": {"INBOX": {"folder_name": "INBOX", "planned": 12, "current": 12, "filtered": 2, "status": "Success"},
                           "Sent": {"folder_name": "Sent", "planned": 3, "current": 3, "filtered": 0, "status": "Success"}},
        "errors": []})
    assert ok["status"] == "success" and ok["ext_id"] == f"11:{start}" and ok["duration_s"] == 30
    assert ok["files_new"] == 13 and ok["files_total"] == 15 and ok["data"]["trigger"] == "scheduled"
    partial = bichon.run_from_session(acc, {
        "startTime": start, "endTime": start + 5_000, "status": "Partial",
        "folderDetails": {"Junk": {"folderName": "Junk", "planned": 4, "current": 0, "status": "Failed",
                                   "message": "NO [UNAVAILABLE] try later"}}})
    assert partial["status"] == "warning" and partial["data"]["failed_folders"] == 1
    assert partial["message"].startswith("Junk: NO [UNAVAILABLE]") and partial["data"]["errors"][0]["item"] == "Junk"
    failed = bichon.run_from_session(acc, {"start_time": start, "status": "Failed", "message": "authentication failed",
                                           "errors": [{"error": "LOGIN rejected", "at": start}]})
    assert failed["status"] == "error" and failed["message"] == "authentication failed" and failed["ended"] is None
    running = bichon.run_from_session(acc, {"start_time": start, "status": "Running", "current_folder": "INBOX",
                                            "folder_details": {"a": {"folder_name": "INBOX", "planned": 10, "current": 5}}})
    assert running["status"] == "running" and running["data"]["progress"]["percent"] == 0.5
    assert bichon.run_from_session(acc, {"status": "Success"}) is None


def test_runs_from_metrics_alone():
    st = bichon.parse_metrics(metrics_text())
    me = next(a for a in st["accounts"] if a["id"] == "11")
    me["_sessions"] = st["sessions"]["11"]
    r = bichon.run_from_metrics(me, None)
    assert r["status"] == "success" and r["ext_id"] == f"11:{int((T - 600) * 1000)}" and r["duration_s"] == 10.25
    assert r["ended"] == r["started"] + timedelta(seconds=10.25)
    # the same sync read from Bichon's history has the same id: no double rows when the token changes
    assert r["ext_id"] == bichon.run_from_session(me, {"start_time": int((T - 600) * 1000), "status": "Success"})["ext_id"]
    # not success: partial when the partial counter went up since the last poll, else failed
    st2 = bichon.parse_metrics(metrics_text(start=T - 60, succeeded=0, partial=1))
    me2 = next(a for a in st2["accounts"] if a["id"] == "11")
    me2["_sessions"] = st2["sessions"]["11"]
    assert bichon.run_from_metrics(me2, st["sessions"]["11"])["status"] == "warning"
    bad = bichon.run_from_metrics(me2, st2["sessions"]["11"])
    assert bad["status"] == "error" and "3 errors" in bad["message"] and bad["data"]["error_count"] == 3
    run = next(a for a in bichon.parse_metrics(metrics_text(start=T - 5, running=1))["accounts"] if a["id"] == "11")
    assert bichon.run_from_metrics(run, None)["status"] == "running"
    never = next(a for a in st["accounts"] if a["id"] == "12")
    assert bichon.run_from_metrics(never, None) is None


def test_data_backup_and_stats():
    before = bichon.parse_metrics(metrics_text())["data_backup"]
    after = bichon.parse_metrics(metrics_text(failed_backups=1))["data_backup"]
    assert [r["status"] for r in bichon.data_backup_runs(before, None, NOW)] == ["success"]
    runs = bichon.data_backup_runs(after, before, NOW)
    assert [r["status"] for r in runs] == ["success", "error"] and runs[1]["started"] == NOW
    st = bichon.parse_metrics(metrics_text())
    s = bichon.stats_run(st, NOW + timedelta(minutes=17))
    assert s["kind"] == "stats" and s["ext_id"] == "stats:2026111312" and s["started"] == NOW
    assert s["data"]["stats"]["index_size"] == 524288000 and s["data"]["accounts"]["me@example.com"] == 1200


DSN = os.environ.get("TEST_DATABASE_URL")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_poller_end_to_end():
    """Metrics-only token: the history call is refused, runs come from the metrics; a failed sync alerts and closes
    again; Bichon's history replaces the metrics runs without doubles once the token may read it."""
    from lookingglass import alert_filters, db

    page = {"text": metrics_text(start=time_now() - 600), "history": None}

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.headers["authorization"] == "Bearer tok"
        if req.url.path.endswith("/api/v1/metrics"):
            return httpx.Response(200, text=page["text"])
        if req.url.path.endswith("/download-stats"):
            if page["history"] is None:
                return httpx.Response(403, json={"message": "Missing permission: account:read_details"})
            return httpx.Response(200, json={"account_id": 11, "history": page["history"], "active_session": None})
        return httpx.Response(404)

    settings = Settings(bichon_url="http://bichon:15630", bichon_token="tok")

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, alert_filters, backup_runs, backup_runs_removed")
            await pool.execute("DELETE FROM snapshots WHERE key LIKE 'backup_jobs:%' OR key LIKE 'bichon:%'")
            alert_filters.invalidate()
            p = bichon.BichonPoller(settings)
            await p.client.close()
            p.client.http = httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                              headers={"Authorization": "Bearer tok"})
            await p.poll()
            assert p.status["history"] == "metrics"
            rows = await pool.fetch("SELECT job, kind, status FROM backup_runs WHERE source = 'bichon' ORDER BY kind, job")
            assert [(r["job"], r["kind"], r["status"]) for r in rows] == [
                (bichon.DATA_BACKUP_JOB, "backup", "success"), ("me@example.com", "backup", "success"), ("", "stats", "success")]
            # the next sync fails
            page["text"] = metrics_text(start=time_now() - 60, succeeded=0)
            await p.poll()
            a = await pool.fetchrow("SELECT rule, status, title FROM alerts")
            assert (a["rule"], a["status"]) == ("backup_failed", "open") and a["title"] == "Bichon mail sync 'me@example.com' failed"
            # the token may now read the history: the same syncs, from Bichon, with folder details
            p.history_ok = None
            s1, s2 = int((time_now() - 600) * 1000), int((time_now() - 60) * 1000)
            page["history"] = [{"start_time": s1, "end_time": s1 + 10_250, "status": "Success", "trigger": "Scheduled"},
                               {"start_time": s2, "end_time": s2 + 4_000, "status": "Partial", "trigger": "Scheduled",
                                "folder_details": {"Junk": {"folder_name": "Junk", "planned": 4, "current": 0,
                                                            "status": "Failed", "message": "timeout"}}}]
            await p.poll()
            assert p.status["history"] == "bichon"
            runs = await pool.fetch("SELECT status, data FROM backup_runs WHERE job = 'me@example.com' ORDER BY started")
            assert [r["status"] for r in runs] == ["success", "warning"] and runs[1]["data"]["failed_folders"] == 1
            alerts = {r["rule"]: r["status"] for r in await pool.fetch("SELECT rule, status FROM alerts")}
            assert alerts == {"backup_failed": "closed", "backup_warning": "open"}
            ov = await backups.overview(30)
            assert {s["source"] for s in ov["sources"]} == {"backrest", "bichon"}
            me = next(j for j in ov["jobs"] if j["job"] == "me@example.com")
            assert me["source_label"] == "Bichon" and me["state"] == "warning"
            # unreachable: an alert after the grace time, closed when it answers again
            await p.down("boom", now=1000.0)
            p.failures = 2
            await p.down("boom", now=1000.0 + 16 * 60)
            assert await pool.fetchval("SELECT status FROM alerts WHERE rule = 'backup_source_unreachable'") == "open"
            await p.back()
            assert await pool.fetchval("SELECT status FROM alerts WHERE rule = 'backup_source_unreachable'") == "closed"
            await p.stop()
        finally:
            await db.close()

    asyncio.run(main())


def time_now() -> float:
    import time
    return float(int(time.time()))


def test_test_connection_reports_the_token_kind():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/metrics"):
            return httpx.Response(200, text=metrics_text())
        return httpx.Response(403, json={"message": "Missing permission"})

    real = httpx.AsyncClient

    def fake(*a, **kw):
        kw.pop("verify", None)
        return real(*a, transport=httpx.MockTransport(handler), **kw)

    httpx.AsyncClient = fake
    try:
        r = asyncio.run(bichon.test_connection(Settings(bichon_url="http://b:15630", bichon_token="t")))
    finally:
        httpx.AsyncClient = real
    assert r["ok"] and r["version"] == "2.4.1" and r["syncing"] == 2 and r["history"] is False and r["data_backup"]
