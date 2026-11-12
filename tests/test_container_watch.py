import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest

from lookingglass import db
from lookingglass.config import Settings
from lookingglass.container_watch import (LogRule, RestartTracker, clean_rule, docker_age, health, parse_status,
                                         rules_for)

DSN = os.environ.get("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")


def test_docker_status_texts():
    assert docker_age("Less than a second") == (0.5, 1.0)
    assert docker_age("5 seconds") == (5.0, 2.0)
    assert docker_age("About a minute") == (90.0, 30.0)
    assert docker_age("3 minutes") == (210.0, 30.0)
    assert docker_age("About an hour") == (3600.0, 1800.0)
    assert docker_age("2 days") == (2 * 86400 + 43200, 43200)
    assert docker_age("nonsense") is None
    assert parse_status("Up 5 seconds (healthy)") == ("up", 5.0, 2.0)
    assert parse_status("Up 3 hours (Paused)") == ("up", 3 * 3600.0, 1800.0)
    assert parse_status("Restarting (1) 10 seconds ago") == ("restarting", 10.0, 2.0)
    assert parse_status("Exited (137) 2 minutes ago")[0] == "exited"
    assert parse_status("Created") is None and parse_status("") is None


def test_health_from_status():
    assert health("Up 3 hours (unhealthy)") == "unhealthy" and health("Up 2 minutes (healthy)") == "healthy"
    assert health("Up 5 seconds (health: starting)") == "starting" and health("Up 3 days") is None


def test_restart_tracker_counts_a_crash_loop_but_not_a_steady_container():
    t, loop, steady = 1_000_000.0, RestartTracker(), RestartTracker()
    # polls every 60 s; a container that crashes ~10 s after every start and is restarted ~every 65 s
    for i in range(15):
        now = t + i * 60
        since_start = (now - t) % 65
        status = f"Up {int(since_start)} seconds" if since_start < 10 else f"Restarting (1) {int(since_start - 10)} seconds ago"
        loop.observe("app", status, now)
        # a healthy container read again and again, its age getting coarser (seconds -> minutes)
        age = 50 + i * 60
        steady.observe("db", f"Up {age} seconds" if age < 60 else ("About a minute" if age < 120 else f"Up {age // 60} minutes"), now)
    assert loop.count("app", t) >= 5
    assert steady.count("db", t - 3600) == 1
    # one restart after a long run is one new start
    steady.observe("db", "Up 4 seconds", t + 20 * 60)
    assert steady.count("db", t + 15 * 60) == 1


def test_log_rule_validation_and_choice():
    r = clean_rule({"name": "Nextcloud", "containers": "nextcloud*, mariadb\nredis", "match": "PHP Fatal\n/error \\d+/",
                    "ignore": "", "threshold": "3", "minutes": "5", "severity": "high"})
    assert r["containers"] == ["nextcloud*", "mariadb", "redis"] and r["match"] == ["PHP Fatal", "/error \\d+/"]
    assert r["threshold"] == 3 and r["server_id"] is None
    for bad in ({"name": ""}, {"name": "x", "match": "/(/"}, {"name": "x", "threshold": -1}, {"name": "x", "minutes": 0},
                {"name": "x", "severity": "huge"}):
        with pytest.raises(ValueError):
            clean_rule(bad)
    default = LogRule(None, "default")
    nc = LogRule(1, "nc", containers=["nextcloud*"])
    other_server = LogRule(2, "s2", containers=["plex"], server_id=2)
    assert rules_for("Nextcloud-AIO", 1, [nc, other_server], default) == [nc]
    assert rules_for("plex", 1, [nc, other_server], default) == [default]
    assert rules_for("plex", 2, [nc, other_server], default) == [other_server]


@needs_db
def test_restart_alert_opens_and_closes():
    from lookingglass.unraid import UnraidServerPoller

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts")
            p = UnraidServerPoller({"id": 1, "name": "Tower", "url": "http://tower", "api_key": "k", "verify_ssl": False},
                                   Settings(unraid_restart_count=5, unraid_restart_minutes=15), None)
            t = 1_000_000.0
            # two restarts (an update): quiet
            for i, status in enumerate(["Up 2 seconds", "Up 3 seconds", "Up About a minute"]):
                await p.check_restarts([{"names": ["/app"], "state": "RUNNING", "status": status}], now=t + i * 60)
            assert await pool.fetchval("SELECT count(*) FROM alerts") == 0
            # restarts every minute
            for i in range(3, 10):
                await p.check_restarts([{"names": ["/app"], "state": "RUNNING", "status": "Up 3 seconds"}], now=t + i * 60)
            row = await pool.fetchrow("SELECT status, title, data FROM alerts WHERE rule = 'unraid_container_restarting'")
            assert row["status"] == "open" and "keeps restarting" in row["title"] and row["data"]["events"]["program"] == "app"
            # stays up for 30 minutes: closed
            for i in range(10, 45):
                await p.check_restarts([{"names": ["/app"], "state": "RUNNING",
                                         "status": f"Up {(i - 9)} minutes" if i > 10 else "Up 50 seconds"}], now=t + i * 60)
            assert await pool.fetchval("SELECT status FROM alerts") == "closed"
            snap = await db.get_snapshot("unraid:1:restarts")
            assert snap["app"]["last_hour"] >= 5
        finally:
            await db.close()

    asyncio.run(main())


@needs_db
def test_log_rules_alert_override_and_close():
    from lookingglass.unraid import UnraidServerPoller
    from lookingglass.web.app import create_app

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, events, container_log_rules")
            await db.set_snapshot("unraid:1:docker", [{"names": ["/plex"]}, {"names": ["/nextcloud"]}, {"names": ["/chatty"]}])
            now = datetime.now(timezone.utc)
            rows = []
            for i in range(60):  # 60 error lines each in the last 10 minutes
                ts = now - timedelta(seconds=i * 9)
                rows += [(ts, "plex", 3, f"ERROR: transcoder failed {i}"), (ts, "chatty", 3, f"0 errors found {i}")]
            rows += [(now - timedelta(minutes=1), "nextcloud", 6, "PHP Fatal error: Allowed memory size exhausted"),
                     (now - timedelta(minutes=2), "nextcloud", 6, "PHP Fatal error: Uncaught Exception")]
            await pool.executemany(
                "INSERT INTO events (ts, source, host, program, severity, action, message) "
                "VALUES ($1, 'docker', 'Tower', $2, $3, 'container_log', $4)", rows)
            routes = {(getattr(r, "path", ""), next(iter(getattr(r, "methods", None) or {""}))): r.endpoint
                      for r in create_app(Settings(), None).routes if hasattr(r, "endpoint")}
            add = routes[("/api/unraid/log-rules", "POST")]
            # nextcloud: two PHP fatals are already too many; chatty: its "errors" are noise -> 0 = no log alerts
            await add(payload={"name": "Nextcloud fatals", "containers": "next*", "match": "PHP Fatal", "threshold": 2,
                               "minutes": 10, "severity": "high"})
            await add(payload={"name": "Chatty is fine", "containers": "chatty", "threshold": 0})
            preview = await routes[("/api/unraid/log-rules/test", "POST")](
                payload={"containers": "chatty", "match": "/\\berrors\\b/", "threshold": 50, "minutes": 10})
            assert [(r["program"], r["total"]) for r in preview["rows"]] == [("chatty", 60)]
            p = UnraidServerPoller({"id": 1, "name": "Tower", "url": "http://tower", "api_key": "k", "verify_ssl": False},
                                   Settings(unraid_log_error_count=50, unraid_log_error_minutes=10), None)
            await p.check_logs()
            got = {r["data"]["container"]: r for r in await pool.fetch(
                "SELECT severity, title, data, description FROM alerts WHERE rule = 'unraid_container_errors'")}
            assert set(got) == {"plex", "nextcloud"}
            assert got["nextcloud"]["severity"] == "high" and "Nextcloud fatals" in got["nextcloud"]["description"]
            assert got["plex"]["severity"] == "low" and "transcoder failed" in got["plex"]["description"]
            with pytest.raises(Exception):
                await add(payload={"name": "bad", "match": "/(/"})
            # the errors stop (older than 3 windows): the alerts close
            await pool.execute("UPDATE events SET ts = ts - interval '2 hours'")
            await p.check_logs()
            assert await pool.fetchval("SELECT count(*) FROM alerts WHERE status <> 'closed'") == 0
            await pool.execute("TRUNCATE alerts, events, container_log_rules")
        finally:
            await db.close()

    asyncio.run(main())


@needs_db
def test_unhealthy_alert_waits_and_closes():
    from lookingglass.unraid import UnraidServerPoller

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts")
            p = UnraidServerPoller({"id": 1, "name": "Tower", "url": "http://tower", "api_key": "k", "verify_ssl": False},
                                   Settings(unraid_unhealthy_minutes=5), None)
            sick = [{"names": ["/web"], "state": "RUNNING", "status": "Up 2 hours (unhealthy)"},
                    {"names": ["/db"], "state": "RUNNING", "status": "Up 2 hours (healthy)"}]
            t = 1_000_000.0
            await p.check_health(sick, now=t)
            await p.check_health(sick, now=t + 240)  # unhealthy for 4 minutes: not yet
            assert await pool.fetchval("SELECT count(*) FROM alerts") == 0
            await p.check_health(sick, now=t + 301)
            row = await pool.fetchrow("SELECT status, title, data FROM alerts")
            assert row["status"] == "open" and row["title"] == "Tower: container web is unhealthy"
            assert row["data"]["events"]["program"] == "web"
            ok = [{"names": ["/web"], "state": "RUNNING", "status": "Up 2 hours (healthy)"}]
            await p.check_health(ok, now=t + 400)
            row = await pool.fetchrow("SELECT status, description FROM alerts")
            assert row["status"] == "closed" and "no longer unhealthy" in row["description"]
            await p.check_health(sick, now=t + 500)  # unhealthy again: the wait starts over
            assert await pool.fetchval("SELECT status FROM alerts") == "closed"
            await pool.execute("TRUNCATE alerts")
        finally:
            await db.close()

    asyncio.run(main())
