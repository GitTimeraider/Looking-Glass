"""Web attacks / scanners from the internet alert only when something got through (Settings › Data & detection)."""
import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest

from lookingglass import db
from lookingglass.config import Settings
from lookingglass.detections import DetectionEngine
from lookingglass.parsers.common import event

from test_behavior_intel import reset

DSN = os.environ.get("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
NOW = datetime.now(timezone.utc)
BLOCKED, LUCKY, INSIDE = "198.51.100.10", "198.51.100.20", "192.168.1.50"


def req(ip, path, status, tags, i=0):
    return event(NOW - timedelta(seconds=i), "nginx", severity=4, action=f"http_{status}", src_ip=ip,
                 message=f"GET {path} {status}", data={"path": path, "status": status, "tags": tags})


def traffic():
    ev = []
    for ip in (BLOCKED, LUCKY, INSIDE):
        ev += [req(ip, f"/probe{i}", 404, [], i) for i in range(60)]          # directory brute force
        ev += [req(ip, "/.env", 403, ["sensitive_file"]), req(ip, "/?id=1 union select 1", 403, ["sqli"]),
               req(ip, "/", 200, ["scanner_ua"])]                             # a visit with a scanner user agent
    ev.append(req(LUCKY, "/.git/config", 200, ["sensitive_file"]))           # this one found something
    return ev


def run(settings, check):
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await reset(pool)
            await db.copy_events(traffic())
            eng = DetectionEngine(settings)
            await eng.web_attacks()
            await eng.web_scanner()
            rows = await pool.fetch("SELECT rule, host(src_ip) ip, title, severity FROM alerts ORDER BY id")
            check({(r["rule"], r["ip"], r["title"].split("(")[1].split(")")[0] if r["rule"] == "web_attack" else "")
                   for r in rows}, rows)
            await reset(pool)
        finally:
            await db.close()
    asyncio.run(main())


@needs_db
def test_blocked_internet_scanners_raise_nothing_by_default():
    def check(got, rows):
        assert not any(ip == BLOCKED for _, ip, _ in got)
        assert ("web_attack", LUCKY, "sensitive_file") in got and ("web_scanner", LUCKY, "") in got
        assert ("web_attack", LUCKY, "scanner_ua") not in got and ("web_attack", LUCKY, "sqli") not in got
        assert {("web_attack", INSIDE, "sensitive_file"), ("web_attack", INSIDE, "sqli"), ("web_scanner", INSIDE, "")} <= got
    run(Settings(), check)


@needs_db
def test_threshold_attacks_and_all_modes():
    def two_needed(got, rows):  # LUCKY found only one path: not enough for 2
        assert not any(ip == LUCKY for _, ip, _ in got)

    def attacks(got, rows):  # failed SQL injection alerts too, a blocked scan / file probe still does not
        assert ("web_attack", BLOCKED, "sqli") in got
        assert ("web_scanner", BLOCKED, "") not in got and ("web_attack", BLOCKED, "sensitive_file") not in got

    def everything(got, rows):  # as before
        assert {("web_attack", BLOCKED, "sqli"), ("web_scanner", BLOCKED, ""), ("web_attack", BLOCKED, "sensitive_file")} <= got

    run(Settings(web_through_min=2), two_needed)
    run(Settings(web_internet_alerts="attacks"), attacks)
    run(Settings(web_internet_alerts="all"), everything)
