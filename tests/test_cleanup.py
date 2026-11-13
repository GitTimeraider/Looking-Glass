"""One-time cleanup (cleanup.py): configd's routine lines out of the stored events, the hourly counts corrected."""
import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest

from lookingglass import cleanup, db, rollup

DSN = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")

GROUPED = ("SELECT {b} bucket, source, coalesce(action, '') action, coalesce(proto, '') proto, coalesce(interface, '') i, "
           "coalesce(direction, '') d, coalesce(dst_port, -1) p, coalesce(src_country, '') c, severity, count(*)::int n "
           "FROM events GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9").format(b=rollup._BUCKET)
ROLLUP = ("SELECT bucket, source, action, proto, interface i, direction d, dst_port p, src_country c, severity, n "
          "FROM event_rollup WHERE n <> 0")


def test_configd_noise_cleanup(monkeypatch):
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, event_rollup, hourly_stats")
            await pool.execute("UPDATE event_rollup_state SET upto = 0, seen = 0")
            await pool.execute("DELETE FROM kv WHERE key = $1", cleanup.DONE_KEY)
            now = datetime.now(timezone.utc).replace(minute=30, second=0, microsecond=0)
            ins = ("INSERT INTO events (ts, source, host, program, severity, action, src_ip, message) "
                   "VALUES ($1, $2, 'fw', $3, $4, $5, $6::inet, $7)")
            rows = []
            for h in (5, 3, 1):  # three hours
                ts = now - timedelta(hours=h)
                rows += [(ts, "auth", "configd.py", 5, None, None, f"[u{h}{i}] action allowed system.status for user root")
                         for i in range(4)]
                rows += [(ts, "auth", "configd.py", 6, None, None, "action allowed nginx.autoblock for user nobody"),
                         (ts, "auth", "configd.py", 5, "config_change", None, "[x] trigger config changed event"),
                         (ts, "auth", "configd.py", 3, None, None, "[x] action not allowed foo.bar for user www"),
                         (ts, "auth", "sshd", 5, "login_success", "192.168.1.10", "Accepted publickey for root"),
                         (ts, "auth", "audit", 5, "config_change", "192.168.1.10", "user changed configuration"),
                         (ts, "firewall", "filterlog", 6, "block", "203.0.113.5", "block")]
            await pool.executemany(ins, rows)
            await rollup.step()
            await rollup.step()  # counted (up to the newest id of the first run)
            assert await pool.fetchval("SELECT sum(n) FROM event_rollup") == len(rows)
            # arrived after the hourly counts ran: not counted yet, cleaned all the same
            await pool.executemany(ins, [(now - timedelta(hours=1), "auth", "configd.py", 5, None, None,
                                          "[late] action allowed qfeeds.index for user root")])
            # the hour-of-week baselines (behavior.py) as they were stored
            await pool.execute("INSERT INTO hourly_stats (metric, hour, value) SELECT 'source:' || source, "
                               "date_trunc('hour', ts), count(*) FROM events GROUP BY 1, 2")

            monkeypatch.setattr(cleanup, "BATCH", 4)  # several steps
            res = await cleanup.configd_noise(delay=0, pause=0)
            assert res == {"done": True, "deleted": 16, "moved": 6}
            assert await cleanup.configd_noise(delay=0, pause=0) is None  # once

            left = await pool.fetch("SELECT source, program, message FROM events ORDER BY id")
            assert not [r for r in left if "action allowed" in r["message"] and "not allowed" not in r["message"]]
            assert {r["source"] for r in left if r["program"] == "configd.py"} == {"system"}
            assert sum(1 for r in left if r["source"] == "auth") == 6  # sshd + audit, 3 hours
            assert await pool.fetchval("SELECT count(*) FROM events WHERE action = 'config_change'") == 6

            # the hourly counts match a recount of the raw events
            await rollup.step()
            await rollup.step()
            key = lambda r: tuple(r.values())  # noqa: E731
            assert sorted(map(key, db.records(await pool.fetch(ROLLUP)))) == \
                sorted(map(key, db.records(await pool.fetch(GROUPED))))
            assert await pool.fetchval("SELECT count(*) FROM event_rollup WHERE n <= 0") == 0
            stats = {(r["metric"], r["hour"]): r["value"] for r in await pool.fetch("SELECT * FROM hourly_stats")}
            raw = {("source:" + r["source"], r["hour"]): float(r["n"]) for r in await pool.fetch(
                "SELECT source, date_trunc('hour', ts) AS hour, count(*) n FROM events GROUP BY 1, 2")}
            assert {k: v for k, v in stats.items() if v} == raw
        finally:
            await pool.execute("TRUNCATE events, event_rollup, hourly_stats")
            await pool.execute("UPDATE event_rollup_state SET upto = 0, seen = 0")
            await pool.execute("DELETE FROM kv WHERE key = $1", cleanup.DONE_KEY)
            await db.close()

    asyncio.run(main())
