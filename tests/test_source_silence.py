"""'A source went quiet': a source that sends something nearly every hour, with nothing for source_silence_hours."""
import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest

from lookingglass import db, rollup
from lookingglass.config import Settings
from lookingglass.detections import DetectionEngine
from lookingglass.parsers.common import event

DSN = os.environ.get("TEST_DATABASE_URL")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_source_silence_alerts_and_closes():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()

            async def reset():
                await pool.execute("TRUNCATE events, alerts, event_rollup")
                await pool.execute("UPDATE event_rollup_state SET upto = 0, seen = 0")

            async def count():
                await rollup.step()
                await rollup.step()  # the first run only notes the newest id

            await reset()
            now = datetime.now(timezone.utc)
            evs = []
            for h in range(60):
                t = now - timedelta(hours=h, minutes=10)
                evs.append(event(t, "firewall", severity=6, action="block", message="fw"))  # every hour, up to now
                if h >= 5:
                    evs.append(event(t, "nginx", severity=6, action="http_200", message="GET /"))  # stopped 5 h ago
                if h % 6 == 0:
                    evs.append(event(t, "auth", severity=5, action="login_success", message="login"))  # never steady
                if h >= 5:
                    evs.append(event(t, "suricata", severity=4, action="alert", message="x"))  # quiet, but switched off
            await db.copy_events(evs)
            await count()

            eng = DetectionEngine(Settings(source_silence_hours=3, ids_pull=False))
            await eng.source_silence()
            rows = await pool.fetch("SELECT title, status, fingerprint FROM alerts WHERE rule = 'source_silence'")
            assert [(r["fingerprint"], r["status"]) for r in rows] == [("source_silence:nginx", "open")]
            assert "nginx" in rows[0]["title"] and "3+ hours" in rows[0]["title"]

            await eng.source_silence()  # not due again within 5 minutes
            eng._ran.clear()
            await eng.source_silence()  # still quiet: one alert
            assert await pool.fetchval("SELECT count(*) FROM alerts WHERE rule = 'source_silence'") == 1

            await db.copy_events([event(now, "nginx", severity=6, action="http_200", message="GET /")])
            eng._ran.clear()
            await eng.source_silence()
            assert await pool.fetchval("SELECT status FROM alerts WHERE rule = 'source_silence'") == "closed"

            eng.settings.source_silence_hours = 0  # off
            await pool.execute("TRUNCATE alerts")
            await pool.execute("DELETE FROM events WHERE source = 'nginx' AND ts > now() - interval '1 hour'")
            eng._ran.clear()
            await eng.source_silence()
            assert await pool.fetchval("SELECT count(*) FROM alerts") == 0
        finally:
            await reset()
            await db.close()

    asyncio.run(main())
