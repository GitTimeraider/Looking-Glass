import os

import pytest

DSN = os.environ.get("TEST_DATABASE_URL")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_service_alerts_wait_for_the_grace_time_and_close_by_themselves():
    """A service that is stopped for a moment (restart, quick stop / start) stays quiet; one that stays stopped is
    alerted once the grace time has passed, and the alert closes when the service runs again."""
    import asyncio

    from lookingglass import alert_filters, db
    from lookingglass.config import Settings
    from lookingglass.detections import DetectionEngine

    def nginx(running, locked="0"):
        return [{"name": "nginx", "description": "Nginx web server", "running": running, "locked": locked},
                {"name": "unbound", "description": "Unbound DNS", "running": 1}]

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, alert_filters")
            alert_filters.invalidate()
            alerts = lambda: pool.fetch("SELECT rule, status, close_reason, description FROM alerts ORDER BY id")  # noqa: E731
            d = DetectionEngine(Settings(service_down_grace=5))
            t = 1_000_000.0
            # stopped for a moment: no alert
            await d.check_services(nginx(0), now=t)
            await d.check_services(nginx(1), now=t + 60)
            assert await alerts() == []
            # stopped for 5 minutes: one alert, saying how long
            await d.check_services(nginx(0), now=t + 1000)
            await d.check_services(nginx(0), now=t + 1299)
            assert await alerts() == []
            await d.check_services(nginx(0), now=t + 1300)
            await d.check_services(nginx(0), now=t + 1360)
            rows = await alerts()
            assert len(rows) == 1 and rows[0]["status"] == "open" and "Stopped for 6 minutes" in rows[0]["description"]
            # running again: closed by itself
            await d.check_services(nginx(1), now=t + 1400)
            row = (await alerts())[0]
            assert row["status"] == "closed" and row["close_reason"] == "resolved" and "running again" in row["description"]
            # a locked (intentionally disabled) service is never alerted
            await pool.execute("TRUNCATE alerts")
            await d.check_services(nginx(0, locked="1"), now=t + 2000)
            await d.check_services(nginx(0, locked="1"), now=t + 3000)
            assert await alerts() == []
            # 0 = right away
            d = DetectionEngine(Settings(service_down_grace=0))
            await d.check_services(nginx(0), now=t)
            assert [r["status"] for r in await alerts()] == ["open"]
            await pool.execute("TRUNCATE alerts")
        finally:
            await db.close()

    asyncio.run(main())
