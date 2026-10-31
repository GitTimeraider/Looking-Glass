import asyncio
import os

import pytest

from lookingglass import alert_filters, db
from lookingglass.config import Settings

DSN = os.environ.get("TEST_DATABASE_URL")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_alert_list_survives_odd_stored_alerts():
    """One alert with unexpected stored data or an unknown severity must not fail the whole list (HTTP 500)."""
    from lookingglass.web.app import create_app

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, alert_filters")
            await pool.execute("INSERT INTO alert_filters (name, enabled, max_severity, action) VALUES ('m', true, 'low', 'close')")
            alert_filters.invalidate()
            odd = [[1, 2], "text", {"device": "abc"}, {"severity_override": "x"},
                   {"severity_override": {"from": "low", "filter": "x"}}, None]
            for i, data in enumerate(odd):
                await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint, status, data) VALUES "
                                   "('r', 'low', 't', $1, 'closed', $2)", f"f{i}", data)
            await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint, status) VALUES ('r', 'warning', 't', 'w', 'closed')")
            ep = next(r.endpoint for r in create_app(Settings(), None).routes if getattr(r, "path", "") == "/api/alerts")
            for status in ("closed", "all"):
                out = await ep(status=status, hours=720, limit=500)
                assert len(out) == len(odd) + 1
            assert sum(1 for a in out if a["muted_by"]) == len(odd) + 1  # 'warning' is compared as info
            await pool.execute("TRUNCATE alerts, alert_filters")
            alert_filters.invalidate()
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_alert_list_sort_orders():
    """?sort= orders the list by priority (default), alert number (both ways) or latest activity; unknown = priority."""
    from lookingglass.web.app import create_app

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, alert_filters")
            alert_filters.invalidate()
            # id order: low (seen last), critical, medium (seen first)
            for fp, sev, ago in (("a", "low", 1), ("b", "critical", 5), ("c", "medium", 10)):
                await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint, status, last_seen) VALUES "
                                   "('r', $1, 't', $2, 'open', now() - make_interval(mins => $3))", sev, fp, ago)
            ep = next(r.endpoint for r in create_app(Settings(), None).routes if getattr(r, "path", "") == "/api/alerts")
            sevs = lambda out: [a["severity"] for a in out]  # noqa: E731
            assert sevs(await ep(status="open", hours=720, limit=500)) == ["critical", "medium", "low"]
            assert sevs(await ep(status="open", hours=720, limit=500, sort="bogus")) == ["critical", "medium", "low"]
            assert sevs(await ep(status="open", hours=720, limit=500, sort="number")) == ["medium", "critical", "low"]
            assert sevs(await ep(status="open", hours=720, limit=500, sort="number_asc")) == ["low", "critical", "medium"]
            assert sevs(await ep(status="open", hours=720, limit=500, sort="recent")) == ["low", "critical", "medium"]
            await pool.execute("TRUNCATE alerts, alert_filters")
        finally:
            await db.close()

    asyncio.run(main())
