"""Integration test: every dashboard panel / report query must run on a real PostgreSQL.

Runs only when TEST_DATABASE_URL is set (CI provides a postgres service).
"""
import asyncio
import os

import pytest

from lookingglass import db
from lookingglass.dashboards import DASHBOARDS, run_dashboard
from lookingglass.reports import build_report, timeline

DSN = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")


def test_all_queries():
    async def main():
        await db.connect(DSN)
        try:
            for name in DASHBOARDS:
                for hours in (1, 168):
                    res = await run_dashboard(name, hours)
                    errors = [(p["id"], p["error"]) for p in res["panels"] if p.get("error")]
                    assert not errors, f"{name}: {errors}"
            rep = await build_report(24)
            assert "totals_by_source" in rep
            await timeline(24)
        finally:
            await db.close()
    asyncio.run(main())


def test_add_metrics_skips_bad_rows_instead_of_failing():
    async def main():
        await db.connect(DSN)
        try:
            await db.pool().execute("DELETE FROM metrics WHERE name LIKE 'test_%'")
            await db.add_metrics([("test_m", None, 1.0), ("test_m", "ok", float("nan")), ("test_m", "x", None), ("test_m", "y", 2)])
            rows = await db.pool().fetch("SELECT labels, value FROM metrics WHERE name = 'test_m' ORDER BY value")
            assert [(r["labels"], r["value"]) for r in rows] == [("", 1.0), ("y", 2.0)]
        finally:
            await db.close()
    asyncio.run(main())
