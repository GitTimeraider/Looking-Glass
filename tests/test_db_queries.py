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
