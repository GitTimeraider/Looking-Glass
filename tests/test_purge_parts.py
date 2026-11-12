import asyncio
import os
from types import SimpleNamespace

import pytest

from lookingglass import auth, db
from lookingglass.config import Settings

DSN = os.environ.get("TEST_DATABASE_URL")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_delete_only_zenarmor_or_only_backups():
    """Settings › Delete collected data: 'Zenarmor data only' leaves the events of other sources, 'Backups' empties
    the run history and nothing else."""
    from lookingglass.web.app import create_app

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, event_rollup, backup_runs, backup_runs_removed")
            for src in ("zenarmor", "zenarmor", "zenarmor", "firewall"):
                await pool.execute("INSERT INTO events (ts, source, message) VALUES (now(), $1, 'x')", src)
            await pool.execute("INSERT INTO backup_runs (source, ext_id, kind, status) VALUES ('backrest', '1', 'backup', 'success')")
            await pool.execute("INSERT INTO backup_runs_removed (source, ext_id) VALUES ('backrest', '2')")
            await db.set_snapshot("backup_jobs:backrest", {"jobs": []})
            app = create_app(Settings(), None)
            ep = lambda path: next(r.endpoint for r in app.routes if getattr(r, "path", "") == path)  # noqa: E731
            sizes = {r["key"]: r for r in await ep("/api/admin/data")()}
            assert sizes["zenarmor"]["rows"] == 3 and sizes["backups"]["rows"] == 1
            req = SimpleNamespace(state=SimpleNamespace(user={"username": "t", "password_hash": auth.hash_password("pw")}))
            out = await ep("/api/admin/purge")(req, {"parts": ["zenarmor"], "password": "pw", "confirm": "DELETE"})
            assert out["background"] == "zenarmor"
            await asyncio.gather(*app.state.purge_tasks)
            assert [r["source"] for r in await pool.fetch("SELECT source FROM events")] == ["firewall"]
            assert await pool.fetchval("SELECT count(*) FROM backup_runs") == 1  # untouched
            await ep("/api/admin/purge")(req, {"parts": ["backups"], "password": "pw", "confirm": "DELETE"})
            assert await pool.fetchval("SELECT count(*) FROM backup_runs") == 0
            assert await pool.fetchval("SELECT count(*) FROM backup_runs_removed") == 0
            assert await db.get_snapshot("backup_jobs:backrest") is None
            assert await pool.fetchval("SELECT count(*) FROM events") == 1  # untouched
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_zenarmor_share_of_a_large_table_is_estimated():
    """Delete collected data: with many events the Zenarmor row count comes from the statistics (no slow count)."""
    from lookingglass.web.app import create_app

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events")
            await pool.execute("INSERT INTO events (ts, source, message) SELECT now(), "
                               "CASE WHEN i % 4 = 0 THEN 'zenarmor' ELSE 'firewall' END, 'x' FROM generate_series(1, 120000) i")
            await pool.execute("ANALYZE events")
            ep = next(r.endpoint for r in create_app(Settings(), None).routes if getattr(r, "path", "") == "/api/admin/data")
            zen = next(r for r in await ep() if r["key"] == "zenarmor")
            assert 27000 <= zen["rows"] <= 33000 and zen["size"]  # about a quarter of 120 000
            await pool.execute("TRUNCATE events")
        finally:
            await db.close()

    asyncio.run(main())
