import asyncio
import os
from types import SimpleNamespace

import pytest

from lookingglass import auth, db
from lookingglass.config import Settings

DSN = os.environ.get("TEST_DATABASE_URL")


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_delete_only_backups():
    """Settings › Delete collected data: 'Backups' empties the run history and nothing else."""
    from lookingglass.web.app import create_app

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, event_rollup, backup_runs, backup_runs_removed")
            await pool.execute("INSERT INTO events (ts, source, message) VALUES (now(), 'firewall', 'x')")
            await pool.execute("INSERT INTO backup_runs (source, ext_id, kind, status) VALUES ('backrest', '1', 'backup', 'success')")
            await pool.execute("INSERT INTO backup_runs_removed (source, ext_id) VALUES ('backrest', '2')")
            await db.set_snapshot("backup_jobs:backrest", {"jobs": []})
            app = create_app(Settings(), None)
            ep = lambda path: next(r.endpoint for r in app.routes if getattr(r, "path", "") == path)  # noqa: E731
            sizes = {r["key"]: r for r in await ep("/api/admin/data")()}
            assert sizes["backups"]["rows"] == 1
            req = SimpleNamespace(state=SimpleNamespace(user={"username": "t", "password_hash": auth.hash_password("pw")}))
            await ep("/api/admin/purge")(req, {"parts": ["backups"], "password": "pw", "confirm": "DELETE"})
            assert await pool.fetchval("SELECT count(*) FROM backup_runs") == 0
            assert await pool.fetchval("SELECT count(*) FROM backup_runs_removed") == 0
            assert await db.get_snapshot("backup_jobs:backrest") is None
            assert await pool.fetchval("SELECT count(*) FROM events") == 1  # untouched
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_delete_only_wan_history():
    """'WAN quality' empties the gateway samples and day values; the other metrics stay."""
    from lookingglass.web.app import create_app

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE metrics, wan_daily")
            await pool.execute("INSERT INTO metrics (name, labels, value) VALUES ('gateway_up', 'WAN_DHCP6', 0), "
                               "('gateway_delay_ms', 'WAN', 9), ('cpu_used_pct', '', 12)")
            await pool.execute("INSERT INTO wan_daily (gateway, day, samples, down_samples) VALUES ('WAN_DHCP6', current_date, 80, 80)")
            app = create_app(Settings(), None)
            ep = lambda path: next(r.endpoint for r in app.routes if getattr(r, "path", "") == path)  # noqa: E731
            sizes = {r["key"]: r for r in await ep("/api/admin/data")()}
            assert sizes["wan"]["rows"] == 3
            req = SimpleNamespace(state=SimpleNamespace(user={"username": "t", "password_hash": auth.hash_password("pw")}))
            await ep("/api/admin/purge")(req, {"parts": ["wan"], "password": "pw", "confirm": "DELETE"})
            assert await pool.fetchval("SELECT count(*) FROM wan_daily") == 0
            assert await pool.fetchval("SELECT array_agg(name) FROM metrics") == ["cpu_used_pct"]
            await pool.execute("TRUNCATE metrics")
        finally:
            await db.close()

    asyncio.run(main())
