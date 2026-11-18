import asyncio
import os
import tarfile

import pytest

from lookingglass import audit, backup, crypto, db, db_config

DSN = os.environ.get("TEST_DATABASE_URL")


def test_audit_filter_and_labels():
    assert audit.wanted("PUT", "/api/settings") and audit.wanted("DELETE", "/api/blocks/3")
    assert not audit.wanted("GET", "/api/settings") and not audit.wanted("POST", "/login")
    assert not audit.wanted("PUT", "/api/layout/overview") and not audit.wanted("POST", "/api/alert-filters/preview")
    assert audit.label("PUT", "/api/settings") == "Settings changed"
    assert audit.label("DELETE", "/api/blocks/7") == "Block removed"
    assert audit.label("POST", "/api/snoozes") == "Snooze created"
    assert audit.label("POST", "/api/snoozes/4/end") == "Snooze ended"
    assert audit.label("POST", "/api/whatever") == "POST /api/whatever"


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_audit_middleware_records_changes_with_status():
    from lookingglass.web.app import AuthGuard

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE audit_log")

            async def check(request):
                request.state.user = {"username": "admin"}
                return None

            async def endpoint(scope, receive, send):
                scope["state"]["audit"] = {"changed": ["theme"]}
                await send({"type": "http.response.start", "status": 200, "headers": []})
                await send({"type": "http.response.body", "body": b"{}"})

            guard = AuthGuard(endpoint, check)
            sent = []

            async def receive():
                return {"type": "http.request", "body": b""}

            async def send(m):
                sent.append(m)
            for method, path in (("PUT", "/api/settings"), ("GET", "/api/settings"), ("PUT", "/api/layout/x")):
                await guard({"type": "http", "method": method, "path": path, "headers": [], "client": ("10.0.0.5", 1),
                             "query_string": b""}, receive, send)
            rows = await pool.fetch("SELECT * FROM audit_log")
            assert len(rows) == 1
            r = rows[0]
            assert (r["username"], r["ip"], r["action"], r["target"], r["status"]) == \
                ("admin", "10.0.0.5", "change", "PUT /api/settings", 200)
            assert r["detail"] == {"changed": ["theme"]}
            out = await audit.listing()
            assert out["rows"][0]["label"] == "Settings changed" and out["users"] == ["admin"]
            await pool.execute("TRUNCATE audit_log")
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_backup_and_restore_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "tmp_root", lambda: tmp_path)
    data = tmp_path / "data"
    data.mkdir()
    crypto.init(str(data))
    key_a = (data / "lookingglass.key").read_bytes()

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, alert_comments, events, kv, app_settings, snoozes")
            await pool.execute("INSERT INTO app_settings (key, value) VALUES ('opnsense_api_secret', $1)",
                               crypto.encrypt("s3cret"))
            aid = await pool.fetchval("INSERT INTO alerts (rule, severity, title, fingerprint, data) VALUES "
                                      "('r', 'high', 'quote \" and, comma\nnewline', 'f', '{\"x\": [1, null]}') RETURNING id")
            await pool.execute("INSERT INTO alert_comments (alert_id, body) VALUES ($1, 'note')", aid)
            await pool.execute("INSERT INTO events (ts, source, src_ip, message) VALUES (now(), 'firewall', '203.0.113.1', NULL)")
            await pool.execute("INSERT INTO kv (key, value) VALUES ('wm:port_scan', '999999')")
            progress: dict = {}
            full = await backup.create(str(data), "full", progress)
            light = await backup.create(str(data), "config")
            assert progress["step"] == "ready" and full.stat().st_mode & 0o777 == 0o600
            with tarfile.open(light) as tar:
                names = tar.getnames()
                assert "tables/alerts.csv" in names and "tables/events.csv" not in names and "lookingglass.key" in names
            # everything changes, and the key is replaced (a new machine)
            await pool.execute("TRUNCATE alerts, alert_comments, events, app_settings")
            await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint) VALUES ('new', 'low', 'n', 'n')")
            (data / "lookingglass.key").unlink()
            crypto.init(str(data))
            db_config.save(str(data), {"host": "h", "port": 5432, "database": "d", "user": "u", "password": "p", "ssl": "prefer"})
            res = await backup.restore(str(full), str(data), log_fn=lambda *_: None)
            assert "alerts" in res["tables"]
            assert (data / "lookingglass.key").read_bytes().strip() == key_a.strip()
            assert any(p.name.startswith("lookingglass.key.before-restore-") for p in data.iterdir())
            assert db_config.load(str(data))["password"] == "p"  # re-encrypted with the restored key
            assert crypto.decrypt(await pool.fetchval("SELECT value FROM app_settings")) == "s3cret"
            a = await pool.fetchrow("SELECT * FROM alerts")
            assert a["id"] == aid and a["title"] == 'quote " and, comma\nnewline' and a["data"] == {"x": [1, None]}
            assert await pool.fetchval("SELECT count(*) FROM alert_comments") == 1
            assert await pool.fetchval("SELECT count(*) FROM events") == 1
            assert await pool.fetchval("SELECT count(*) FROM kv WHERE key LIKE 'wm:%'") == 0
            nid = await pool.fetchval("INSERT INTO alerts (rule, severity, title, fingerprint) VALUES ('n', 'low', 'n', 'n') RETURNING id")
            assert nid == aid + 1  # the id sequence continues after the restored rows
            await pool.execute("TRUNCATE alerts, alert_comments, events, kv, app_settings")
        finally:
            await db.close()

    asyncio.run(main())
