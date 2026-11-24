import asyncio
import os
from types import SimpleNamespace

import httpx
import pytest

from lookingglass import db
from lookingglass.config import Settings
from lookingglass.opnsense import ApiError, OPNsenseClient

DSN = os.environ.get("TEST_DATABASE_URL")
SETTINGS = dict(opnsense_url="https://fw.test", opnsense_api_key="k", opnsense_api_secret="s")


def client_with(handler) -> OPNsenseClient:
    c = OPNsenseClient(Settings(**SETTINGS))
    c.client = httpx.AsyncClient(base_url="https://fw.test", transport=httpx.MockTransport(handler))
    return c


def test_delete_decision_uses_delete_then_falls_back_to_post():
    calls = []

    def handler(req):
        calls.append((req.method, req.url.path))
        if req.method == "DELETE":
            return httpx.Response(405, text="Method Not Allowed")
        return httpx.Response(200, json={"result": "deleted"})

    async def main():
        await client_with(handler).delete_crowdsec_decision(42)
    asyncio.run(main())
    assert calls == [("DELETE", "/api/crowdsec/decisions/del/42"), ("POST", "/api/crowdsec/decisions/del/42")]


def test_delete_decision_failed_answer_raises():
    async def main():
        with pytest.raises(ApiError):
            await client_with(lambda req: httpx.Response(200, json={"result": "failed"})).delete_crowdsec_decision(1)
    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_unban_route_removes_the_decision(monkeypatch):
    from lookingglass.web.app import create_app
    seen = []

    async def fake_delete(self, did):
        seen.append(did)
    monkeypatch.setattr(OPNsenseClient, "delete_crowdsec_decision", fake_delete)

    async def main():
        await db.connect(DSN)
        try:
            await db.set_snapshot("crowdsec_decisions", [{"id": 5, "lg_value": "203.0.113.5"}, {"id": 6, "lg_value": "x"}])
            app = create_app(Settings(**SETTINGS), None)
            ep = next(r.endpoint for r in app.routes if getattr(r, "path", "") == "/api/crowdsec/unban")
            req = SimpleNamespace(state=SimpleNamespace(user={"username": "t"}))
            res = await ep(req, {"id": "5"})
            assert res == {"ok": True, "id": 5, "value": "203.0.113.5"} and seen == [5]
            assert [r["id"] for r in await db.get_snapshot("crowdsec_decisions")] == [6]
        finally:
            await db.pool().execute("DELETE FROM snapshots WHERE key = 'crowdsec_decisions'")
            await db.close()
    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_unban_route_lapi(monkeypatch):
    from fastapi import HTTPException

    from lookingglass import crowdsec_lapi as lapi
    from lookingglass.web.app import create_app
    seen = []

    async def fake_delete(self, did):
        if not self.has_machine:
            raise lapi.LapiError(400, "unbanning needs the machine login")
        seen.append(did)
        return 1
    monkeypatch.setattr(lapi.LapiClient, "delete_decision", fake_delete)

    async def main():
        await db.connect(DSN)
        try:
            await db.set_snapshot(lapi.DECISIONS_KEY, [{"id": 9, "value": "198.51.100.9"}, {"id": 10, "value": "x"}])
            req = SimpleNamespace(state=SimpleNamespace(user={"username": "t"}))
            app = create_app(Settings(crowdsec_lapi_url="http://cs:8080", crowdsec_lapi_machine="lg",
                                      crowdsec_lapi_password="pw"), None)
            ep = next(r.endpoint for r in app.routes if getattr(r, "path", "") == "/api/crowdsec/unban")
            assert (await ep(req, {"id": 9, "src": "lapi"}))["value"] == "198.51.100.9" and seen == [9]
            assert [r["id"] for r in await db.get_snapshot(lapi.DECISIONS_KEY)] == [10]
            # one Unban for an address with several decisions (one per scenario): all of them
            await db.set_snapshot(lapi.DECISIONS_KEY, [{"id": 11, "value": "198.51.100.11"}, {"id": 12, "value": "198.51.100.11"},
                                                       {"id": 10, "value": "x"}])
            res = await ep(req, {"id": "11,12", "src": "lapi"})
            assert res["id"] == [11, 12] and seen == [9, 11, 12]
            assert [r["id"] for r in await db.get_snapshot(lapi.DECISIONS_KEY)] == [10]
            # bouncer key only: refused with the reason, the list is untouched
            app = create_app(Settings(crowdsec_lapi_url="http://cs:8080", crowdsec_lapi_bouncer_key="k"), None)
            ep = next(r.endpoint for r in app.routes if getattr(r, "path", "") == "/api/crowdsec/unban")
            with pytest.raises(HTTPException) as exc:
                await ep(req, {"id": 10, "src": "lapi"})
            assert exc.value.status_code == 400 and "machine login" in exc.value.detail
            assert len(await db.get_snapshot(lapi.DECISIONS_KEY)) == 1
        finally:
            await db.pool().execute("DELETE FROM snapshots WHERE key = $1", lapi.DECISIONS_KEY)
            await db.close()
    asyncio.run(main())
