import asyncio
import os
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from lookingglass import ai, alert_filters, db
from lookingglass.config import Settings

DSN = os.environ.get("TEST_DATABASE_URL")
REQ = SimpleNamespace(state=SimpleNamespace(user={"username": "rod"}))


def endpoints():
    from lookingglass.web.app import create_app
    return {(next(iter(r.methods)), r.path): r.endpoint for r in create_app(Settings(), None).routes if hasattr(r, "methods")}


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_comments_on_alerts_in_every_status():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, alert_comments, alert_filters")
            alert_filters.invalidate()
            ep = endpoints()
            ids = [await pool.fetchval("INSERT INTO alerts (rule, severity, title, fingerprint, status, src_ip) VALUES "
                                       "('port_scan', 'low', 't', $1, $2, '192.168.1.20') RETURNING id", f"f{i}", st)
                   for i, st in enumerate(("open", "acknowledged", "closed"))]
            for aid in ids:  # any status can be commented
                c = await ep[("POST", "/api/alerts/{aid}/comments")](aid, REQ, {"body": f"  note {aid}  "})
                assert c["body"] == f"note {aid}" and c["author"] == "rod" and c["alert_id"] == aid
            with pytest.raises(HTTPException) as exc:
                await ep[("POST", "/api/alerts/{aid}/comments")](999999, REQ, {"body": "x"})
            assert exc.value.status_code == 404
            with pytest.raises(HTTPException) as exc:
                await ep[("POST", "/api/alerts/{aid}/comments")](ids[0], REQ, {"body": "   "})
            assert exc.value.status_code == 400

            # close as false positive with a comment
            await ep[("POST", "/api/alerts/status")](REQ, {"ids": [ids[0]], "status": "closed", "reason": "false_positive",
                                                           "comment": "My backup NAS scanning, expected."})
            listed = {a["id"]: a for a in await ep[("GET", "/api/alerts")](status="all", hours=720, limit=500)}
            first = listed[ids[0]]
            assert first["status"] == "closed" and first["close_reason"] == "false_positive"
            assert [c["body"] for c in first["comments"]] == [f"note {ids[0]}", "My backup NAS scanning, expected."]
            assert [c["body"] for c in listed[ids[1]]["comments"]] == [f"note {ids[1]}"]

            # edit and delete
            cid = first["comments"][0]["id"]
            edited = await ep[("PUT", "/api/alerts/comments/{cid}")](cid, {"body": "changed"})
            assert edited["body"] == "changed" and edited["updated_at"]
            assert (await ep[("DELETE", "/api/alerts/comments/{cid}")](cid))["ok"]
            with pytest.raises(HTTPException):
                await ep[("DELETE", "/api/alerts/comments/{cid}")](cid)

            # the AI analyst sees them
            tool = await ai.tool_list_alerts(status="all")
            assert [c["comment"] for c in next(a for a in tool if a["id"] == ids[0])["comments"]] == \
                ["My backup NAS scanning, expected."]
            detail = await ai.tool_alert_detail(ids[1])
            assert detail["alert"]["comments"][0]["comment"] == f"note {ids[1]}"
            earlier = {a["id"]: a for a in detail["earlier_alerts_same_rule_and_source"]}
            assert set(earlier) == {ids[0], ids[2]} and earlier[ids[0]]["close_reason"] == "false_positive"
            assert earlier[ids[0]]["comments"][0]["comment"] == "My backup NAS scanning, expected."
            assert "error" in await ai.tool_alert_detail(999999)

            # deleting closed alerts deletes their comments
            await ep[("POST", "/api/alerts/delete")]({"ids": [ids[0], ids[2]]})
            left = {r["alert_id"] for r in await pool.fetch("SELECT alert_id FROM alert_comments")}
            assert left == {ids[1]}
            await pool.execute("TRUNCATE alerts, alert_comments, alert_filters")
        finally:
            await db.close()

    asyncio.run(main())
