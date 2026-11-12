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


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_ai_event_detail_with_context():
    """'Ask AI' on an event: the analyst loads the event with its device, what the source did around it, how often it
    happened and alerts about its addresses (with comments)."""
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, alert_comments, devices")
            await pool.execute("DELETE FROM events WHERE src_ip = '192.168.1.77'")
            await pool.execute("INSERT INTO devices (mac, ip, hostname) VALUES ('aa:00:00:00:00:77', '192.168.1.77', 'nas')")
            ids = [await pool.fetchval(
                "INSERT INTO events (ts, source, action, src_ip, dst_ip, dst_port, proto, message, data) VALUES "
                "(now() - make_interval(mins => $1), 'firewall', 'block', '192.168.1.77', '203.0.113.9', 23, 'tcp', $2, "
                "'{\"rule\": \"x\"}') RETURNING id", m, f"block {m}") for m in (0, 5, 60)]
            aid = await pool.fetchval("INSERT INTO alerts (rule, severity, title, fingerprint, src_ip) VALUES "
                                      "('port_scan', 'low', 't', 'f77', '192.168.1.77') RETURNING id")
            await pool.execute("INSERT INTO alert_comments (alert_id, author, body) VALUES ($1, 'rod', 'known backup job')", aid)
            d = await ai.tool_event_detail(ids[0])
            assert d["event"]["id"] == ids[0] and d["event"]["data"] == {"rule": "x"}
            assert d["devices"]["192.168.1.77"]["hostname"] == "nas"
            assert [e["id"] for e in d["same_source_15_minutes_around"]] == [ids[1]]  # not itself, not an hour earlier
            assert d["similar_events_last_7_days"]["n"] == 3
            assert d["alerts_about_these_addresses"][0]["comments"][0]["comment"] == "known backup job"
            assert "error" in await ai.tool_event_detail(-1)
            assert "event_detail" in ai.TOOL_NAMES and "known backup job" in await ai.run_tool("event_detail", {"event_id": ids[0]})
            await pool.execute("DELETE FROM events WHERE src_ip = '192.168.1.77'")
            await pool.execute("TRUNCATE alerts, alert_comments, devices")
        finally:
            await db.close()

    asyncio.run(main())
