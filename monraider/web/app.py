"""FastAPI web application: dashboards, event search, alerts, reports, system view and the AI chat."""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .. import __version__, db
from ..ai import Analyst
from ..config import Settings
from ..ingest import STATS
from ..reports import build_report, timeline

log = logging.getLogger(__name__)
HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(HERE / "templates"))

PAGES = {
    "/": ("dashboard.html", "Dashboard"),
    "/events": ("events.html", "Events"),
    "/alerts": ("alerts.html", "Alerts"),
    "/system": ("system.html", "System"),
    "/reports": ("reports.html", "Reports"),
    "/ai": ("ai.html", "AI Analyst"),
    "/setup": ("setup.html", "Setup"),
}


def create_app(settings: Settings, analyst: Analyst, poller_status: dict[str, Any] | None = None) -> FastAPI:
    app = FastAPI(title="MonRaider", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def auth(request: Request, call_next):
        path = request.url.path
        if path.startswith("/static") or path in ("/login", "/healthz"):
            return await call_next(request)
        if not request.session.get("user"):
            if path.startswith("/api/"):
                return JSONResponse({"detail": "not authenticated"}, status_code=401)
            return RedirectResponse("/login")
        # simple CSRF protection for state changing API calls: require a custom header
        if path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS") \
                and request.headers.get("x-monraider") != "1":
            return JSONResponse({"detail": "missing X-MonRaider header"}, status_code=403)
        return await call_next(request)

    # added after the auth middleware so it wraps it (sessions must be decoded first)
    app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, session_cookie="monraider_session",
                       max_age=7 * 24 * 3600, same_site="strict", https_only=False)
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    # ------------------------------------------------------------ pages ---
    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        return templates.TemplateResponse(request, "login.html", {"error": None, "version": __version__})

    @app.post("/login")
    async def login(request: Request):
        form = await request.form()
        user, password = str(form.get("username", "")), str(form.get("password", ""))
        ok = hmac.compare_digest(user, settings.admin_user) and hmac.compare_digest(password, settings.admin_password)
        if not ok:
            await asyncio.sleep(1)  # slow down guessing
            return templates.TemplateResponse(request, "login.html", {"error": "Invalid credentials", "version": __version__},
                                              status_code=401)
        request.session["user"] = user
        return RedirectResponse("/", status_code=303)

    @app.get("/logout")
    async def logout(request: Request):
        request.session.clear()
        return RedirectResponse("/login")

    @app.get("/healthz")
    async def healthz():
        await db.pool().fetchval("SELECT 1")
        return {"ok": True}

    def page(path: str):
        tpl, title = PAGES[path]

        async def handler(request: Request):
            return templates.TemplateResponse(request, tpl, {
                "title": title, "path": path, "version": __version__, "ai_enabled": settings.ai_enabled,
                "ai_model": settings.ai_model, "opnsense": settings.opnsense_enabled,
                "syslog_port": settings.syslog_udp_port,
            })
        return handler

    for p in PAGES:
        app.add_api_route(p, page(p), methods=["GET"], response_class=HTMLResponse)

    @app.get("/reports/{report_id}", response_class=HTMLResponse)
    async def report_page(request: Request, report_id: int):
        return templates.TemplateResponse(request, "report_view.html", {
            "title": "Report", "path": "/reports", "version": __version__, "report_id": report_id, "ai_enabled": settings.ai_enabled})

    # -------------------------------------------------------------- api ---
    @app.get("/api/overview")
    async def overview(hours: float = Query(24, gt=0, le=24 * 90)):
        pool = db.pool()
        secs = hours * 3600
        kpi = await pool.fetchrow(
            "SELECT count(*) total, count(*) FILTER (WHERE action IN ('block', 'drop', 'ban')) blocked, "
            "count(DISTINCT src_ip) FILTER (WHERE action IN ('block', 'drop')) blocked_ips, "
            "count(*) FILTER (WHERE action = 'login_failed') login_failed, "
            "count(*) FILTER (WHERE source = 'unbound') dns, count(*) FILTER (WHERE source = 'suricata') ids "
            "FROM events WHERE ts > now() - make_interval(secs => $1)", secs)
        alerts = await pool.fetch("SELECT severity, count(*) n FROM alerts WHERE status = 'open' GROUP BY 1")
        decisions = await db.get_snapshot("crowdsec_decisions")
        devices = await pool.fetchval("SELECT count(*) FROM devices WHERE last_seen > now() - interval '1 day'")
        report = await build_report(hours)
        return {
            "kpi": {**db.jsonable(dict(kpi)), "open_alerts": {r["severity"]: r["n"] for r in alerts},
                    "crowdsec_decisions": len(decisions) if isinstance(decisions, list) else None, "devices": devices},
            "timeline": await timeline(hours),
            "report": report,
            "system": await db.get_snapshot("system"),
            "gateways": await db.get_snapshot("gateways"),
            "ingest": STATS.as_dict(),
        }

    @app.get("/api/events")
    async def events(source: str | None = None, ip: str | None = None, action: str | None = None, q: str | None = None,
                     hours: float = Query(24, gt=0), limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
                     min_severity: int | None = Query(None, ge=0, le=7)):
        where, args = ["ts > now() - make_interval(secs => $1)"], [hours * 3600]
        if source:
            args.append(source.split(","))
            where.append(f"source = ANY(${len(args)}::text[])")
        if ip:
            args.append(ip.strip())
            if "/" in ip:
                where.append(f"(src_ip << ${len(args)}::inet OR dst_ip << ${len(args)}::inet)")
            else:
                where.append(f"(src_ip = ${len(args)}::inet OR dst_ip = ${len(args)}::inet)")
        if action:
            args.append(action.split(","))
            where.append(f"action = ANY(${len(args)}::text[])")
        if q:
            args.append(f"%{q}%")
            where.append(f"(message ILIKE ${len(args)} OR domain ILIKE ${len(args)} OR username ILIKE ${len(args)})")
        if min_severity is not None:
            args.append(min_severity)
            where.append(f"severity <= ${len(args)}")
        args += [limit + 1, offset]
        try:
            rows = await db.pool().fetch(
                f"SELECT id, ts, source, host, program, severity, action, host(src_ip) src_ip, src_port, host(dst_ip) dst_ip, dst_port, "
                f"proto, interface, direction, username, domain, src_country, dst_country, message, data FROM events "
                f"WHERE {' AND '.join(where)} ORDER BY ts DESC LIMIT ${len(args) - 1} OFFSET ${len(args)}", *args)
        except Exception as exc:  # noqa: BLE001 - e.g. invalid inet literal
            raise HTTPException(400, f"invalid filter: {exc}") from exc
        out = db.records(rows)
        return {"rows": out[:limit], "has_more": len(out) > limit}

    @app.get("/api/alerts")
    async def alerts(status: str = "open", hours: float = Query(24 * 30, gt=0), limit: int = Query(500, le=5000)):
        args: list[Any] = [hours * 3600, limit]
        cond = ""
        if status != "all":
            args.append(status.split(","))
            cond = "AND status = ANY($3::text[])"
        rows = await db.pool().fetch(
            f"SELECT id, created_at, last_seen, rule, severity, title, description, host(src_ip) src_ip, host(dst_ip) dst_ip, count, status, data "
            f"FROM alerts WHERE last_seen > now() - make_interval(secs => $1) {cond} "
            f"ORDER BY array_position(ARRAY['critical','high','medium','low','info'], severity), last_seen DESC LIMIT $2", *args)
        return db.records(rows)

    @app.post("/api/alerts/status")
    async def set_alert_status(payload: dict = Body(...)):
        ids = [int(i) for i in payload.get("ids", [])]
        status = payload.get("status")
        if status not in ("open", "acknowledged", "closed"):
            raise HTTPException(400, "invalid status")
        await db.pool().execute("UPDATE alerts SET status = $1 WHERE id = ANY($2::bigint[])", status, ids)
        return {"ok": True, "updated": len(ids)}

    @app.get("/api/system")
    async def system():
        keys = ["system", "gateways", "interfaces", "services", "firmware", "arp", "poller_status", "unbound_totals",
                "qfeeds_stats", "rule_labels"]
        rows = await db.pool().fetch("SELECT key, ts, data FROM snapshots WHERE key = ANY($1::text[])", keys)
        snaps = {r["key"]: {"ts": r["ts"].isoformat(), "data": r["data"]} for r in rows}
        snaps.pop("rule_labels", None)
        return {"snapshots": snaps, "ingest": STATS.as_dict(), "opnsense": settings.opnsense_enabled}

    @app.get("/api/metrics")
    async def metrics(name: str, hours: float = Query(24, gt=0), labels: str | None = None):
        secs = hours * 3600
        step = max(60, int(secs / 300))
        args: list[Any] = [name, secs, step]
        cond = ""
        if labels is not None:
            args.append(labels)
            cond = "AND labels = $4"
        rows = await db.pool().fetch(
            "SELECT labels, to_timestamp(floor(extract(epoch FROM ts) / $3) * $3) t, avg(value) v FROM metrics "
            f"WHERE name = $1 AND ts > now() - make_interval(secs => $2) {cond} GROUP BY 1, 2 ORDER BY 2", *args)
        series: dict[str, list] = {}
        for r in rows:
            series.setdefault(r["labels"], []).append([r["t"].isoformat(), round(r["v"], 3)])
        return series

    @app.get("/api/devices")
    async def devices():
        rows = await db.pool().fetch("SELECT mac, host(ip) ip, hostname, first_seen, last_seen FROM devices ORDER BY last_seen DESC LIMIT 2000")
        return db.records(rows)

    @app.get("/api/status")
    async def status():
        return {"ingest": STATS.as_dict(), "poller": await db.get_snapshot("poller_status"),
                "opnsense": settings.opnsense_enabled, "ai": settings.ai_enabled, "ai_model": settings.ai_model,
                "ai_base_url": settings.ai_base_url, "retention_days": settings.retention_days,
                "syslog": {"udp": settings.syslog_udp_port, "tcp": settings.syslog_tcp_port, "enabled": settings.syslog_enabled},
                "db_size": await db.pool().fetchval("SELECT pg_size_pretty(pg_database_size(current_database()))"),
                "events_total": await db.pool().fetchval("SELECT reltuples::bigint FROM pg_class WHERE relname = 'events'")}

    # ----------------------------------------------------------- reports ---
    @app.get("/api/reports")
    async def list_reports():
        rows = await db.pool().fetch("SELECT id, created_at, period_h, title, ai_summary IS NOT NULL has_ai FROM reports ORDER BY id DESC LIMIT 200")
        return db.records(rows)

    @app.post("/api/reports")
    async def create_report(payload: dict = Body(...)):
        hours = int(payload.get("hours", 24))
        if hours <= 0 or hours > 24 * 90:
            raise HTTPException(400, "hours out of range")
        data = await build_report(hours)
        summary = None
        if payload.get("ai") and settings.ai_enabled:
            try:
                summary = await analyst.analyse(hours)
            except Exception as exc:  # noqa: BLE001
                summary = f"AI analysis failed: {exc}"
        label = {24: "Daily", 168: "Weekly", 720: "Monthly"}.get(hours, f"{hours}h")
        rid = await db.pool().fetchval(
            "INSERT INTO reports (period_h, title, data, ai_summary) VALUES ($1, $2, $3, $4) RETURNING id",
            hours, f"{label} security report", data, summary)
        return {"id": rid}

    @app.get("/api/reports/{report_id}")
    async def get_report(report_id: int):
        row = await db.pool().fetchrow("SELECT * FROM reports WHERE id = $1", report_id)
        if not row:
            raise HTTPException(404)
        return db.jsonable(dict(row))

    @app.get("/api/reports/{report_id}/download")
    async def download_report(report_id: int):
        row = await db.pool().fetchrow("SELECT * FROM reports WHERE id = $1", report_id)
        if not row:
            raise HTTPException(404)
        return Response(json.dumps(db.jsonable(dict(row)), indent=2), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="monraider-report-{report_id}.json"'})

    @app.delete("/api/reports/{report_id}")
    async def delete_report(report_id: int):
        await db.pool().execute("DELETE FROM reports WHERE id = $1", report_id)
        return {"ok": True}

    # ---------------------------------------------------------------- AI ---
    @app.get("/api/ai/chats")
    async def chats():
        rows = await db.pool().fetch("SELECT id, title, updated_at FROM ai_chats ORDER BY updated_at DESC LIMIT 100")
        return db.records(rows)

    @app.get("/api/ai/chats/{chat_id}")
    async def chat(chat_id: int):
        row = await db.pool().fetchrow("SELECT * FROM ai_chats WHERE id = $1", chat_id)
        if not row:
            raise HTTPException(404)
        return db.jsonable(dict(row))

    @app.delete("/api/ai/chats/{chat_id}")
    async def delete_chat(chat_id: int):
        await db.pool().execute("DELETE FROM ai_chats WHERE id = $1", chat_id)
        return {"ok": True}

    @app.post("/api/ai/message")
    async def ai_message(payload: dict = Body(...)):
        text = str(payload.get("text", "")).strip()
        if not text:
            raise HTTPException(400, "empty message")
        if not settings.ai_enabled:
            raise HTTPException(400, "AI is not configured (AI_API_KEY / AI_BASE_URL / AI_MODEL)")
        chat_id = payload.get("chat_id")
        history: list[dict[str, Any]] = []
        if chat_id:
            row = await db.pool().fetchrow("SELECT messages FROM ai_chats WHERE id = $1", int(chat_id))
            if row:
                history = row["messages"]
            else:
                chat_id = None
        try:
            new = await analyst.chat(history, text)
        except Exception as exc:  # noqa: BLE001
            log.exception("AI request failed")
            raise HTTPException(502, f"AI request failed: {exc}") from exc
        messages = history + new
        if chat_id:
            await db.pool().execute("UPDATE ai_chats SET messages = $2, updated_at = now() WHERE id = $1", int(chat_id), messages)
        else:
            chat_id = await db.pool().fetchval("INSERT INTO ai_chats (title, messages) VALUES ($1, $2) RETURNING id",
                                               text[:80], messages)
        return {"chat_id": chat_id, "messages": new}

    return app
