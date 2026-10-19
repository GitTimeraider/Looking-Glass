"""FastAPI web application: dashboards, event search, alerts, reports, system view and the AI chat."""
from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime
import logging
from pathlib import Path
from typing import Any

import httpx
from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .. import __version__, app_config, auth, crypto, db
from ..ai import Analyst
from ..config import Settings
from ..ingest import STATS
from ..dashboards import DASHBOARDS, run_dashboard
from ..reports import build_report, timeline
from .. import setup_checks, unraid_storage
from ..parsers.common import real_name
from ..unraid import test_connection as unraid_test
from .auth_routes import PUBLIC_PATHS, SETUP_PATHS, current_user
from .auth_routes import register as register_auth

log = logging.getLogger(__name__)
HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(HERE / "templates"))
# (key, menu label, menu group): dashboards sit under their product ("opnsense", "unifi"), "tools" covers every source
DASH_NAV = [(k, v["title"].split(" (")[0], v.get("group", "tools")) for k, v in DASHBOARDS.items()]
templates.env.globals["dashboards"] = DASH_NAV

PAGES = {
    "/": ("dashboard.html", "Overview"),
    "/events": ("events.html", "Events"),
    "/alerts": ("alerts.html", "Alerts"),
    "/system": ("system.html", "OPNsense"),
    "/devices": ("devices.html", "Devices"),
    "/unraid": ("unraid.html", "Unraid"),
    "/unifi": ("unifi.html", "UniFi"),
    "/reports": ("reports.html", "Reports"),
    "/ai": ("ai.html", "AI Analyst"),
    "/setup": ("setup.html", "Setup"),
    "/settings": ("settings.html", "Settings"),
}


def create_app(settings: Settings, analyst: Analyst, poller_status: dict[str, Any] | None = None) -> FastAPI:
    app = FastAPI(title="Looking Glass", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def auth_guard(request: Request, call_next):
        path = request.url.path
        if path.startswith("/static/") or path in PUBLIC_PATHS:
            return await call_next(request)
        user, mfa = await current_user(request)
        if not user:
            if path.startswith("/api/"):
                return JSONResponse({"detail": "not authenticated"}, status_code=401)
            return RedirectResponse("/login")
        # MFA is mandatory: until a TOTP app or passkey is enrolled only the account page is reachable
        if not mfa and not (path in SETUP_PATHS or path.startswith("/api/account")):
            if path.startswith("/api/"):
                return JSONResponse({"detail": "set up MFA first"}, status_code=403)
            return RedirectResponse("/account?setup=1")
        # CSRF protection for state changing API calls: require a custom header (not settable cross-site)
        if path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS") \
                and request.headers.get("x-looking-glass") != "1":
            return JSONResponse({"detail": "missing X-Looking-Glass header"}, status_code=403)
        request.state.user = user
        return await call_next(request)

    # added after the guard so it wraps it (the session must be decoded first)
    app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, session_cookie="lookingglass_session",
                       max_age=7 * 24 * 3600, same_site="lax", https_only=settings.cookie_secure)
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    register_auth(app, settings, templates)

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
                "syslog_port": settings.syslog_udp_port, "user": request.session.get("user"),
                "dashboards": DASH_NAV,
            })
        return handler

    for p in PAGES:
        app.add_api_route(p, page(p), methods=["GET"], response_class=HTMLResponse)

    @app.get("/hardware")
    async def hardware_moved():  # merged into the OPNsense page
        return RedirectResponse("/system")

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
        # optional sources: hide their overview cards when their pull is off and they have no data in the period
        has = {r["source"] for r in report.get("totals_by_source") or []}
        enabled = {"suricata": settings.ids_pull, "crowdsec": settings.crowdsec_pull, "qfeeds": settings.qfeeds_pull,
                   "nginx": settings.nginx_pull, "unbound": settings.unbound_query_pull, "zenarmor": False}
        enabled = {k: (v and settings.opnsense_enabled) or k in has for k, v in enabled.items()}
        return {
            "sources": enabled,
            "kpi": {**db.jsonable(dict(kpi)), "open_alerts": {r["severity"]: r["n"] for r in alerts},
                    "crowdsec_decisions": len(decisions) if isinstance(decisions, list) else None, "devices": devices},
            "timeline": await timeline(hours),
            "report": report,
            "system": await db.get_snapshot("system"),
            "gateways": await db.get_snapshot("gateways"),
            "ingest": STATS.as_dict(),
        }

    @app.get("/api/events")
    async def events(request: Request, source: str | None = None, ip: str | None = None, action: str | None = None,
                     q: str | None = None, hours: float = Query(24, gt=0), limit: int = Query(100, ge=1, le=1000),
                     offset: int = Query(0, ge=0), min_severity: int | None = Query(None, ge=0, le=7),
                     start: str | None = None, end: str | None = None):
        """Event search. Besides the form fields every dashboard click-through filter is accepted:
        program, host, domain, user, port, proto, iface, direction, country, start/end (ISO time) and
        ``d_<key>=<value>`` for a key inside the event's JSON data (``none`` matches an empty value)."""
        where: list[str] = []
        args: list[Any] = []

        def arg(v: Any) -> str:
            args.append(v)
            return f"${len(args)}"

        if start or end:
            try:
                t0 = datetime.fromisoformat(start.replace("Z", "+00:00")) if start else None
                t1 = datetime.fromisoformat(end.replace("Z", "+00:00")) if end else None
            except ValueError as exc:
                raise HTTPException(400, "start/end must be ISO timestamps") from exc
            if t0:
                where.append(f"ts >= {arg(t0)}")
            if t1:
                where.append(f"ts < {arg(t1)}")
        else:
            where.append(f"ts > now() - make_interval(secs => {arg(hours * 3600)})")
        if source:
            where.append(f"source = ANY({arg(source.split(','))}::text[])")
        if ip:
            ip = ip.strip()
            op = "<<=" if "/" in ip else "="
            a = arg(ip)
            where.append(f"(src_ip {op} {a}::inet OR dst_ip {op} {a}::inet)")
        if action:  # "a,b" = any of; "http_4*" = prefix
            acts = action.split(",")
            exact, prefixes = [a for a in acts if not a.endswith("*")], [a[:-1] + "%" for a in acts if a.endswith("*")]
            conds = ([f"action = ANY({arg(exact)}::text[])"] if exact else []) + \
                    ([f"action LIKE ANY({arg(prefixes)}::text[])"] if prefixes else [])
            where.append("(" + " OR ".join(conds) + ")")
        if q:
            a = arg(f"%{q}%")
            where.append(f"(message ILIKE {a} OR domain ILIKE {a} OR username ILIKE {a} OR program ILIKE {a})")
        if min_severity is not None:
            where.append(f"severity <= {arg(min_severity)}")
        qp = request.query_params
        simple = {"program": "program", "host": "host", "domain": "domain", "user": "username", "proto": "proto",
                  "iface": "interface", "direction": "direction", "country": "src_country"}
        for param, col in simple.items():
            v = qp.get(param)
            if v is None:
                continue
            where.append(f"{col} IS NULL" if v == "none" else f"{col} = {arg(v)}")
        if qp.get("port"):
            try:
                where.append(f"dst_port = {arg(int(qp['port']))}")
            except ValueError as exc:
                raise HTTPException(400, "port must be a number") from exc
        for key, v in qp.items():
            if key.startswith("d_") and re.fullmatch(r"d_[A-Za-z0-9_]{1,40}", key):
                k = arg(key[2:])
                where.append(f"coalesce(data->>{k}, '') = ''" if v == "none" else f"data->>{k} = {arg(v)}")
        lim, off = arg(limit + 1), arg(offset)
        try:
            rows = await db.pool().fetch(
                f"SELECT id, ts, source, host, program, severity, action, host(src_ip) src_ip, src_port, host(dst_ip) dst_ip, dst_port, "
                f"proto, interface, direction, username, domain, src_country, dst_country, message, data FROM events "
                f"WHERE {' AND '.join(where)} ORDER BY ts DESC LIMIT {lim} OFFSET {off}", *args)
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
        out = db.records(rows)
        # which enabled alert filter (mute) matches each alert - the alerts page offers "Unmute" for those
        from .. import alert_filters

        filters = await alert_filters._filters()
        for a in out:
            f = next((f for f in filters if alert_filters.matches(f, a["rule"], a["severity"], a["title"], a.get("description") or "",
                                                                 a.get("src_ip"), a.get("dst_ip"))), None)
            a["muted_by"] = {"id": f["id"], "name": f.get("name") or f"filter #{f['id']}", "action": f["action"]} if f else None
        return out

    # ------------------------------------------------------------ layouts ---
    # per user page layouts (Overview widgets): [{"id": "timeline", "w": 1-3, "h": 1-2}, ...]
    def _layout_key(request: Request, page: str) -> str:
        if page not in ("overview",):
            raise HTTPException(404)
        return f"layout:{page}:{request.session.get('user') or '?'}"

    @app.get("/api/layout/{page}")
    async def get_layout(page: str, request: Request):
        return {"layout": await db.kv_get(_layout_key(request, page))}

    @app.put("/api/layout/{page}")
    async def put_layout(page: str, request: Request, payload: dict = Body(...)):
        key = _layout_key(request, page)
        items = payload.get("layout")
        if not isinstance(items, list) or len(items) > 80:
            raise HTTPException(400, "layout must be a list")
        clean, seen = [], set()
        for it in items:
            wid = str((it or {}).get("id") or "")
            if not re.fullmatch(r"[a-z0-9_-]{1,40}", wid) or wid in seen:
                continue
            seen.add(wid)
            try:
                w, h = int(it.get("w") or 1), int(it.get("h") or 1)
            except (TypeError, ValueError):
                w, h = 1, 1
            clean.append({"id": wid, "w": min(3, max(1, w)), "h": min(2, max(1, h))})
        await db.kv_set(key, clean)
        return {"ok": True, "layout": clean}

    @app.delete("/api/layout/{page}")
    async def reset_layout(page: str, request: Request):
        await db.pool().execute("DELETE FROM kv WHERE key = $1", _layout_key(request, page))
        return {"ok": True}

    # -------------------------------------------------------- alert filters ---
    from .. import alert_filters as af

    def _filter_out(r: Any) -> dict[str, Any]:
        return db.jsonable({k: v for k, v in dict(r).items()})

    @app.get("/api/alert-filters")
    async def list_filters():
        rows = await db.pool().fetch("SELECT * FROM alert_filters ORDER BY id")
        seen = {r["rule"] for r in await db.pool().fetch("SELECT DISTINCT rule FROM alerts")}
        groups = {g: [{"rule": r, "label": label} for r, label in items] for g, items in af.RULES.items()}
        extra = sorted(seen - af.RULE_NAMES)
        if extra:
            groups["Other"] = [{"rule": r, "label": r} for r in extra]
        return {"filters": [_filter_out(r) for r in rows], "rules": groups, "severities": af.SEVERITIES}

    def _clean_filter(payload: dict) -> dict[str, Any]:
        try:
            return af.clean(payload)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/alert-filters")
    async def add_filter(payload: dict = Body(...)):
        f = _clean_filter(payload)
        row = await db.pool().fetchrow(
            "INSERT INTO alert_filters (name, enabled, max_severity, rules, contains, networks, action, match_mode, text_mode) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *", *f.values())
        af.invalidate()
        return _filter_out(row)

    @app.put("/api/alert-filters/{fid}")
    async def edit_filter(fid: int, payload: dict = Body(...)):
        f = _clean_filter(payload)
        row = await db.pool().fetchrow(
            "UPDATE alert_filters SET name = $2, enabled = $3, max_severity = $4, rules = $5, contains = $6, networks = $7, "
            "action = $8, match_mode = $9, text_mode = $10 WHERE id = $1 RETURNING *", fid, *f.values())
        if not row:
            raise HTTPException(404)
        af.invalidate()
        return _filter_out(row)

    @app.delete("/api/alert-filters/{fid}")
    async def delete_filter(fid: int):
        await db.pool().execute("DELETE FROM alert_filters WHERE id = $1", fid)
        af.invalidate()
        return {"ok": True}

    async def _matching_alerts(f: dict[str, Any], statuses: tuple[str, ...]) -> list[dict[str, Any]]:
        rows = await db.pool().fetch(
            "SELECT id, rule, severity, title, coalesce(description, '') description, host(src_ip) src_ip, host(dst_ip) dst_ip, "
            "status, last_seen FROM alerts WHERE last_seen > now() - interval '30 days' AND status = ANY($1::text[]) "
            "ORDER BY last_seen DESC LIMIT 20000", list(statuses))
        return [dict(r) for r in rows if af.matches(f, r["rule"], r["severity"], r["title"], r["description"], r["src_ip"], r["dst_ip"])]

    @app.post("/api/alert-filters/preview")
    async def preview_filter(payload: dict = Body(...)):
        """Which alerts of the last 30 days this filter would have caught."""
        f = _clean_filter(payload)
        hits = await _matching_alerts(f, ("open", "acknowledged", "closed"))
        open_n = sum(1 for h in hits if h["status"] != "closed")
        return {"total": len(hits), "open": open_n,
                "sample": db.jsonable([{k: h[k] for k in ("id", "severity", "rule", "title", "status", "last_seen")} for h in hits[:15]])}

    @app.post("/api/alert-filters/{fid}/apply")
    async def apply_filter(fid: int):
        """Close the open / acknowledged alerts this filter matches."""
        row = await db.pool().fetchrow("SELECT * FROM alert_filters WHERE id = $1", fid)
        if not row:
            raise HTTPException(404)
        ids = [h["id"] for h in await _matching_alerts(dict(row), ("open", "acknowledged"))]
        if ids:
            await db.pool().execute("UPDATE alerts SET status = 'closed' WHERE id = ANY($1::bigint[])", ids)
        return {"closed": len(ids)}

    @app.get("/api/alerts/counts")
    async def alert_counts(hours: float = Query(24 * 30, gt=0)):
        """Number of alerts per status in the same window as /api/alerts (not limited by its row limit)."""
        rows = await db.pool().fetch("SELECT status, count(*) n FROM alerts WHERE last_seen > now() - make_interval(secs => $1) "
                                     "GROUP BY 1", hours * 3600)
        counts = {s: 0 for s in ("open", "acknowledged", "closed")} | {r["status"]: r["n"] for r in rows}
        return {**counts, "all": sum(counts.values())}

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

    @app.get("/api/status")
    async def status():
        return {"ingest": STATS.as_dict(), "poller": await db.get_snapshot("poller_status"),
                "opnsense": settings.opnsense_enabled, "ai": settings.ai_enabled, "ai_model": settings.ai_model,
                "ai_base_url": settings.ai_base_url, "retention_days": settings.retention_days,
                "syslog": {"udp": settings.syslog_udp_port, "tcp": settings.syslog_tcp_port, "enabled": settings.syslog_enabled},
                "db_size": await db.pool().fetchval("SELECT pg_size_pretty(pg_database_size(current_database()))"),
                "events_total": await db.pool().fetchval("SELECT reltuples::bigint FROM pg_class WHERE relname = 'events'")}

    # ------------------------------------------------- delete collected data ---
    # What can be wiped. Never touched: settings, credentials, accounts / MFA, Unraid servers, encryption key.
    PURGE = {
        "events": ("events", "Logs / events"),
        "alerts": ("alerts", "Alerts"),
        "metrics": ("metrics", "Graphs (metrics history)"),
        "reports": ("reports", "Reports"),
        "ai_chats": ("ai_chats", "AI analyst conversations"),
        "devices": ("devices", "Device list (incl. names, notes and trusted marks you set)"),
    }

    @app.get("/api/admin/data")
    async def data_sizes():
        out = []
        for key, (table, label) in PURGE.items():
            row = await db.pool().fetchrow(
                f"SELECT pg_size_pretty(pg_total_relation_size('{table}')) size, "
                f"(SELECT reltuples::bigint FROM pg_class WHERE relname = '{table}') approx")
            exact = await db.pool().fetchval(f"SELECT count(*) FROM {table}") if (row["approx"] or 0) < 100000 else None
            out.append({"key": key, "label": label, "size": row["size"], "rows": exact if exact is not None else max(0, row["approx"])})
        return out

    @app.post("/api/admin/purge")
    async def purge(request: Request, payload: dict = Body(...)):
        parts = [p for p in payload.get("parts") or [] if p in PURGE]
        if not parts:
            raise HTTPException(400, "Select what to delete.")
        if str(payload.get("confirm", "")).strip() != "DELETE":
            raise HTTPException(400, "Type DELETE to confirm.")
        user = request.state.user
        if not await asyncio.to_thread(auth.verify_password, str(payload.get("password", "")), user["password_hash"]):
            raise HTTPException(403, "Wrong password.")
        # TRUNCATE without RESTART IDENTITY: event ids keep growing, so the detection rules' watermarks stay valid
        await db.pool().execute(f"TRUNCATE {', '.join(PURGE[p][0] for p in parts)}")
        log.warning("user %s deleted collected data: %s", user["username"], ", ".join(parts))
        return {"ok": True, "deleted": parts}

    @app.get("/api/setup/checks")
    async def setup_status():
        return await setup_checks.run(settings)

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
                        headers={"Content-Disposition": f'attachment; filename="looking-glass-report-{report_id}.json"'})

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

    @app.post("/api/ai/chats/delete")
    async def delete_chats(payload: dict = Body(...)):
        try:
            ids = [int(i) for i in payload.get("ids") or []]
        except (TypeError, ValueError):
            raise HTTPException(400, "ids must be a list of chat ids")
        deleted = await db.pool().fetchval(
            "WITH d AS (DELETE FROM ai_chats WHERE id = ANY($1::bigint[]) RETURNING 1) SELECT count(*) FROM d", ids)
        return {"ok": True, "deleted": deleted}

    @app.post("/api/ai/message")
    async def ai_message(payload: dict = Body(...)):
        text = str(payload.get("text", "")).strip()
        if not text:
            raise HTTPException(400, "empty message")
        if not settings.ai_enabled:
            raise HTTPException(400, "AI is not configured - enter the API key under Settings › AI analyst")
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


    # ------------------------------------------------- function dashboards ---
    @app.get("/dash/{name}", response_class=HTMLResponse)
    async def dash_page(request: Request, name: str):
        if name not in DASHBOARDS:
            raise HTTPException(404)
        return templates.TemplateResponse(request, "dash.html", {
            "title": DASHBOARDS[name]["title"], "path": f"/dash/{name}", "version": __version__, "name": name,
            "ai_enabled": settings.ai_enabled, "user": request.session.get("user")})

    @app.get("/api/dash/{name}")
    async def dash_data(name: str, hours: float = Query(24, gt=0, le=24 * 90)):
        if name not in DASHBOARDS:
            raise HTTPException(404)
        return await run_dashboard(name, hours)

    @app.get("/api/unifi")
    async def unifi_data():
        rows = await db.pool().fetch("SELECT key, ts, data FROM snapshots WHERE key LIKE 'unifi:%'")
        snaps = {r["key"].split(":", 1)[1]: r["data"] for r in rows}
        ts = {r["key"].split(":", 1)[1]: r["ts"].isoformat() for r in rows}
        clients = snaps.get("clients") or []
        if clients:  # UniFi often has no name for a client - the device list may (DHCP, dnsmasq Hosts, your own name)
            names = {r["mac"]: r["hostname"] for r in await db.pool().fetch(
                "SELECT mac, hostname FROM devices WHERE mac = ANY($1::text[]) AND hostname IS NOT NULL", [c.get("mac") for c in clients])}
            for c in clients:
                c["known_as"] = names.get(c.get("mac"))
        return {"configured": settings.unifi_enabled, "url": settings.unifi_url, "updated": ts.get("devices"), **snaps}

    @app.get("/api/metrics/multi")
    async def metrics_multi(names: str, hours: float = Query(24, gt=0), prefix: str | None = None):
        """Several metric series at once: {name: {labels: [[t, v], ...]}}; ``prefix`` filters labels (e.g. unraid server id)."""
        secs = hours * 3600
        step = max(60, int(secs / 300))
        rows = await db.pool().fetch(
            "SELECT name, labels, to_timestamp(floor(extract(epoch FROM ts) / $3) * $3) t, avg(value) v FROM metrics "
            "WHERE name = ANY($1::text[]) AND ts > now() - make_interval(secs => $2) "
            "AND ($4::text IS NULL OR labels = $4 OR labels LIKE $4 || ':%') GROUP BY 1, 2, 3 ORDER BY 3",
            names.split(","), secs, step, prefix)
        out: dict[str, dict[str, list]] = {}
        for r in rows:
            out.setdefault(r["name"], {}).setdefault(r["labels"], []).append([r["t"].isoformat(), round(r["v"], 3)])
        return out

    # ----------------------------------------------------------- hardware ---
    @app.get("/api/hardware")
    async def hardware():
        keys = ["system", "activity", "interfaces", "gateways"]
        rows = await db.pool().fetch("SELECT key, ts, data FROM snapshots WHERE key = ANY($1::text[])", keys)
        latest = await db.pool().fetch(
            "SELECT DISTINCT ON (name, labels) name, labels, value FROM metrics WHERE ts > now() - interval '15 minutes' "
            "AND name IN ('cpu_used_pct', 'memory_used_pct', 'swap_used_pct', 'pf_states_pct', 'load1', 'temperature', "
            "'disk_used_pct', 'if_rx_bps', 'if_tx_bps', 'zfs_arc_pct') ORDER BY name, labels, ts DESC")
        return {"snapshots": {r["key"]: {"ts": r["ts"].isoformat(), "data": r["data"]} for r in rows},
                "latest": db.records(latest)}

    # ------------------------------------------------------------ devices ---
    @app.get("/api/devices")
    async def devices(hours: float = Query(24, gt=0)):
        rows = await db.pool().fetch(
            "SELECT d.mac, host(d.ip) ip, d.hostname, d.name_source, d.vendor, d.interface, d.sources, d.lease_type, d.lease_expires, "
            "d.online, d.trusted, d.notes, d.first_seen, d.last_seen, d.conn_type, d.conn_where, d.conn_signal, "
            "(SELECT count(*) FROM events e WHERE e.src_ip = d.ip AND e.ts > now() - make_interval(secs => $1)) events, "
            "(SELECT count(*) FROM events e WHERE e.src_ip = d.ip AND e.action = 'block' AND e.ts > now() - make_interval(secs => $1)) blocked, "
            "(SELECT count(*) FROM events e WHERE e.src_ip = d.ip AND e.source = 'unbound' AND e.ts > now() - make_interval(secs => $1)) dns, "
            "(SELECT count(*) FROM alerts a WHERE (a.src_ip = d.ip OR a.dst_ip = d.ip) AND a.status = 'open') alerts "
            "FROM devices d ORDER BY d.online DESC, d.last_seen DESC LIMIT 3000", hours * 3600)
        return db.records(rows)

    @app.post("/api/devices/{mac}")
    async def update_device(mac: str, payload: dict = Body(...)):
        pool = db.pool()
        await pool.execute("UPDATE devices SET trusted = COALESCE($2, trusted), notes = COALESCE($3, notes) WHERE mac = $1",
                           mac.lower(), payload.get("trusted"), payload.get("notes"))
        if "hostname" in payload:
            # a name typed here is never replaced by DHCP / DNS; an empty name hands naming back to them
            name = real_name(payload.get("hostname"))
            await pool.execute("UPDATE devices SET hostname = $2, name_source = $3, name_rank = $4 WHERE mac = $1",
                               mac.lower(), name, "manual" if name else None, 100 if name else 0)
        return {"ok": True}

    @app.delete("/api/devices/{mac}")
    async def delete_device(mac: str):
        await db.pool().execute("DELETE FROM devices WHERE mac = $1", mac.lower())
        return {"ok": True}

    # ------------------------------------------------------------- unraid ---
    def _server_out(r: Any) -> dict[str, Any]:
        d = db.jsonable(dict(r))
        d["api_key"] = "set" if d.get("api_key") else ""  # never returned, not even partially
        return d

    @app.get("/api/unraid/servers")
    async def unraid_servers():
        rows = await db.pool().fetch("SELECT * FROM unraid_servers ORDER BY id")
        status = await db.get_snapshot("unraid_status") or {}
        out = []
        for r in rows:
            snap = await db.get_snapshot(f"unraid:{r['id']}:storage") or {}
            groups = [{k: g.get(k) for k in ("name", "kind", "disks", "fsType", "excluded", "smart_minutes", "spinning",
                                              "standby", "ssd")} for g in snap.get("groups") or []]
            out.append({**_server_out(r), "storage": unraid_storage.clean_prefs(r["storage"]), "groups": groups,
                        "status": status.get(str(r["id"]))})
        return out

    @app.put("/api/unraid/servers/{sid}/storage")
    async def unraid_storage_prefs(sid: int, payload: dict = Body(...)):
        prefs = unraid_storage.clean_prefs(payload)
        await db.pool().execute("UPDATE unraid_servers SET storage = $2 WHERE id = $1", sid, prefs)
        return prefs

    def _validate_server(payload: dict) -> dict[str, Any]:
        url = str(payload.get("url", "")).strip().rstrip("/")
        if not url.startswith(("http://", "https://")):
            raise HTTPException(400, "URL must start with http:// or https://")
        docker_url = str(payload.get("docker_url") or "").strip().rstrip("/") or None
        if docker_url and not docker_url.startswith(("http://", "https://")):
            raise HTTPException(400, "Docker URL must start with http:// or https://")
        return {"name": str(payload.get("name") or "Unraid").strip()[:60], "url": url,
                "api_key": str(payload.get("api_key") or "").strip(), "verify_ssl": bool(payload.get("verify_ssl")),
                "docker_url": docker_url, "collect_logs": bool(payload.get("collect_logs", True)),
                "enabled": bool(payload.get("enabled", True))}

    @app.post("/api/unraid/servers")
    async def add_unraid(payload: dict = Body(...)):
        v = _validate_server(payload)
        if not v["api_key"]:
            raise HTTPException(400, "API key is required")
        sid = await db.pool().fetchval(
            "INSERT INTO unraid_servers (name, url, api_key, verify_ssl, docker_url, collect_logs, enabled) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id", *{**v, "api_key": crypto.encrypt(v["api_key"])}.values())
        return {"id": sid}

    @app.put("/api/unraid/servers/{sid}")
    async def edit_unraid(sid: int, payload: dict = Body(...)):
        v = _validate_server(payload)
        await db.pool().execute(
            "UPDATE unraid_servers SET name = $2, url = $3, api_key = COALESCE(nullif($4, ''), api_key), verify_ssl = $5, "
            "docker_url = $6, collect_logs = $7, enabled = $8 WHERE id = $1", sid,
            *{**v, "api_key": crypto.encrypt(v["api_key"]) if v["api_key"] else ""}.values())
        return {"ok": True}

    @app.delete("/api/unraid/servers/{sid}")
    async def delete_unraid(sid: int):
        await db.pool().execute("DELETE FROM unraid_servers WHERE id = $1", sid)
        await db.pool().execute("DELETE FROM snapshots WHERE key LIKE $1", f"unraid:{sid}:%")
        return {"ok": True}

    @app.post("/api/unraid/test")
    async def test_unraid(payload: dict = Body(...)):
        v = _validate_server(payload)
        if not v["api_key"] and payload.get("id"):
            v["api_key"] = crypto.decrypt(await db.pool().fetchval("SELECT api_key FROM unraid_servers WHERE id = $1",
                                                                  int(payload["id"])) or "")
        return await unraid_test(v["url"], v["api_key"], v["verify_ssl"], v["docker_url"])

    @app.get("/api/unraid/{sid}")
    async def unraid_overview(sid: int):
        rows = await db.pool().fetch("SELECT key, ts, data FROM snapshots WHERE key LIKE $1", f"unraid:{sid}:%")
        snaps = {r["key"].split(":", 2)[2]: {"ts": r["ts"].isoformat(), "data": r["data"]} for r in rows}
        status = (await db.get_snapshot("unraid_status") or {}).get(str(sid))
        return {"snapshots": snaps, "status": status}

    @app.get("/api/unraid/{sid}/logs")
    async def unraid_logs(sid: int, container: str | None = None, kind: str = "docker", limit: int = Query(300, le=2000),
                          q: str | None = None, hours: float = 24):
        name = await db.pool().fetchval("SELECT name FROM unraid_servers WHERE id = $1", sid)
        args: list[Any] = [name, hours * 3600, limit]
        cond = "source = 'docker'" if kind == "docker" else "source IN ('unraid', 'auth', 'system', 'dhcp', 'vpn')"
        if container:
            args.append(container)
            cond += f" AND program = ${len(args)}"
        if q:
            args.append(f"%{q}%")
            cond += f" AND message ILIKE ${len(args)}"
        rows = await db.pool().fetch(
            f"SELECT ts, program, severity, action, message FROM events WHERE host = $1 AND {cond} "
            f"AND ts > now() - make_interval(secs => $2) ORDER BY ts DESC LIMIT $3", *args)
        return db.records(rows)

    # ------------------------------------------------------- app settings ---
    @app.get("/api/settings")
    async def get_app_settings():
        return app_config.public_view(settings)

    @app.put("/api/settings")
    async def put_app_settings(payload: dict = Body(...)):
        try:
            changed = await app_config.save(settings, payload.get("values") or {})
        except app_config.SettingsError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"ok": True, "changed": changed}

    def _candidate(values: dict) -> Any:
        """Settings copy with the (unsaved) form values; empty secrets fall back to the stored ones."""
        update = {}
        for key, value in (values or {}).items():
            f = app_config.BY_KEY.get(key)
            if f is None or (f.kind == "secret" and not value):
                continue
            try:
                update[key] = value if f.kind == "secret" else app_config._coerce(f, value)
            except app_config.SettingsError as exc:
                raise HTTPException(400, str(exc)) from exc
        return settings.model_copy(update=update)

    @app.post("/api/settings/test/opnsense")
    async def test_opnsense(payload: dict = Body(...)):
        from ..opnsense import ApiError, OPNsenseClient

        cand = _candidate(payload.get("values"))
        if not cand.opnsense_enabled:
            return {"ok": False, "error": "URL, API key and API secret are required"}
        client = OPNsenseClient(cand)
        try:
            info = await client.get("diagnostics/system/systemInformation")
            return {"ok": True, "name": info.get("name"), "versions": info.get("versions")}
        except ApiError as exc:
            hint = " (wrong key/secret?)" if exc.status == 401 else " (user lacks the privilege for this page)" if exc.status == 403 else ""
            return {"ok": False, "error": f"{exc}{hint}"}
        except httpx.HTTPError as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        finally:
            await client.close()

    @app.post("/api/settings/test/unifi")
    async def test_unifi(payload: dict = Body(...)):
        from ..unifi import test_connection

        cand = _candidate(payload.get("values"))
        if not cand.unifi_enabled:
            return {"ok": False, "error": "URL and an API key (or username + password) are required"}
        return await test_connection(cand)

    @app.post("/api/settings/test/ai")
    async def test_ai(payload: dict = Body(...)):
        cand = _candidate(payload.get("values"))
        if not cand.ai_enabled:
            return {"ok": False, "error": "base URL, API key and model are required"}
        body = {"model": cand.ai_model, "max_tokens": 20, "messages": [{"role": "user", "content": "Reply with the single word OK."}]}
        try:
            async with httpx.AsyncClient(base_url=cand.ai_base_url.rstrip("/") + "/", timeout=60,
                                         headers={"Authorization": f"Bearer {cand.ai_api_key}"}) as client:
                r = await client.post("chat/completions", json=body)
            if r.status_code >= 400:
                return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:300]}"}
            return {"ok": True, "reply": (r.json()["choices"][0]["message"].get("content") or "")[:100], "model": cand.ai_model}
        except (httpx.HTTPError, ValueError, KeyError, IndexError) as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    return app
