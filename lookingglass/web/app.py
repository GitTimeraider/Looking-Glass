"""FastAPI web application: dashboards, event search, alerts, reports, system view and the AI chat."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import re
import secrets
import time
from datetime import datetime
import logging
from pathlib import Path
from typing import Any

import httpx
from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from starlette.middleware.sessions import SessionMiddleware

from .. import __version__, app_config, auth, crypto, db, event_filter, optional_sources
from ..ai import Analyst, request_log
from ..config import Settings
from . import asset_version
from ..ingest import STATS
from .. import rollup
from ..cache import ResultCache, ttl_for
from ..dashboards import DASHBOARDS, run_dashboard
from ..reports import build_report, report_mail, run_ai_summary, timeline
from .. import setup_checks, unraid_storage
from ..parsers.common import real_name
from ..unraid import test_connection as unraid_test
from .auth_routes import PUBLIC_PATHS, SETUP_PATHS, current_user
from .auth_routes import register as register_auth

log = logging.getLogger(__name__)
HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(HERE / "templates"))
templates.env.globals["asset_v"] = asset_version()
# (key, menu label, menu group): dashboards sit under their product ("opnsense", "unifi"), "tools" covers every source
DASH_NAV = [(k, v["title"].split(" (")[0], v.get("group", "tools")) for k, v in DASHBOARDS.items()]
templates.env.globals["dashboards"] = DASH_NAV


def dash_nav() -> list[tuple[str, str, str]]:
    """Menu entries of the dashboards; Zenarmor only when it is set up (in-memory flag, optional_sources.py)."""
    return DASH_NAV if optional_sources.zenarmor() else [d for d in DASH_NAV if d[0] != "zenarmor"]


templates.env.globals["dash_nav"] = dash_nav

# alert list orders (?sort=): highest priority first (the default), newest / oldest alert number, latest activity
_PRIO = "array_position(ARRAY['critical','high','medium','low','info'], severity)"
ALERT_SORT = {"priority": f"{_PRIO}, last_seen DESC", "number": "id DESC", "number_asc": "id",
              "recent": f"last_seen DESC, {_PRIO}"}

PAGES = {
    "/": ("dashboard.html", "Overview"),
    "/events": ("events.html", "Events"),
    "/alerts": ("alerts.html", "Alerts"),
    "/system": ("system.html", "OPNsense"),
    "/devices": ("devices.html", "Devices"),
    "/vulns": ("vulns.html", "Vulnerabilities"),
    "/unraid": ("unraid.html", "Unraid"),
    "/unifi": ("unifi.html", "UniFi"),
    "/reports": ("reports.html", "Reports"),
    "/ai": ("ai.html", "AI Analyst"),
    "/setup": ("setup.html", "Setup"),
    "/settings": ("settings.html", "Settings"),
}


_TASKS: set[asyncio.Task] = set()


def _background(coro) -> None:
    """Run a coroutine after the response; keep a reference so it is not garbage collected."""
    task = asyncio.create_task(coro)
    _TASKS.add(task)
    task.add_done_callback(_TASKS.discard)


def create_app(settings: Settings, analyst: Analyst, poller_status: dict[str, Any] | None = None) -> FastAPI:
    templates.env.globals["time_format"] = lambda: settings.time_format  # live setting, read per page
    templates.env.globals["theme_attrs"] = lambda: Markup(  # <html> attributes for the theme (style.css), live as well
        f' data-theme="{escape(settings.theme)}" data-mode="{"light" if settings.theme == "light" else "dark"}" '
        f'data-accent="{escape(settings.accent)}"')
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
                "ai_privacy": settings.ai_privacy,
                "ai_model": settings.ai_model, "opnsense": settings.opnsense_enabled,
                "syslog_port": settings.syslog_udp_port, "user": request.session.get("user"),
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
    # dashboard / Overview results shared by every tab and user for a short while (cache.py)
    results = ResultCache()
    app.state.results = results

    async def overview_counts(hours: float) -> dict[str, Any]:
        """The part of the Overview that counts events (the expensive part): cached."""
        secs = hours * 3600
        # plain counts (from 2 days on from the hourly counts) and the distinct blocked sources apart: in one query
        # count(DISTINCT) FILTER sorts every event of the period (30 days: seconds instead of a fraction)
        counts = ("SELECT coalesce(count(*), 0) total, coalesce(count(*) FILTER (WHERE action IN ('block', 'drop', 'ban')), 0) blocked, "
                  "coalesce(count(*) FILTER (WHERE action = 'login_failed'), 0) login_failed, "
                  "coalesce(count(*) FILTER (WHERE source = 'unbound'), 0) dns, coalesce(count(*) FILTER (WHERE source = 'suricata'), 0) ids "
                  "FROM events WHERE ts > now() - make_interval(secs => $1)")

        async def kpi_counts() -> dict[str, Any]:
            async with db.heavy(), db.pool().acquire() as conn:
                row = await (rollup.fetch(conn, counts, secs) if hours >= rollup.MIN_HOURS else conn.fetch(counts, secs))
            return dict(row[0])

        async def blocked_ips() -> int:
            async with db.heavy(), db.pool().acquire() as conn:
                return await conn.fetchval(
                    "SELECT count(*) FROM (SELECT DISTINCT src_ip FROM events WHERE action IN ('block', 'drop') "
                    "AND src_ip IS NOT NULL AND ts > now() - make_interval(secs => $1)) x", secs)

        kpi, ips, report, tl = await asyncio.gather(kpi_counts(), blocked_ips(), build_report(hours), timeline(hours))
        return {"kpi": db.jsonable({**kpi, "blocked_ips": ips}), "report": report, "timeline": tl}

    @app.get("/api/overview")
    async def overview(hours: float = Query(24, gt=0, le=24 * 90)):
        pool = db.pool()
        counted = await results.get(("overview", hours), ttl_for(hours), lambda: overview_counts(hours))
        kpi = counted["kpi"]
        # open alerts, devices and the system state are cheap and always current
        alerts = await pool.fetch("SELECT severity, count(*) n FROM alerts WHERE status = 'open' GROUP BY 1")
        decisions = await db.get_snapshot("crowdsec_decisions")
        blocklists = await db.get_snapshot("blocklists") or {}
        blocklist_n = ((blocklists.get("crowdsec") or {}) if isinstance(blocklists, dict) else {}).get("size")
        devices = await pool.fetchval("SELECT count(*) FROM devices WHERE last_seen > now() - interval '1 day'")
        report = counted["report"]
        # optional sources: hide their overview cards when their pull is off and they have no data in the period
        has = {r["source"] for r in report.get("totals_by_source") or []}
        enabled = {"suricata": settings.ids_pull, "crowdsec": settings.crowdsec_pull, "qfeeds": settings.qfeeds_pull,
                   "nginx": settings.nginx_pull, "unbound": settings.unbound_query_pull}
        enabled = {k: (v and settings.opnsense_enabled) or k in has for k, v in enabled.items()}
        enabled["zenarmor"] = optional_sources.zenarmor() or "zenarmor" in has
        return {
            "sources": enabled,
            "kpi": {**kpi, "open_alerts": {r["severity"]: r["n"] for r in alerts},
                    "crowdsec_decisions": len(decisions) if isinstance(decisions, list) else None,
                    "crowdsec_blocklist": blocklist_n, "devices": devices},
            "timeline": counted["timeline"],
            "report": report,
            "system": await db.get_snapshot("system"),
            "gateways": await db.get_snapshot("gateways"),
            "ingest": STATS.as_dict(),
        }

    @app.get("/api/events")
    async def events(request: Request, source: str | None = None, ip: str | None = None, src: str | None = None,
                     dst: str | None = None, action: str | None = None,
                     q: str | None = None, hours: float = Query(24, gt=0), limit: int = Query(100, ge=1, le=1000),
                     offset: int = Query(0, ge=0), min_severity: int | None = Query(None, ge=0, le=7),
                     start: str | None = None, end: str | None = None):
        """Event search: the form fields (source, ip / src / dst, sport / dport, action, text, severity, time) and every
        dashboard click-through filter - see event_filter.build."""
        params = {k: v for k, v in request.query_params.items() if k not in ("limit", "offset")}
        params["hours"] = hours
        try:
            where, args = event_filter.build(params)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

        def arg(v: Any) -> str:
            args.append(v)
            return f"${len(args)}"

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
    async def alerts(status: str = "open", hours: float = Query(24 * 30, gt=0), limit: int = Query(500, le=5000),
                     sort: str = "priority"):
        args: list[Any] = [hours * 3600, limit]
        cond = ""
        if status != "all":
            args.append(status.split(","))
            cond = "AND status = ANY($3::text[])"
        rows = await db.pool().fetch(
            f"SELECT id, created_at, last_seen, rule, severity, title, description, host(src_ip) src_ip, host(dst_ip) dst_ip, count, status, close_reason, data "
            f"FROM alerts WHERE last_seen > now() - make_interval(secs => $1) {cond} "
            f"ORDER BY {ALERT_SORT.get(sort, ALERT_SORT['priority'])} LIMIT $2", *args)
        out = db.records(rows)
        # one alert with unexpected stored data (an older version, a hand edit ...) must never fail the whole list:
        # it is logged and shown without the extras
        dict_or_empty = lambda v: v if isinstance(v, dict) else {}  # noqa: E731
        for a in out:
            a["src_name"] = dict_or_empty(dict_or_empty(a.get("data")).get("device")).get("hostname")
        # device name of the source IP: the one stored when the alert was created (the IP may belong to another
        # device by now); only alerts created before the device had a name get its current name
        ips = list({a["src_ip"] for a in out if a.get("src_ip") and not a["src_name"]})
        names = {r["ip"]: r["hostname"] for r in await db.pool().fetch(
            "SELECT DISTINCT ON (x) host(x) ip, hostname FROM devices, unnest(coalesce(ips, '{}'::inet[]) || ip) x "
            "WHERE x = ANY($1::inet[]) AND hostname IS NOT NULL ORDER BY x, mac LIKE 'ip:%', last_seen DESC", ips)} if ips else {}
        # which enabled alert filter (mute) matches each alert - the alerts page offers "Unmute" for those
        from .. import alert_filters

        all_filters = await alert_filters._filters()
        active_ids = {f["id"] for f in all_filters}
        filters = [f for f in all_filters if f["action"] != "severity"]
        comments: dict[int, list[dict[str, Any]]] = {}
        if out:
            for r in await db.pool().fetch("SELECT id, alert_id, created_at, updated_at, author, body FROM alert_comments "
                                           "WHERE alert_id = ANY($1::bigint[]) ORDER BY created_at, id", [a["id"] for a in out]):
                comments.setdefault(r["alert_id"], []).append(db.jsonable(dict(r)))
        for a in out:
            a["comments"] = comments.get(a["id"], [])
            a["src_name"] = a["src_name"] or names.get(a.get("src_ip"))
            a["muted_by"], a["override_active"] = None, False
            try:
                f = next((f for f in filters if alert_filters.matches(f, a["rule"], a["severity"], a["title"], a.get("description") or "",
                                                                     a.get("src_ip"), a.get("dst_ip"),
                                                                     dict_or_empty(a.get("data")).get("ports"))), None)
                a["muted_by"] = {"id": f["id"], "name": f.get("name") or f"filter #{f['id']}", "action": f["action"]} if f else None
                ov = dict_or_empty(a.get("data")).get("severity_override")
                a["override_active"] = isinstance(ov, dict) and dict_or_empty(ov.get("filter")).get("id") in active_ids
            except Exception:  # noqa: BLE001
                log.exception("alerts list: alert #%s (%s, severity %r) could not be checked against the alert filters",
                              a.get("id"), a.get("rule"), a.get("severity"))
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
            "INSERT INTO alert_filters (name, enabled, max_severity, rules, contains, networks, action, match_mode, text_mode, "
            "set_severity, src_ports, dst_ports) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *", *f.values())
        af.invalidate()
        return _filter_out(row)

    @app.put("/api/alert-filters/{fid}")
    async def edit_filter(fid: int, payload: dict = Body(...)):
        f = _clean_filter(payload)
        row = await db.pool().fetchrow(
            "UPDATE alert_filters SET name = $2, enabled = $3, max_severity = $4, rules = $5, contains = $6, networks = $7, "
            "action = $8, match_mode = $9, text_mode = $10, set_severity = $11, src_ports = $12, dst_ports = $13 "
            "WHERE id = $1 RETURNING *", fid, *f.values())
        if not row:
            raise HTTPException(404)
        af.invalidate()
        return _filter_out(row)

    @app.delete("/api/alert-filters/{fid}")
    async def delete_filter(fid: int):
        await db.pool().execute("DELETE FROM alert_filters WHERE id = $1", fid)
        # a removed severity rule: open / acknowledged alerts it changed get their own severity back
        restored = await db.pool().execute(
            "UPDATE alerts SET severity = data->'severity_override'->>'from', data = data - 'severity_override' "
            "WHERE status <> 'closed' AND data ? 'severity_override' "
            "AND (data->'severity_override'->'filter'->>'id') = $1::text", str(fid))
        af.invalidate()
        return {"ok": True, "restored": int(restored.split()[-1])}

    async def _matching_alerts(f: dict[str, Any], statuses: tuple[str, ...]) -> list[dict[str, Any]]:
        rows = await db.pool().fetch(
            "SELECT id, rule, severity, title, coalesce(description, '') description, host(src_ip) src_ip, host(dst_ip) dst_ip, "
            "status, last_seen, data->'ports' AS ports FROM alerts WHERE last_seen > now() - interval '30 days' "
            "AND status = ANY($1::text[]) ORDER BY last_seen DESC LIMIT 20000", list(statuses))
        return [dict(r) for r in rows if af.matches(f, r["rule"], r["severity"], r["title"], r["description"], r["src_ip"],
                                                    r["dst_ip"], r["ports"])]

    @app.post("/api/alert-filters/preview")
    async def preview_filter(payload: dict = Body(...)):
        """Which alerts of the last 30 days this filter would have caught."""
        f = _clean_filter(payload)
        hits = await _matching_alerts(f, ("open", "acknowledged", "closed"))
        open_n = sum(1 for h in hits if h["status"] != "closed")
        return {"total": len(hits), "open": open_n,
                "sample": db.jsonable([{k: h[k] for k in ("id", "severity", "rule", "title", "status", "last_seen")} for h in hits[:15]])}

    # ---- email notification rules
    from .. import notify

    _NR_COLS = ("name", "enabled", "recipients", "min_severity", "rules", "contains", "networks", "match_mode", "text_mode",
                "on_escalation", "min_interval")

    def _clean_nrule(payload: dict) -> dict[str, Any]:
        try:
            return notify.clean(payload)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/api/notification-rules")
    async def list_nrules():
        rows = await db.pool().fetch("SELECT * FROM notification_rules ORDER BY id")
        return {"rules": [_filter_out(r) for r in rows], "smtp": settings.smtp_enabled}

    @app.post("/api/notification-rules")
    async def add_nrule(payload: dict = Body(...)):
        n = _clean_nrule(payload)
        row = await db.pool().fetchrow(
            f"INSERT INTO notification_rules ({', '.join(_NR_COLS)}) VALUES ({', '.join(f'${i + 1}' for i in range(len(_NR_COLS)))}) "
            "RETURNING *", *(n[c] for c in _NR_COLS))
        return _filter_out(row)

    @app.put("/api/notification-rules/{rid}")
    async def edit_nrule(rid: int, payload: dict = Body(...)):
        n = _clean_nrule(payload)
        sets = ", ".join(f"{c} = ${i + 2}" for i, c in enumerate(_NR_COLS))
        row = await db.pool().fetchrow(f"UPDATE notification_rules SET {sets}, last_error = NULL WHERE id = $1 RETURNING *",
                                       rid, *(n[c] for c in _NR_COLS))
        if not row:
            raise HTTPException(404)
        return _filter_out(row)

    @app.delete("/api/notification-rules/{rid}")
    async def delete_nrule(rid: int):
        await db.pool().execute("DELETE FROM notification_rules WHERE id = $1", rid)
        return {"ok": True}

    @app.post("/api/notification-rules/preview")
    async def preview_nrule(payload: dict = Body(...)):
        """How many alerts of the last 7 days this rule would have mailed."""
        n = _clean_nrule(payload)
        rows = await db.pool().fetch(
            "SELECT id, rule, severity, title, coalesce(description, '') description, host(src_ip) src_ip, host(dst_ip) dst_ip, "
            "last_seen FROM alerts WHERE last_seen > now() - interval '7 days' ORDER BY last_seen DESC LIMIT 20000")
        hits = [r for r in rows if af.matches(n, r["rule"], r["severity"], r["title"], r["description"], r["src_ip"], r["dst_ip"])]
        return {"total": len(hits), "sample": db.jsonable([{k: h[k] for k in ("id", "severity", "rule", "title", "last_seen")}
                                                           for h in hits[:10]])}

    @app.post("/api/notification-rules/{rid}/test")
    async def test_nrule(rid: int):
        """Mail the newest matching alert (or an example) to this rule's recipients."""
        row = await db.pool().fetchrow("SELECT * FROM notification_rules WHERE id = $1", rid)
        if not row:
            raise HTTPException(404)
        rule = dict(row)
        rows = await db.pool().fetch(
            "SELECT id, rule, severity, title, coalesce(description, '') description, host(src_ip) src_ip, host(dst_ip) dst_ip, "
            "data, last_seen FROM alerts ORDER BY last_seen DESC LIMIT 5000")
        hit = next((dict(r) for r in rows if af.matches(rule, r["rule"], r["severity"], r["title"], r["description"],
                                                        r["src_ip"], r["dst_ip"])), None)
        example = hit or {"id": 0, "rule": "example", "severity": rule.get("min_severity") or "high",
                          "title": "Example alert (no alert matched this rule yet)", "data": {}}
        subject, text, body = notify.compose(rule, [example], settings.mail_link_url or settings.public_url, settings)
        try:
            await notify.send(settings, notify.recipients(rule["recipients"]), "[TEST] " + subject, text, body)
        except (notify.MailError, ValueError) as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "example": hit is None}

    @app.post("/api/alerts/{aid}/restore-severity")
    async def restore_severity(aid: int):
        """Undo a severity change on one alert (e.g. after its rule was paused): back to the severity it had."""
        row = await db.pool().fetchrow("SELECT data FROM alerts WHERE id = $1", aid)
        ov = ((row or {}).get("data") or {}).get("severity_override") if row else None
        if not ov:
            raise HTTPException(404, "this alert has no changed severity")
        await db.pool().execute("UPDATE alerts SET severity = $2, data = data - 'severity_override' WHERE id = $1", aid, ov["from"])
        return {"ok": True, "severity": ov["from"]}

    @app.post("/api/alert-filters/{fid}/apply")
    async def apply_filter(fid: int):
        """Apply a filter to the open / acknowledged alerts it matches: close them, or change their severity."""
        row = await db.pool().fetchrow("SELECT * FROM alert_filters WHERE id = $1", fid)
        if not row:
            raise HTTPException(404)
        f = dict(row)
        hits = await _matching_alerts(f, ("open", "acknowledged"))
        if f["action"] == "severity":
            for h in hits:
                if h["severity"] == f["set_severity"]:
                    continue
                note = {"from": h["severity"], "to": f["set_severity"], "filter": {"id": f["id"], "name": f.get("name")}}
                await db.pool().execute(
                    "UPDATE alerts SET severity = $2, data = coalesce(data, '{}'::jsonb) || jsonb_build_object('severity_override', $3::jsonb) "
                    "WHERE id = $1", h["id"], f["set_severity"], note)
            return {"changed": len(hits), "closed": 0}
        ids = [h["id"] for h in hits]
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

    @app.post("/api/alerts/delete")
    async def delete_alerts(payload: dict = Body(...)):
        """Permanently delete CLOSED alerts: the selected ones ("ids") or all of them ("all_closed"). "dry_run" only
        counts. Open / acknowledged alerts are never deleted here."""
        if payload.get("all_closed"):
            where, args = "status = 'closed'", []
        else:
            ids = [int(i) for i in payload.get("ids") or []]
            if not ids:
                raise HTTPException(400, "nothing selected")
            where, args = "status = 'closed' AND id = ANY($1::bigint[])", [ids]
        if payload.get("dry_run"):
            return {"count": await db.pool().fetchval(f"SELECT count(*) FROM alerts WHERE {where}", *args)}
        async with db.pool().acquire() as conn, conn.transaction():
            ids = [r["id"] for r in await conn.fetch(f"DELETE FROM alerts WHERE {where} RETURNING id", *args)]
            await conn.execute("DELETE FROM alert_comments WHERE alert_id = ANY($1::bigint[])", ids)
        n = len(ids)
        log.info("deleted %d closed alert(s)", n)
        return {"deleted": n}

    @app.post("/api/alerts/status")
    async def set_alert_status(request: Request, payload: dict = Body(...)):
        """Change the status of alerts; an optional "comment" is added to each of them (e.g. why it was closed)."""
        ids = [int(i) for i in payload.get("ids", [])]
        status = payload.get("status")
        if status not in ("open", "acknowledged", "closed"):
            raise HTTPException(400, "invalid status")
        reason = payload.get("reason") if status == "closed" else None
        if reason not in (None, "false_positive", "resolved"):
            raise HTTPException(400, "invalid reason")
        comment = _comment_text(payload.get("comment"), required=False)
        async with db.pool().acquire() as conn, conn.transaction():
            await conn.execute("UPDATE alerts SET status = $1, close_reason = $3 WHERE id = ANY($2::bigint[])",
                               status, ids, reason)
            if comment:
                await conn.execute("INSERT INTO alert_comments (alert_id, author, body) SELECT id, $2, $3 FROM alerts "
                                   "WHERE id = ANY($1::bigint[])", ids, _author(request), comment)
        return {"ok": True, "updated": len(ids)}

    # ----------------------------------------------------- alert comments ---
    # notes on an alert in any status (why it was closed / a false positive, extra context); the AI analyst reads them
    COMMENT_MAX = 5000

    def _comment_text(value: Any, required: bool = True) -> str:
        text = str(value or "").strip()
        if required and not text:
            raise HTTPException(400, "The comment is empty.")
        if len(text) > COMMENT_MAX:
            raise HTTPException(400, f"A comment can be at most {COMMENT_MAX} characters.")
        return text

    def _author(request: Request) -> str | None:
        user = getattr(request.state, "user", None)  # set by the login guard for every API call
        return user.get("username") if isinstance(user, dict) else None

    @app.post("/api/alerts/{aid}/comments")
    async def add_alert_comment(aid: int, request: Request, payload: dict = Body(...)):
        text = _comment_text(payload.get("body"))
        row = await db.pool().fetchrow(
            "INSERT INTO alert_comments (alert_id, author, body) SELECT id, $2, $3 FROM alerts WHERE id = $1 "
            "RETURNING id, alert_id, created_at, updated_at, author, body", aid, _author(request), text)
        if not row:
            raise HTTPException(404, f"Alert #{aid} does not exist (any more).")
        return db.jsonable(dict(row))

    @app.put("/api/alerts/comments/{cid}")
    async def edit_alert_comment(cid: int, payload: dict = Body(...)):
        row = await db.pool().fetchrow(
            "UPDATE alert_comments SET body = $2, updated_at = now() WHERE id = $1 "
            "RETURNING id, alert_id, created_at, updated_at, author, body", cid, _comment_text(payload.get("body")))
        if not row:
            raise HTTPException(404, "That comment does not exist (any more).")
        return db.jsonable(dict(row))

    @app.delete("/api/alerts/comments/{cid}")
    async def delete_alert_comment(cid: int):
        res = await db.pool().execute("DELETE FROM alert_comments WHERE id = $1", cid)
        if res.endswith(" 0"):
            raise HTTPException(404, "That comment does not exist (any more).")
        return {"ok": True}

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
        "events": ("events, event_rollup", "Logs / events"),
        "alerts": ("alerts, alert_comments", "Alerts (and your comments on them)"),
        "metrics": ("metrics", "Graphs (metrics history)"),
        "reports": ("reports", "Reports"),
        "ai_chats": ("ai_chats, ai_pseudonyms", "AI analyst conversations (and the privacy mode pseudonyms)"),
        "devices": ("devices", "Device list (incl. names, notes and trusted marks you set)"),
        "behavior": ("device_profile, device_hourly, hourly_stats, risk_scores, seen_domains",
                     "Learned behaviour (device profiles, hourly baselines, risk scores, seen domains)"),
    }

    @app.get("/api/admin/data")
    async def data_sizes():
        out = []
        for key, (table, label) in PURGE.items():
            tables = [t.strip() for t in table.split(",")]
            row = await db.pool().fetchrow(
                "SELECT pg_size_pretty(sum(pg_total_relation_size(t::regclass))) size, "
                "(SELECT sum(greatest(reltuples, 0))::bigint FROM pg_class WHERE relname = ANY($1::text[])) approx "
                "FROM unnest($1::text[]) t", tables)
            exact = sum([await db.pool().fetchval(f"SELECT count(*) FROM {t}") for t in tables]) \
                if (row["approx"] or 0) < 100000 else None
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
        results.clear()
        if "ai_chats" in parts:
            from .. import privacy
            privacy.invalidate()
        log.warning("user %s deleted collected data: %s", user["username"], ", ".join(parts))
        return {"ok": True, "deleted": parts}

    @app.get("/api/setup/checks")
    async def setup_status():
        return await setup_checks.run(settings)

    # ----------------------------------------------------------- reports ---
    @app.get("/api/reports")
    async def list_reports():
        rows = await db.pool().fetch("SELECT id, created_at, period_h, title, ai_summary IS NOT NULL has_ai, ai_state FROM reports "
                                     "ORDER BY id DESC LIMIT 200")
        return db.records(rows)

    @app.post("/api/reports")
    async def create_report(payload: dict = Body(...)):
        hours = int(payload.get("hours", 24))
        if hours <= 0 or hours > 24 * 90:
            raise HTTPException(400, "hours out of range")
        data = await build_report(hours)
        ai = bool(payload.get("ai") and settings.ai_enabled)
        label = {24: "Daily", 168: "Weekly", 720: "Monthly"}.get(hours, f"{hours}h")
        rid = await db.pool().fetchval(
            "INSERT INTO reports (period_h, title, data, ai_state) VALUES ($1, $2, $3, $4) RETURNING id",
            hours, f"{label} security report", data, "running" if ai else None)
        if ai:  # the AI analysis takes minutes: in the background, the report page shows its progress
            _background(run_ai_summary(analyst, rid))
        return {"id": rid}

    @app.post("/api/reports/{report_id}/ai")
    async def retry_report_ai(report_id: int):
        if not settings.ai_enabled:
            raise HTTPException(400, "AI is not configured (Settings › AI analyst)")
        state = await db.pool().fetchval("SELECT ai_state FROM reports WHERE id = $1", report_id)
        if state == "running":
            return {"ok": True, "state": "running"}
        await db.pool().execute("UPDATE reports SET ai_state = 'running', ai_error = NULL WHERE id = $1", report_id)
        _background(run_ai_summary(analyst, report_id))
        return {"ok": True, "state": "running"}

    @app.post("/api/reports/{report_id}/mail")
    async def mail_report(report_id: int, payload: dict = Body(default={})):
        """Mail a report now - to the given addresses, else Settings › Reports › Email the report to, else the sender."""
        if not settings.smtp_enabled:
            raise HTTPException(400, "No mail server set up (Settings › Email & notifications)")
        try:
            to = (notify.recipients(payload.get("to")) or notify.recipients(settings.report_mail_to)
                  or notify.recipients(settings.smtp_from))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        mail = await report_mail(report_id, settings.mail_link_url or settings.public_url)
        if not mail:
            raise HTTPException(404, "no such report")
        try:
            await notify.send(settings, to, *mail)
        except notify.MailError as exc:
            raise HTTPException(502, f"Sending failed: {exc}") from exc
        return {"ok": True, "to": to}

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

    @app.get("/api/ai/chats/{chat_id}/sent")
    async def chat_as_sent(chat_id: int):
        """A conversation exactly as the AI receives it with the next question (AI Analyst › What the AI sees): system
        instructions, questions, the AI's tool calls, the data returned to it and its answers - in privacy mode with
        the pseudonyms, each one paired with the real value it stands for."""
        from .. import privacy
        from ..ai import TOOLS
        row = await db.pool().fetchrow("SELECT messages FROM ai_chats WHERE id = $1", chat_id)
        if not row:
            raise HTTPException(404, "This chat does not exist (any more).")
        priv = await privacy.session(settings) if settings.ai_privacy else None

        async def parts(text: Any) -> list[tuple[str, str | None]]:
            text = text if isinstance(text, str) else ""
            return await priv.hide_parts(text) if priv else ([(text, None)] if text else [])

        def args_text(arguments: Any) -> str:
            # written out the way it is sent (names as they are, not \u escaped)
            try:
                return json.dumps(json.loads(arguments or "{}"), ensure_ascii=False)
            except (TypeError, ValueError):
                return str(arguments or "")

        out = []
        for m in row["messages"] if isinstance(row["messages"], list) else []:
            item: dict[str, Any] = {"role": m.get("role"), "parts": await parts(m.get("content"))}
            if m.get("tool_calls"):
                item["tool_calls"] = [{"name": (c.get("function") or {}).get("name"),
                                       "parts": await parts(args_text((c.get("function") or {}).get("arguments")))}
                                      for c in m["tool_calls"] if isinstance(c, dict)]
            out.append(item)
        return {"privacy": priv is not None, "names": priv.known_names() if priv else {},
                "model": settings.ai_model, "base_url": settings.ai_base_url,
                "system": await analyst.system_message(priv is not None),
                "tools": [t["function"]["name"] for t in TOOLS], "messages": out}

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

    ai_jobs: dict[str, dict[str, Any]] = {}

    async def run_ai_message(job_id: str, chat_id: int | None, history: list[dict[str, Any]], text: str) -> None:
        job = ai_jobs[job_id]
        try:
            new = await analyst.chat(history, text)
            messages = history + new
            if chat_id:
                await db.pool().execute("UPDATE ai_chats SET messages = $2, updated_at = now() WHERE id = $1", chat_id, messages)
            else:
                chat_id = await db.pool().fetchval("INSERT INTO ai_chats (title, messages) VALUES ($1, $2) RETURNING id",
                                                   text[:80], messages)
            job.update(status="done", chat_id=chat_id, messages=new)
        except Exception as exc:  # noqa: BLE001
            log.exception("AI request failed")
            job.update(status="error", error=f"AI request failed: {exc}")
        job["finished"] = time.time()

    @app.post("/api/ai/message")
    async def ai_message(payload: dict = Body(...)):
        """Starts the analysis and answers at once: an agent run takes minutes, longer than reverse proxies in front of
        Looking Glass wait for a response (nginx: 60 s). The page polls /api/ai/jobs/{job} for the result."""
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
        for old_id in [k for k, j in ai_jobs.items() if j.get("finished") and j["finished"] < time.time() - 3600]:
            del ai_jobs[old_id]
        job_id = secrets.token_urlsafe(12)
        ai_jobs[job_id] = {"status": "running", "started": time.time()}
        _background(run_ai_message(job_id, int(chat_id) if chat_id else None, history, text))
        return {"job": job_id}

    @app.get("/api/ai/jobs/{job_id}")
    async def ai_job(job_id: str):
        job = ai_jobs.get(job_id)
        if not job:
            raise HTTPException(404, "AI job not found (Looking Glass restarted?) - send the question again")
        if job["status"] == "error":
            raise HTTPException(502, job["error"])
        if job["status"] == "done":
            return {"done": True, "chat_id": job["chat_id"], "messages": job["messages"]}
        return {"done": False, "seconds": int(time.time() - job["started"])}


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
        return await results.get(("dash", name, hours), ttl_for(hours), lambda: dash_compute(name, hours))

    async def dash_compute(name: str, hours: float) -> dict[str, Any]:
        # an optional source whose pull is off and that has no data in the period: its tiles and panels are hidden
        pulls = {"suricata": settings.ids_pull, "crowdsec": settings.crowdsec_pull, "qfeeds": settings.qfeeds_pull}
        has = {r["s"] for r in await db.pool().fetch(
            "SELECT s FROM unnest($1::text[]) s WHERE EXISTS (SELECT 1 FROM events WHERE source = s "
            "AND ts > now() - make_interval(secs => $2))", list(pulls), hours * 3600)}
        off = {k for k, on in pulls.items() if not (on and settings.opnsense_enabled) and k not in has}
        return await run_dashboard(name, hours, off)

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
            if r["v"] is not None and math.isfinite(r["v"]):  # NaN / inf cannot be sent as JSON
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
            "SELECT d.mac, d.hwaddr, host(d.ip) ip, d.hostname, d.name_source, d.vendor, d.interface, d.sources, d.lease_type, d.lease_expires, "
            "d.online, d.trusted, d.notes, d.first_seen, d.last_seen, d.conn_type, d.conn_where, d.conn_signal, d.limits, "
            "coalesce((d.limits->>'risk_threshold')::int, $2) risk_threshold, "
            "(SELECT count(*) FROM events e WHERE e.src_ip = ANY(d.all_ips) AND e.ts > now() - make_interval(secs => $1)) events, "
            "(SELECT count(*) FROM events e WHERE e.src_ip = ANY(d.all_ips) AND e.action = 'block' AND e.ts > now() - make_interval(secs => $1)) blocked, "
            "(SELECT count(*) FROM events e WHERE e.src_ip = ANY(d.all_ips) AND e.source = 'unbound' AND e.ts > now() - make_interval(secs => $1)) dns, "
            "(SELECT count(*) FROM alerts a WHERE (a.src_ip = ANY(d.all_ips) OR a.dst_ip = ANY(d.all_ips)) AND a.status = 'open') alerts, "
            "(SELECT round(r.score::numeric, 0) FROM risk_scores r WHERE r.entity = host(d.ip)) risk, "
            "(SELECT count(*) FROM device_profile p WHERE p.key = d.mac) learned, "
            "(SELECT array_agg(host(x)) FROM unnest(d.ips) x WHERE x IS DISTINCT FROM d.ip) other_ips "
            "FROM (SELECT *, coalesce(nullif(ips, '{}'), ARRAY[ip]) all_ips FROM devices) d "
            "ORDER BY d.online DESC, d.last_seen DESC LIMIT 3000", hours * 3600, settings.risk_threshold)
        return db.records(rows)

    @app.get("/api/devices/limits")
    async def device_limit_defaults():
        """The global values a device without its own limits uses (Settings › Behaviour & ML)."""
        return {"volume_factor": settings.behavior_volume_factor if settings.behavior_enabled else 0,
                "ml_sensitivity": settings.anomaly_ml_sensitivity
                if settings.behavior_enabled and settings.anomaly_ml_enabled else "off",
                "risk_threshold": settings.risk_threshold if settings.risk_enabled else 0,
                "behavior_enabled": settings.behavior_enabled, "risk_enabled": settings.risk_enabled}

    @app.get("/api/devices/{mac}/profile")
    async def device_profile(mac: str):
        """What Looking Glass learned as normal for this device (Settings › Behaviour & ML)."""
        pool = db.pool()
        ip = await pool.fetchval("SELECT host(ip) FROM devices WHERE mac = $1", mac.lower())
        keys = [k for k in (mac.lower(), ip) if k]
        rows = await pool.fetch("SELECT kind, value, first_seen, last_seen, hits FROM device_profile WHERE key = ANY($1::text[]) "
                                "ORDER BY kind, hits DESC", keys)
        risk = await pool.fetchrow("SELECT score, parts, updated FROM risk_scores WHERE entity = $1", ip) if ip else None
        out: dict[str, list] = {}
        for r in rows:
            out.setdefault(r["kind"], []).append(db.jsonable(dict(r)))
        since = min((r["first_seen"] for r in rows), default=None)
        return {"mac": mac.lower(), "ip": ip, "since": since.isoformat() if since else None, "profile": out,
                "risk": db.jsonable(dict(risk)) if risk else None}

    @app.delete("/api/devices/{mac}/profile")
    async def forget_profile(mac: str, kind: str | None = None):
        """Forget the learned behaviour (all, or one kind): the device is learned again from scratch."""
        pool = db.pool()
        ip = await pool.fetchval("SELECT host(ip) FROM devices WHERE mac = $1", mac.lower())
        keys = [k for k in (mac.lower(), ip) if k]
        if kind:
            await pool.execute("DELETE FROM device_profile WHERE key = ANY($1::text[]) AND kind = $2", keys, kind)
        else:
            await pool.execute("DELETE FROM device_profile WHERE key = ANY($1::text[])", keys)
            await pool.execute("DELETE FROM device_hourly WHERE key = ANY($1::text[])", keys)
        return {"ok": True}

    @app.get("/api/risk")
    async def risk_list(limit: int = Query(50, ge=1, le=500)):
        rows = await db.pool().fetch(
            "SELECT r.entity, round(r.score::numeric, 1) score, r.parts, r.updated, d.hostname, d.mac, "
            "coalesce((d.limits->>'risk_threshold')::int, $2) threshold FROM risk_scores r "
            "LEFT JOIN devices d ON host(d.ip) = r.entity ORDER BY r.score DESC LIMIT $1", limit, settings.risk_threshold)
        return {"threshold": settings.risk_threshold, "rows": db.records(rows)}

    @app.get("/api/intel/status")
    async def intel_status():
        from ..intel import FEEDS
        st = await db.kv_get("intel:status", {}) or {}
        counts = {r["feed"]: r["n"] for r in await db.pool().fetch("SELECT feed, count(*) n FROM intel_indicators GROUP BY 1")}
        nod = await db.pool().fetchrow("SELECT count(*) n, count(*) FILTER (WHERE first_seen > now() - interval '1 day') new "
                                       "FROM seen_domains")
        return {"feeds": [{"feed": k, "label": f["label"], **(st.get(k) or {}), "count": counts.get(k, 0)}
                          for k, f in FEEDS.items()],
                "seen_domains": dict(nod) if nod else {}, "exposure": await db.kv_get("exposure:status")}

    @app.post("/api/intel/update")
    async def intel_update():
        from ..intel import Intel
        await Intel(settings).update(force=True)
        return await intel_status()

    # --------------------------------------------- container vulnerabilities ---
    # a finding the user closed (vuln_closed): by its id or an alias, its source package (else package) and the image
    # repository or every image ('')
    not_closed = ("NOT EXISTS (SELECT 1 FROM vuln_closed c WHERE (c.vuln = f.vuln OR c.vuln = ANY(f.aliases)) "
                  "AND c.grp = coalesce(nullif(f.upstream, ''), f.package) AND c.repo IN ('', i.repo))")

    # listed on the page: from 'Minimum CVSS score to show' (findings that meet the alert rules always); your
    # exceptions are always listed under Exceptions
    shown = "(f.shown OR f.ignored IS NOT NULL)"

    async def _vulns_reevaluate() -> None:
        """Ask the scanner to judge the stored findings again (alerts follow within ~20 s), without a new scan."""
        await db.kv_set("vulnscan:reevaluate", {"at": time.time()})
        scanner = getattr(app.state, "vulnscan", None)
        if scanner is not None:
            scanner.wake.set()

    @app.get("/api/vulns")
    async def vulns_overview():
        rows = await db.pool().fetch(
            # distinct vulnerabilities: one CVE in a source package is one finding, however many packages it built;
            # findings you closed, and those below 'Minimum CVSS score to show', do not count
            "SELECT i.*, count(DISTINCT f.vuln) total, count(DISTINCT f.vuln) FILTER (WHERE f.alerted) alerted, "
            "count(DISTINCT f.vuln) FILTER (WHERE f.kev AND f.ignored IS NULL) kev, "
            "count(DISTINCT f.vuln) FILTER (WHERE f.ignored IS NOT NULL) ignored_n, "
            "max(f.cvss) FILTER (WHERE f.ignored IS NULL) max_cvss, "
            "count(DISTINCT f.vuln) FILTER (WHERE coalesce(f.cvss, 0) >= 9 AND f.ignored IS NULL) crit, "
            "count(DISTINCT f.vuln) FILTER (WHERE f.cvss >= 7 AND f.cvss < 9 AND f.ignored IS NULL) high "
            f"FROM vuln_images i LEFT JOIN vuln_findings f ON f.image_key = i.key AND {not_closed} AND {shown} "
            "GROUP BY i.key ORDER BY alerted DESC, i.image")
        kev = await db.kv_get("vulnscan:kev", []) or []
        closed_n = await db.pool().fetchval("SELECT count(*) FROM vuln_closed")
        hidden = await db.pool().fetch(
            "SELECT coalesce(f.hidden_why, 'hidden') why, count(DISTINCT (f.image_key, f.vuln)) n FROM vuln_findings f "
            f"JOIN vuln_images i ON i.key = f.image_key WHERE {not_closed} AND NOT {shown} GROUP BY 1 ORDER BY 2 DESC")
        hidden_n = await db.pool().fetchval(
            "SELECT count(*) FROM (SELECT DISTINCT f.image_key, f.vuln FROM vuln_findings f JOIN vuln_images i "
            f"ON i.key = f.image_key WHERE {not_closed} AND NOT {shown}) x")
        return {"enabled": settings.vuln_scan_enabled, "status": await db.kv_get("vulnscan:status", {}) or {},
                "queued": await db.kv_get("vulnscan:request"),  # Check now pressed, the scanner has not picked it up yet
                "now": time.time(),
                "images": db.records(rows), "kev_count": len(kev), "closed_count": closed_n, "hidden_count": hidden_n,
                "hidden": {r["why"]: r["n"] for r in hidden},
                "policy": {"min_cvss": settings.vuln_min_cvss, "kev_always": settings.vuln_kev_always,
                           "epss_min": settings.vuln_epss_min, "only_fixed": settings.vuln_only_fixed,
                           "alerts": settings.vuln_alerts, "show_min_cvss": settings.vuln_show_min_cvss}}

    @app.get("/api/vulns/findings")
    async def vulns_findings(image: str | None = None, show: str = "all", q: str | None = None,
                             limit: int = Query(1000, ge=1, le=10000)):
        if show == "closed":
            return await vulns_closed_list()
        cond, args = [not_closed, shown], []
        if image:
            args.append(image)
            cond.append(f"f.image_key = ${len(args)}")
        if show == "alerted":
            cond.append("f.alerted")
        elif show == "kev":
            cond.append("f.kev")
        elif show == "ignored":
            cond.append("f.ignored IS NOT NULL")
        elif show == "fixable":
            cond.append("(f.fix_state = 'fixed' OR cardinality(f.fix_versions) > 0)")
        if q:
            args.append(f"%{q}%")
            cond.append(f"(f.vuln ILIKE ${len(args)} OR f.package ILIKE ${len(args)} OR f.upstream ILIKE ${len(args)} "
                        f"OR array_to_string(f.aliases, ' ') "
                        f"ILIKE ${len(args)} OR i.image ILIKE ${len(args)})")
        from ..vulnscan import group_findings
        rows = await db.pool().fetch(
            "SELECT f.*, i.image, i.repo, i.containers FROM vuln_findings f JOIN vuln_images i ON i.key = f.image_key "
            f"WHERE {' AND '.join(cond)} ORDER BY f.kev DESC, f.cvss DESC NULLS LAST, f.epss DESC NULLS LAST, f.vuln, f.package "
            f"LIMIT 50000", *args)
        return group_findings(db.records(rows))[:limit]

    async def vulns_closed_list() -> list[dict[str, Any]]:
        """Your closed findings, with the images they currently hide a finding in."""
        rows = db.records(await db.pool().fetch(
            "SELECT c.*, (SELECT array_agg(DISTINCT i.image ORDER BY i.image) FROM vuln_findings f JOIN vuln_images i "
            "ON i.key = f.image_key WHERE (c.vuln = f.vuln OR c.vuln = ANY(f.aliases)) "
            "AND c.grp = coalesce(nullif(f.upstream, ''), f.package) AND c.repo IN ('', i.repo)) images "
            "FROM vuln_closed c ORDER BY c.closed_at DESC"))
        return rows

    @app.post("/api/vulns/close")
    async def vulns_close(request: Request, payload: dict = Body(...)):
        """Close findings: [{vuln, group, repo}], scope 'image' (that image repository) or 'all' (every image)."""
        items = payload.get("items") or []
        if not isinstance(items, list) or not items:
            raise HTTPException(400, "Select the findings to close first.")
        if len(items) > 5000:
            raise HTTPException(400, "At most 5000 findings at once.")
        everywhere = payload.get("scope") == "all"
        note = str(payload.get("note") or "").strip()[:500] or None
        rows = set()
        for it in items:
            vuln, grp = str((it or {}).get("vuln") or "").strip(), str((it or {}).get("group") or "").strip()
            repo = "" if everywhere else str((it or {}).get("repo") or "").strip()
            if not vuln or not grp or (not everywhere and not repo):
                raise HTTPException(400, "Each finding needs its vulnerability, package and image.")
            rows.add((vuln[:200], grp[:300], repo[:500]))
        await db.pool().executemany(
            "INSERT INTO vuln_closed (vuln, grp, repo, note, closed_by) VALUES ($1, $2, $3, $4, $5) "
            "ON CONFLICT (vuln, grp, repo) DO UPDATE SET note = coalesce(EXCLUDED.note, vuln_closed.note), "
            "closed_by = EXCLUDED.closed_by, closed_at = now()",
            [(*r, note, _author(request)) for r in sorted(rows)])
        await _vulns_reevaluate()
        return {"ok": True, "closed": len(rows)}

    @app.post("/api/vulns/reopen")
    async def vulns_reopen(payload: dict = Body(...)):
        items = payload.get("items") or []
        if not isinstance(items, list) or not items:
            raise HTTPException(400, "Select the closed findings to reopen first.")
        keys = [(str(i.get("vuln") or ""), str(i.get("grp") or ""), str(i.get("repo") or "")) for i in items
                if isinstance(i, dict)]
        await db.pool().executemany("DELETE FROM vuln_closed WHERE vuln = $1 AND grp = $2 AND repo = $3", keys)
        await _vulns_reevaluate()
        return {"ok": True, "reopened": len(keys)}

    @app.post("/api/vulns/scan")
    async def vulns_scan(payload: dict = Body(default={})):
        if not settings.vuln_scan_enabled:
            raise HTTPException(400, "Switch scanning on first: Settings › Container vulnerabilities")
        await db.kv_set("vulnscan:request", {"at": time.time(), "rebuild": bool(payload.get("rebuild"))})
        scanner = getattr(app.state, "vulnscan", None)
        if scanner is not None:
            scanner.wake.set()
        return {"ok": True}

    @app.post("/api/vulns/test-sources")
    async def vulns_test_sources(payload: dict = Body(default={})):
        from ..vulnscan import test_sources
        try:
            return await test_sources(settings, payload.get("text"))
        except ValueError as exc:
            raise HTTPException(400, f"Sources: {exc}") from exc

    @app.get("/api/feedback/suggestions")
    async def feedback_suggestions():
        from ..behavior import Behavior
        if settings.feedback_mode != "suggest":
            return {"suggestions": []}
        return {"suggestions": await Behavior(settings, lambda ip: False).feedback()}

    @app.post("/api/feedback/dismiss")
    async def feedback_dismiss(payload: dict = Body(...)):
        dismissed = list(await db.kv_get("feedback:dismissed", []) or [])
        if payload.get("id") and payload["id"] not in dismissed:
            dismissed.append(str(payload["id"]))
        await db.kv_set("feedback:dismissed", dismissed[-500:])
        return {"ok": True}

    @app.post("/api/devices/{mac}")
    async def update_device(mac: str, payload: dict = Body(...)):
        pool = db.pool()
        if "limits" in payload:
            # the device's own alert limits (traffic spike, machine learning, risk score); {} = global settings again
            from ..behavior import clean_limits
            try:
                limits = clean_limits(payload["limits"])
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
            await pool.execute("UPDATE devices SET limits = $2 WHERE mac = $1", mac.lower(), limits)
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
        """Remove a device and what was learned about it; if it shows up again it is a new device."""
        from ..detections import delete_devices
        await delete_devices([mac.lower()])
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
        nut = str(payload.get("nut") or "").strip()[:200]
        if nut and nut.lower() != "off" and not re.fullmatch(r"(?:[\w.-]+@)?[\w.\-\[\]:]*", nut):
            raise HTTPException(400, "NUT: use ups@host:port, host, or off")
        return {"name": str(payload.get("name") or "Unraid").strip()[:60], "url": url,
                "api_key": str(payload.get("api_key") or "").strip(), "verify_ssl": bool(payload.get("verify_ssl")),
                "docker_url": docker_url, "collect_logs": bool(payload.get("collect_logs", True)),
                "enabled": bool(payload.get("enabled", True)), "nut": nut}

    @app.post("/api/unraid/servers")
    async def add_unraid(payload: dict = Body(...)):
        v = _validate_server(payload)
        if not v["api_key"]:
            raise HTTPException(400, "API key is required")
        sid = await db.pool().fetchval(
            "INSERT INTO unraid_servers (name, url, api_key, verify_ssl, docker_url, collect_logs, enabled, nut) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id", *{**v, "api_key": crypto.encrypt(v["api_key"])}.values())
        return {"id": sid}

    @app.put("/api/unraid/servers/{sid}")
    async def edit_unraid(sid: int, payload: dict = Body(...)):
        v = _validate_server(payload)
        await db.pool().execute(
            "UPDATE unraid_servers SET name = $2, url = $3, api_key = COALESCE(nullif($4, ''), api_key), verify_ssl = $5, "
            "docker_url = $6, collect_logs = $7, enabled = $8, nut = $9 WHERE id = $1", sid,
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
        return await unraid_test(v["url"], v["api_key"], v["verify_ssl"], v["docker_url"], v["nut"])

    # log alert rules for containers (Unraid › Docker); registered before /api/unraid/{sid}
    def _log_rule_out(r: Any) -> dict[str, Any]:
        return {k: r[k] for k in ("id", "name", "enabled", "server_id", "containers", "match", "ignore", "threshold",
                                  "minutes", "severity")}

    async def _clean_log_rule(payload: dict) -> dict[str, Any]:
        from .. import container_watch
        try:
            rule = container_watch.clean_rule(payload)
            await container_watch.check_regex(rule)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return rule

    @app.get("/api/unraid/log-rules")
    async def log_rules():
        rows = await db.pool().fetch("SELECT * FROM container_log_rules ORDER BY id")
        return {"rules": [_log_rule_out(r) for r in rows],
                "default": {"threshold": settings.unraid_log_error_count, "minutes": settings.unraid_log_error_minutes},
                "restarts": {"count": settings.unraid_restart_count, "minutes": settings.unraid_restart_minutes}}

    @app.post("/api/unraid/log-rules")
    async def add_log_rule(payload: dict = Body(...)):
        r = await _clean_log_rule(payload)
        rid = await db.pool().fetchval(
            "INSERT INTO container_log_rules (name, enabled, server_id, containers, match, ignore, threshold, minutes, "
            "severity) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id", r["name"], r["enabled"], r["server_id"],
            r["containers"], r["match"], r["ignore"], r["threshold"], r["minutes"], r["severity"])
        return {"id": rid}

    @app.put("/api/unraid/log-rules/{rid}")
    async def edit_log_rule(rid: int, payload: dict = Body(...)):
        r = await _clean_log_rule(payload)
        await db.pool().execute(
            "UPDATE container_log_rules SET name = $2, enabled = $3, server_id = $4, containers = $5, match = $6, "
            "ignore = $7, threshold = $8, minutes = $9, severity = $10 WHERE id = $1", rid, r["name"], r["enabled"],
            r["server_id"], r["containers"], r["match"], r["ignore"], r["threshold"], r["minutes"], r["severity"])
        return {"ok": True}

    @app.delete("/api/unraid/log-rules/{rid}")
    async def delete_log_rule(rid: int):
        await db.pool().execute("DELETE FROM container_log_rules WHERE id = $1", rid)
        return {"ok": True}

    @app.post("/api/unraid/log-rules/test")
    async def test_log_rule(payload: dict = Body(...)):
        """How a rule (saved or not) would have done over the last hours, per container."""
        from .. import container_watch
        r = await _clean_log_rule({"name": "test", **payload})
        rule = container_watch.LogRule(id=None, **r)
        hours = max(1, min(int(payload.get("hours") or 24), 24 * 30))
        host = None
        if r["server_id"]:
            host = await db.pool().fetchval("SELECT name FROM unraid_servers WHERE id = $1", r["server_id"])
        names = None
        if rule.containers:  # the containers this rule covers, among those that logged in that time
            known = [x["program"] for x in await db.pool().fetch(
                "SELECT DISTINCT program FROM events WHERE source = 'docker' AND ts > now() - make_interval(hours => $1) "
                "AND program IS NOT NULL", hours)]
            names = [n for n in known if rule.covers(n)]
        rows = await container_watch.preview(host, names, rule, hours)
        return {"hours": hours, "rows": db.records(rows)}

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
        if any(str(k).startswith("vuln_") for k in changed or []):
            await _vulns_reevaluate()  # new thresholds / alert level / exceptions apply right away
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

    @app.post("/api/settings/test/email")
    async def test_email(payload: dict = Body(...)):
        from .. import notify

        cand = _candidate(payload.get("values"))
        if not cand.smtp_enabled:
            return {"ok": False, "error": "SMTP server and sender address are required"}
        try:
            to = notify.recipients(payload.get("to")) or notify.recipients(cand.smtp_from)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        try:
            await notify.send(cand, to, "[Looking Glass] Test mail",
                              "This is a test mail from Looking Glass. Mail notifications work.\n\n"
                              "Set up what you want to be mailed about under Settings › Email & notifications.")
        except notify.MailError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "to": ", ".join(to)}

    @app.post("/api/settings/test/ai")
    async def test_ai(payload: dict = Body(...)):
        cand = _candidate(payload.get("values"))
        if not cand.ai_enabled:
            return {"ok": False, "error": "base URL, API key and model are required"}
        request_log.info("AI connection test (Settings › AI analyst › Test)")
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
