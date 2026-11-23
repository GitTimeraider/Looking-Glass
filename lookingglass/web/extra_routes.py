"""API of blocking, snoozes, the incident timeline, WAN quality, the audit log and backups."""
from __future__ import annotations

import asyncio
import logging
import secrets
import time
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from .. import audit, auth, backup, blocking, db, snooze, timeline, wan
from ..config import Settings
from .auth_routes import client_ip

log = logging.getLogger(__name__)


def _user(request: Request) -> str | None:
    user = getattr(request.state, "user", None)
    return user.get("username") if isinstance(user, dict) else None


def register(app: FastAPI, settings: Settings) -> None:
    # --------------------------------------------------------------- blocking ---
    @app.get("/api/blocks")
    async def blocks_list():
        out = await blocking.listing()
        out["configured"] = bool(settings.block_alias.strip()) and settings.opnsense_enabled
        if isinstance(out["state"], dict) and out["state"].get("alias") != settings.block_alias.strip():
            out["state"] = None  # from before the alias was changed: the next sync (within a minute) tells
        out["alias"] = settings.block_alias.strip()
        out["default_hours"] = settings.block_hours
        out["auto"] = {"on": settings.block_auto, "severity": settings.block_auto_severity, "hours": settings.block_auto_hours}
        return out

    @app.post("/api/blocks")
    async def blocks_add(request: Request, payload: dict = Body(...)):
        try:
            hours = float(payload.get("hours") if payload.get("hours") not in (None, "") else settings.block_hours)
        except (TypeError, ValueError) as exc:
            raise HTTPException(400, "the duration must be a number of hours") from exc
        if hours < 0 or hours > 24 * 365:
            raise HTTPException(400, "the duration must be between 0 (until removed) and 8760 hours")
        aid = payload.get("alert_id")
        reason = str(payload.get("reason") or "").strip()
        if aid and not reason:
            row = await db.pool().fetchrow("SELECT severity, title FROM alerts WHERE id = $1", int(aid))
            reason = f"alert #{aid}: [{row['severity']}] {row['title']}" if row else f"alert #{aid}"
        request.state.audit = {"ip": str(payload.get("ip")), "hours": hours, **({"alert": int(aid)} if aid else {})}
        try:
            return await blocking.create(settings, str(payload.get("ip") or ""), hours, reason, by=_user(request),
                                         alert_id=int(aid) if aid else None, client_ip=client_ip(request),
                                         allow_internal=bool(payload.get("allow_internal")))
        except blocking.BlockError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.delete("/api/blocks/{bid}")
    async def blocks_remove(bid: int, request: Request):
        try:
            out = await blocking.remove(settings, bid, by=_user(request))
        except blocking.BlockError as exc:
            raise HTTPException(404, str(exc)) from exc
        request.state.audit = {"ip": out["ip"], "block": bid}
        return out

    @app.post("/api/blocks/sync")
    async def blocks_sync():
        return await blocking.sync_once(settings)

    # ---------------------------------------------------------------- snoozes ---
    @app.get("/api/snoozes")
    async def snoozes_list():
        return {"snoozes": await snooze.listing()}

    @app.get("/api/mute-schedule/reference")
    async def mute_schedule_reference():
        """Settings › Alert filters › Recurring mute windows › Format & categories."""
        from .. import mute_schedule
        return mute_schedule.reference()

    async def _save_snooze(request: Request, payload: dict, sid: int | None = None) -> dict[str, Any]:
        try:
            v = snooze.clean(payload)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        request.state.audit = {"name": v["name"], "networks": v["networks"], "rules": v["rules"],
                               "until": v["ends_at"].isoformat()}
        pool = db.pool()
        if sid is None:
            sid = await pool.fetchval(
                "INSERT INTO snoozes (created_by, name, starts_at, ends_at, networks, rules) VALUES ($1, $2, $3, $4, $5, $6) "
                "RETURNING id", _user(request), v["name"], v["starts_at"], v["ends_at"], v["networks"], v["rules"])
        elif (await pool.execute("UPDATE snoozes SET name = $2, starts_at = $3, ends_at = $4, networks = $5, rules = $6 "
                                 "WHERE id = $1", sid, v["name"], v["starts_at"], v["ends_at"], v["networks"],
                                 v["rules"])).endswith(" 0"):
            raise HTTPException(404, "That snooze does not exist (any more).")
        snooze.invalidate()
        return {"ok": True, "id": sid}

    @app.post("/api/snoozes")
    async def snoozes_add(request: Request, payload: dict = Body(...)):
        return await _save_snooze(request, payload)

    @app.put("/api/snoozes/{sid}")
    async def snoozes_edit(sid: int, request: Request, payload: dict = Body(...)):
        return await _save_snooze(request, payload, sid)

    @app.post("/api/snoozes/{sid}/end")
    async def snoozes_end(sid: int):
        """End it now (it stays in the list as ended)."""
        await db.pool().execute("UPDATE snoozes SET ends_at = least(ends_at, now()), "
                                "starts_at = least(starts_at, now()) WHERE id = $1", sid)
        snooze.invalidate()
        return {"ok": True}

    @app.delete("/api/snoozes/{sid}")
    async def snoozes_delete(sid: int):
        await db.pool().execute("DELETE FROM snoozes WHERE id = $1", sid)
        snooze.invalidate()
        return {"ok": True}

    # --------------------------------------------------------------- timeline ---
    @app.get("/api/timeline")
    async def timeline_data(ip: str | None = None, mac: str | None = None, hours: float = Query(24, gt=0, le=24 * 31),
                            start: str | None = None, end: str | None = None):
        try:
            return await timeline.build(ip=ip, mac=mac, hours=hours, start=start, end=end)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    # -------------------------------------------------------------------- WAN ---
    @app.get("/api/wan")
    async def wan_data(days: int = Query(90, ge=7, le=730)):
        return await wan.overview(settings, days)

    @app.put("/api/wan/prefs")
    async def wan_prefs(request: Request, payload: dict = Body(...)):
        try:
            p = await wan.save_prefs(payload)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        request.state.audit = {"hidden": p["hidden"], "ignored": p["ignored"]}
        return p

    # -------------------------------------------------------------- audit log ---
    @app.get("/api/audit")
    async def audit_list(limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0),
                         action: str | None = None, user: str | None = None, q: str | None = None):
        return await audit.listing(limit, offset, action or None, user or None, q or None)

    # ----------------------------------------------------------------- backup ---
    jobs: dict[str, dict[str, Any]] = {}

    async def run_backup(job: dict[str, Any]) -> None:
        try:
            job["path"] = await backup.create(settings.data_dir, job["kind"], job)
            job["state"] = "ready"
        except Exception as exc:  # noqa: BLE001
            log.exception("backup failed")
            job.update(state="failed", error=f"{type(exc).__name__}: {exc}"[:500])

    @app.post("/api/admin/backup")
    async def backup_start(request: Request, payload: dict = Body(...)):
        kind = payload.get("kind") or "full"
        if kind not in backup.KINDS:
            raise HTTPException(400, "unknown backup kind")
        user = request.state.user
        if not await asyncio.to_thread(auth.verify_password, str(payload.get("password", "")), user["password_hash"]):
            request.state.audit = {"kind": kind, "error": "wrong password"}
            raise HTTPException(403, "Wrong password.")
        if any(j["state"] == "running" for j in jobs.values()):
            raise HTTPException(409, "A backup is already being made - wait for it to finish.")
        for jid in [k for k, j in jobs.items() if time.time() - j["created"] > 3600]:
            jobs.pop(jid, None)
        jid = secrets.token_urlsafe(16)
        job = jobs[jid] = {"state": "running", "kind": kind, "created": time.time(), "user": user["username"]}
        request.state.audit = {"kind": kind}
        task = asyncio.create_task(run_backup(job))
        job["_task"] = task
        return {"job": jid}

    def _job(jid: str, request: Request) -> dict[str, Any]:
        job = jobs.get(jid)
        if not job or job["user"] != request.state.user["username"]:
            raise HTTPException(404, "This backup does not exist (any more) - make a new one.")
        return job

    @app.get("/api/admin/backup/{jid}")
    async def backup_status(jid: str, request: Request):
        job = _job(jid, request)
        return {k: v for k, v in job.items() if not k.startswith("_") and k != "path"} | \
            ({"file": job["path"].name} if job.get("path") else {})

    @app.get("/api/admin/backup/{jid}/download")
    async def backup_download(jid: str, request: Request):
        job = _job(jid, request)
        path = job.get("path")
        if job["state"] != "ready" or not path or not path.exists():
            raise HTTPException(404, "The backup is not ready (or was downloaded already).")
        jobs.pop(jid, None)  # one download; the file is deleted after it was sent
        await audit.record("backup", job["user"], client_ip(request), "download",
                           detail={"kind": job["kind"], "file": path.name, "size": path.stat().st_size})
        return FileResponse(path, media_type="application/gzip", filename=path.name,
                            background=BackgroundTask(path.unlink, missing_ok=True),
                            headers={"Cache-Control": "no-store"})
