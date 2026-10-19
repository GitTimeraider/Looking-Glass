"""Login (password + TOTP / passkey), MFA enrollment, account management and password reset routes."""
from __future__ import annotations

import asyncio
import io
import json
import logging
import time
from typing import Any

import segno
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

from .. import __version__, auth, db
from ..config import Settings

log = logging.getLogger("lookingglass.auth")

PUBLIC_PATHS = ("/login", "/login/mfa", "/login/totp", "/login/passkey/options", "/login/passkey/verify",
                "/reset", "/reset/request", "/healthz")
# reachable while logged in but before MFA has been set up
SETUP_PATHS = ("/account", "/logout")

_user_cache: dict[int, tuple[float, dict[str, Any] | None, bool]] = {}


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def rp(request: Request, settings: Settings) -> tuple[str, str]:
    """Relying party id and expected origin for WebAuthn."""
    if settings.public_url:
        origin = settings.public_url.rstrip("/")
    else:
        origin = f"{request.url.scheme}://{request.headers.get('host', request.url.netloc)}"
    host = origin.split("://", 1)[1].split("/")[0]
    rp_id = settings.webauthn_rp_id or (host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0][1:])
    return rp_id, origin


async def current_user(request: Request) -> tuple[dict[str, Any] | None, bool]:
    """Return (user, mfa_configured) for a fully logged-in session, else (None, False)."""
    uid = request.session.get("uid")
    if not uid or not request.session.get("mfa_ok"):
        return None, False
    cached = _user_cache.get(uid)
    if cached and time.time() - cached[0] < 5:
        user, mfa = cached[1], cached[2]
    else:
        user = await auth.get_user(uid)
        mfa = await auth.has_mfa(user) if user else False
        _user_cache[uid] = (time.time(), user, mfa)
    if not user or user["session_version"] != request.session.get("sv"):
        request.session.clear()
        return None, False
    return user, mfa


def invalidate_cache(uid: int) -> None:
    _user_cache.pop(uid, None)


def register(app: FastAPI, settings: Settings, templates: Jinja2Templates) -> None:
    def render(request: Request, tpl: str, status: int = 200, **ctx: Any) -> HTMLResponse:
        return templates.TemplateResponse(request, tpl, {"version": __version__, **ctx}, status_code=status)

    def finish_login(request: Request, user: dict[str, Any]) -> None:
        request.session.clear()
        request.session.update(uid=user["id"], sv=user["session_version"], mfa_ok=True, user=user["username"])
        invalidate_cache(user["id"])

    # ------------------------------------------------------------ login ---
    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        return render(request, "login.html", error=None, step="password")

    @app.post("/login")
    async def login(request: Request):
        ip = client_ip(request)
        form = await request.form()
        username, password = str(form.get("username", "")).strip(), str(form.get("password", ""))
        if auth.too_many_failures(ip):
            return render(request, "login.html", 429, error="Too many failed attempts, try again in 15 minutes.", step="password")
        user = await auth.get_user_by_name(username)
        ok = user is not None and await asyncio.to_thread(auth.verify_password, password, user["password_hash"])
        if not ok:
            auth.record_failure(ip)
            log.warning("failed login for %r from %s", username, ip)
            await asyncio.sleep(1)
            return render(request, "login.html", 401, error="Invalid username or password.", step="password")
        request.session.clear()
        if not await auth.has_mfa(user):
            # first login (or after a reset): log in and force MFA enrollment
            finish_login(request, user)
            await db.pool().execute("UPDATE users SET last_login = now() WHERE id = $1", user["id"])
            return RedirectResponse("/account?setup=1", status_code=303)
        request.session.update(pending_uid=user["id"], pending_at=time.time())
        return RedirectResponse("/login/mfa", status_code=303)

    async def pending_user(request: Request) -> dict[str, Any] | None:
        uid = request.session.get("pending_uid")
        if not uid or time.time() - request.session.get("pending_at", 0) > 300:
            return None
        return await auth.get_user(uid)

    @app.get("/login/mfa", response_class=HTMLResponse)
    async def mfa_page(request: Request):
        user = await pending_user(request)
        if not user:
            return RedirectResponse("/login")
        has_passkey = bool(await auth.passkeys(user["id"]))
        return render(request, "login.html", step="mfa", error=None, totp=user["totp_enabled"], passkey=has_passkey,
                      username=user["username"])

    @app.post("/login/totp")
    async def login_totp(request: Request):
        ip = client_ip(request)
        user = await pending_user(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        form = await request.form()
        if auth.too_many_failures(ip) or not auth.verify_totp(user["totp_secret"] or "", str(form.get("code", "")), user["id"]):
            auth.record_failure(ip)
            await asyncio.sleep(1)
            return render(request, "login.html", 401, step="mfa", error="Invalid code.", totp=user["totp_enabled"],
                          passkey=bool(await auth.passkeys(user["id"])), username=user["username"])
        auth.clear_failures(ip)
        finish_login(request, user)
        await db.pool().execute("UPDATE users SET last_login = now() WHERE id = $1", user["id"])
        log.info("login %s from %s (totp)", user["username"], ip)
        return RedirectResponse("/", status_code=303)

    @app.post("/login/passkey/options")
    async def login_passkey_options(request: Request):
        user = await pending_user(request)
        if not user:
            raise HTTPException(401, "login expired")
        rp_id, _ = rp(request, settings)
        creds = await auth.passkeys(user["id"])
        opts = generate_authentication_options(
            rp_id=rp_id, user_verification=UserVerificationRequirement.PREFERRED,
            allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id"])) for c in creds])
        request.session["challenge"] = bytes_to_base64url(opts.challenge)
        return JSONResponse(json.loads(options_to_json(opts)))

    @app.post("/login/passkey/verify")
    async def login_passkey_verify(request: Request, payload: dict = Body(...)):
        ip = client_ip(request)
        user = await pending_user(request)
        challenge = request.session.pop("challenge", None)
        if not user or not challenge:
            raise HTTPException(401, "login expired")
        rp_id, origin = rp(request, settings)
        cred_id = payload.get("id") or payload.get("rawId")
        row = await db.pool().fetchrow("SELECT * FROM webauthn_credentials WHERE credential_id = $1 AND user_id = $2",
                                       cred_id, user["id"])
        if not row:
            auth.record_failure(ip)
            raise HTTPException(400, "unknown passkey")
        try:
            res = verify_authentication_response(
                credential=payload, expected_challenge=base64url_to_bytes(challenge), expected_rp_id=rp_id,
                expected_origin=origin, credential_public_key=bytes(row["public_key"]),
                credential_current_sign_count=row["sign_count"])
        except Exception as exc:  # noqa: BLE001 - library raises various verification errors
            auth.record_failure(ip)
            log.warning("passkey verification failed for %s from %s: %s", user["username"], ip, exc)
            raise HTTPException(400, f"passkey verification failed: {exc}") from exc
        await db.pool().execute("UPDATE webauthn_credentials SET sign_count = $2, last_used = now() WHERE id = $1",
                                row["id"], res.new_sign_count)
        finish_login(request, user)
        await db.pool().execute("UPDATE users SET last_login = now() WHERE id = $1", user["id"])
        log.info("login %s from %s (passkey)", user["username"], ip)
        return {"ok": True, "redirect": "/"}

    @app.get("/logout")
    async def logout(request: Request):
        request.session.clear()
        return RedirectResponse("/login")

    # ------------------------------------------------------------ reset ---
    @app.get("/reset", response_class=HTMLResponse)
    async def reset_page(request: Request):
        return render(request, "reset.html", error=None, info=None)

    @app.post("/reset/request")
    async def reset_request(request: Request):
        form = await request.form()
        username = str(form.get("username", "")).strip()
        if not username:
            first = await db.pool().fetchval("SELECT username FROM users ORDER BY id LIMIT 1")
            username = first or settings.admin_user
        log.warning("reset code requested from %s", client_ip(request))
        auth.create_reset_code(username)
        if "text/html" in request.headers.get("accept", ""):
            return render(request, "reset.html", error=None,
                          info="A reset code was written to the Looking Glass container log. Run  docker logs looking-glass --tail 20  "
                               "on the Docker host (or open the container's log in Unraid/Portainer) and enter it below.")
        return {"ok": True}

    @app.post("/reset")
    async def reset_do(request: Request):
        ip = client_ip(request)
        form = await request.form()
        code, pw1, pw2 = str(form.get("code", "")), str(form.get("password", "")), str(form.get("password2", ""))
        if auth.too_many_failures("reset:" + ip, limit=10):
            return render(request, "reset.html", 429, error="Too many attempts, try again later.", info=None)
        if pw1 != pw2:
            return render(request, "reset.html", 400, error="Passwords do not match.", info=None)
        problem = auth.password_problem(pw1)
        if problem:
            return render(request, "reset.html", 400, error=problem, info=None)
        username = auth.check_reset_code(code)
        if not username:
            auth.record_failure("reset:" + ip)
            await asyncio.sleep(1)
            return render(request, "reset.html", 400, error="Invalid or expired code.", info=None)
        await auth.reset_user(username, pw1)
        _user_cache.clear()
        request.session.clear()
        return render(request, "login.html", error=None, step="password",
                      info=f"Password and MFA for '{username}' were reset. Log in and set up MFA again.")

    # ---------------------------------------------------------- account ---
    @app.get("/account", response_class=HTMLResponse)
    async def account_page(request: Request):
        user, mfa = await current_user(request)
        if not user:
            return RedirectResponse("/login")
        return render(request, "account.html", title="Account", path="/account", user=user, mfa=mfa,
                      setup=not mfa, ai_enabled=settings.ai_enabled)

    @app.get("/api/account")
    async def account_info(request: Request):
        user, mfa = await current_user(request)
        if not user:
            raise HTTPException(401)
        keys = await auth.passkeys(user["id"])
        return {"username": user["username"], "totp_enabled": user["totp_enabled"], "mfa": mfa,
                "last_login": user["last_login"].isoformat() if user["last_login"] else None,
                "passkeys": [{"id": k["id"], "name": k["name"], "created_at": k["created_at"].isoformat(),
                              "last_used": k["last_used"].isoformat() if k["last_used"] else None} for k in keys]}

    @app.post("/api/account/password")
    async def change_password(request: Request, payload: dict = Body(...)):
        user, _ = await current_user(request)
        if not user:
            raise HTTPException(401)
        if not await asyncio.to_thread(auth.verify_password, str(payload.get("current", "")), user["password_hash"]):
            raise HTTPException(400, "current password is wrong")
        problem = auth.password_problem(str(payload.get("new", "")))
        if problem:
            raise HTTPException(400, problem)
        new_hash = await asyncio.to_thread(auth.hash_password, str(payload["new"]))
        await db.pool().execute("UPDATE users SET password_hash = $2, session_version = session_version + 1 WHERE id = $1",
                                user["id"], new_hash)
        user = await auth.get_user(user["id"])
        finish_login(request, user)  # keep this session, drop all others
        return {"ok": True}

    @app.post("/api/account/totp/begin")
    async def totp_begin(request: Request):
        user, _ = await current_user(request)
        if not user:
            raise HTTPException(401)
        secret = auth.new_totp_secret()
        request.session["totp_pending"] = secret
        uri = auth.totp_uri(secret, user["username"])
        buf = io.BytesIO()
        segno.make(uri, error="m").save(buf, kind="svg", scale=5, dark="#000", light="#fff", border=2)
        return {"secret": secret, "uri": uri, "svg": buf.getvalue().decode()}

    @app.post("/api/account/totp/confirm")
    async def totp_confirm(request: Request, payload: dict = Body(...)):
        user, _ = await current_user(request)
        secret = request.session.get("totp_pending")
        if not user or not secret:
            raise HTTPException(400, "start TOTP setup first")
        if not auth.verify_totp(secret, str(payload.get("code", "")), user["id"]):
            raise HTTPException(400, "code does not match - check the time on your phone and try again")
        await db.pool().execute("UPDATE users SET totp_secret = $2, totp_enabled = true WHERE id = $1", user["id"], secret)
        request.session.pop("totp_pending", None)
        invalidate_cache(user["id"])
        return {"ok": True}

    @app.post("/api/account/totp/disable")
    async def totp_disable(request: Request, payload: dict = Body(...)):
        user, _ = await current_user(request)
        if not user:
            raise HTTPException(401)
        if not await asyncio.to_thread(auth.verify_password, str(payload.get("password", "")), user["password_hash"]):
            raise HTTPException(400, "password is wrong")
        if not await auth.passkeys(user["id"]):
            raise HTTPException(400, "add a passkey first - MFA cannot be removed completely")
        await db.pool().execute("UPDATE users SET totp_secret = NULL, totp_enabled = false WHERE id = $1", user["id"])
        invalidate_cache(user["id"])
        return {"ok": True}

    @app.post("/api/account/passkey/options")
    async def passkey_options(request: Request):
        user, _ = await current_user(request)
        if not user:
            raise HTTPException(401)
        rp_id, _ = rp(request, settings)
        existing = await auth.passkeys(user["id"])
        opts = generate_registration_options(
            rp_id=rp_id, rp_name="Looking Glass", user_name=user["username"], user_id=f"lookingglass-{user['id']}".encode(),
            authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.PREFERRED,
                                                                   user_verification=UserVerificationRequirement.PREFERRED),
            exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id"])) for c in existing])
        request.session["reg_challenge"] = bytes_to_base64url(opts.challenge)
        return JSONResponse(json.loads(options_to_json(opts)))

    @app.post("/api/account/passkey/verify")
    async def passkey_verify(request: Request, payload: dict = Body(...)):
        user, _ = await current_user(request)
        challenge = request.session.pop("reg_challenge", None)
        if not user or not challenge:
            raise HTTPException(400, "start passkey registration first")
        rp_id, origin = rp(request, settings)
        cred = payload.get("credential") or {}
        try:
            res = verify_registration_response(credential=cred, expected_challenge=base64url_to_bytes(challenge),
                                               expected_rp_id=rp_id, expected_origin=origin)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(400, f"passkey registration failed: {exc}") from exc
        name = str(payload.get("name") or "Passkey")[:60]
        await db.pool().execute(
            "INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, name, transports) "
            "VALUES ($1, $2, $3, $4, $5, $6)", user["id"], bytes_to_base64url(res.credential_id), res.credential_public_key,
            res.sign_count, name, (cred.get("response") or {}).get("transports"))
        invalidate_cache(user["id"])
        return {"ok": True}

    @app.delete("/api/account/passkey/{key_id}")
    async def passkey_delete(request: Request, key_id: int):
        user, _ = await current_user(request)
        if not user:
            raise HTTPException(401)
        keys = await auth.passkeys(user["id"])
        if len(keys) <= 1 and not user["totp_enabled"]:
            raise HTTPException(400, "this is your only MFA method - set up TOTP or another passkey first")
        await db.pool().execute("DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2", key_id, user["id"])
        invalidate_cache(user["id"])
        return {"ok": True}
