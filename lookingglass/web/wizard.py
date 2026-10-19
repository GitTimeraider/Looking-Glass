"""First-start setup wizard.

Served on the web port instead of the normal UI while the database connection or the first account is missing.
Every request needs the one-time setup code printed in the container log, so nobody else on the network can claim a
fresh instance.
"""
from __future__ import annotations

import asyncio
import hmac
import logging
import secrets
from pathlib import Path
from typing import Any

import asyncpg
from fastapi import Body, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__, auth, db, db_config
from ..config import Settings

log = logging.getLogger("lookingglass.setup")
HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(HERE / "templates"))
MAX_ATTEMPTS = 10
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I


def _new_code() -> str:
    raw = "".join(secrets.choice(_ALPHABET) for _ in range(12))
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


def _db_error(exc: BaseException) -> str:
    if isinstance(exc, (asyncpg.InvalidPasswordError, asyncpg.InvalidAuthorizationSpecificationError)):
        return f"Login refused: wrong user name or password ({exc})."
    if isinstance(exc, asyncpg.InvalidCatalogNameError):
        return f"The database does not exist ({exc}). Create it first or check the name."
    if isinstance(exc, asyncpg.InsufficientPrivilegeError):
        return f"The user may not create tables in this database ({exc}). Make it the database owner."
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "No answer from the server (timeout). Check host, port and firewall."
    if isinstance(exc, OSError):
        return f"Cannot reach the server: {exc.strerror or exc}. Check host and port."
    return f"{type(exc).__name__}: {exc}"


class Wizard:
    def __init__(self, settings: Settings, need_db: bool, need_admin: bool) -> None:
        self.settings = settings
        self.need_db = need_db
        self.need_admin = need_admin
        self.done = asyncio.Event()
        self.attempts = 0
        self.code = ""
        self._lock = asyncio.Lock()
        self._rotate()

    def _rotate(self) -> None:
        self.code = _new_code()
        self.attempts = 0
        log.warning("=" * 72)
        log.warning("FIRST-TIME SETUP: open the web UI (port %s) and enter this setup code:", self.settings.web_port)
        log.warning("    %s", self.code)
        log.warning("=" * 72)

    def _check(self, given: Any) -> JSONResponse | None:
        """None when the code is right, else an error response."""
        given = str(given or "").strip().upper().replace(" ", "").replace("-", "")
        if given and hmac.compare_digest(given.encode(), self.code.replace("-", "").encode()):
            return None
        self.attempts += 1
        if self.attempts >= MAX_ATTEMPTS:
            log.warning("too many wrong setup codes - a new code was generated")
            self._rotate()
            return JSONResponse({"detail": "Too many wrong codes. A new code was written to the container log."}, 403)
        return JSONResponse({"detail": "Wrong setup code. Copy it from the container log."}, 403)

    def state(self) -> dict[str, Any]:
        return {"need_db": self.need_db, "need_admin": self.need_admin, "done": self.done.is_set()}

    async def _try_db(self, cfg: dict[str, Any], save: bool) -> dict[str, Any]:
        kwargs = db_config.connect_kwargs(cfg)
        if not save:
            conn = await asyncpg.connect(timeout=10, **kwargs)
            try:
                version = await conn.fetchval("SHOW server_version")
                can_create = await conn.fetchval(
                    "SELECT has_schema_privilege(current_user, 'public', 'CREATE')")
                tables = await conn.fetchval(
                    "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users'")
                users = await conn.fetchval("SELECT count(*) FROM users") if tables else 0
            finally:
                await conn.close()
            if not can_create:
                raise asyncpg.InsufficientPrivilegeError("no CREATE privilege on schema public")
            msg = f"Connected to PostgreSQL {version}."
            if users:
                msg += f" This database already contains Looking Glass data ({users} account(s)); it will be reused."
            return {"ok": True, "message": msg}
        await db.close()
        try:
            await db.connect(retry=False, **kwargs)
        except BaseException:
            await db.close()
            raise
        db_config.save(self.settings.data_dir, cfg)
        self.need_db = False
        # ADMIN_USER / ADMIN_PASSWORD from the environment still create the first account
        self.need_admin = not await auth.ensure_admin(self.settings.admin_user, self.settings.admin_password)
        if not self.need_admin:
            self.done.set()
        return {"ok": True, **self.state()}

    def app(self) -> FastAPI:
        app = FastAPI(title="Looking Glass setup", docs_url=None, redoc_url=None, openapi_url=None)
        app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

        @app.middleware("http")
        async def csrf(request: Request, call_next):
            if request.method == "POST" and request.headers.get("x-looking-glass") != "1":
                return JSONResponse({"detail": "missing X-Looking-Glass header"}, status_code=403)
            return await call_next(request)

        @app.get("/healthz")
        async def healthz():
            return {"status": "setup"}

        @app.get("/wizard/state")
        async def get_state():
            return self.state()

        @app.post("/wizard/code")
        async def code(payload: dict = Body(...)):
            return self._check(payload.get("code")) or {"ok": True, **self.state()}

        @app.post("/wizard/database")
        async def database(payload: dict = Body(...)):
            if err := self._check(payload.get("code")):
                return err
            if not self.need_db:
                return JSONResponse({"detail": "The database is already configured."}, 409)
            try:
                cfg = db_config.clean(payload)
            except ValueError as exc:
                return JSONResponse({"detail": str(exc)}, 400)
            async with self._lock:
                try:
                    return await self._try_db(cfg, save=not payload.get("test_only"))
                except Exception as exc:  # noqa: BLE001
                    log.warning("setup: database connection to %s:%s failed: %s", cfg["host"], cfg["port"], exc)
                    return JSONResponse({"detail": _db_error(exc)}, 400)

        @app.post("/wizard/admin")
        async def admin(payload: dict = Body(...)):
            if err := self._check(payload.get("code")):
                return err
            if self.need_db or not self.need_admin:
                return JSONResponse({"detail": "Not possible at this step."}, 409)
            username = str(payload.get("username") or "").strip()
            password = str(payload.get("password") or "")
            if not username or len(username) > 64 or any(c.isspace() for c in username):
                return JSONResponse({"detail": "Choose a user name without spaces."}, 400)
            if problem := auth.password_problem(password):
                return JSONResponse({"detail": problem}, 400)
            async with self._lock:
                if await db.pool().fetchval("SELECT count(*) FROM users"):
                    return JSONResponse({"detail": "An account already exists."}, 409)
                await auth.create_user(username, password)
            log.info("setup: first account %r created", username)
            self.need_admin = False
            self.done.set()
            return {"ok": True, **self.state()}

        @app.get("/{path:path}", response_class=HTMLResponse)
        async def page(request: Request, path: str):
            return templates.TemplateResponse(request, "wizard.html", {"version": __version__})

        return app
