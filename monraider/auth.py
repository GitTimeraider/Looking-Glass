"""Users, password hashing, TOTP, passkeys (WebAuthn) and the log-printed reset code."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import secrets
import time
from typing import Any

import pyotp

from . import db

log = logging.getLogger("monraider.auth")

# scrypt parameters: 2^15 * 8 * 128 bytes = 32 MiB memory per hash
_N, _R, _P = 2 ** 15, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, maxmem=64 * 1024 * 1024, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, digest = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                              maxmem=64 * 1024 * 1024, dklen=len(base64.b64decode(digest)))
        return hmac.compare_digest(calc, base64.b64decode(digest))
    except (ValueError, TypeError):
        return False


def password_problem(password: str) -> str | None:
    if len(password) < 10:
        return "Password must be at least 10 characters."
    if password.lower() in ("password12", "changeme12", "admin12345") or len(set(password)) < 5:
        return "Password is too simple."
    return None


# ------------------------------------------------------------------ users ---
async def ensure_admin(username: str, password: str) -> None:
    """Create the initial admin user on first start."""
    pool = db.pool()
    if await pool.fetchval("SELECT count(*) FROM users"):
        return
    generated = not password
    if generated:
        password = secrets.token_urlsafe(12)
    pw_hash = await asyncio.to_thread(hash_password, password)
    await pool.execute("INSERT INTO users (username, password_hash) VALUES ($1, $2)", username, pw_hash)
    if generated:
        log.warning("=" * 72)
        log.warning("Initial admin account created: user=%s password=%s", username, password)
        log.warning("Log in and change it; you will be asked to set up MFA (TOTP or passkey).")
        log.warning("=" * 72)
    else:
        log.info("initial admin user %r created from ADMIN_USER/ADMIN_PASSWORD", username)


async def get_user(user_id: int) -> dict[str, Any] | None:
    row = await db.pool().fetchrow("SELECT * FROM users WHERE id = $1", user_id)
    return dict(row) if row else None


async def get_user_by_name(username: str) -> dict[str, Any] | None:
    row = await db.pool().fetchrow("SELECT * FROM users WHERE lower(username) = lower($1)", username)
    return dict(row) if row else None


async def passkeys(user_id: int) -> list[dict[str, Any]]:
    rows = await db.pool().fetch(
        "SELECT id, credential_id, public_key, sign_count, name, transports, created_at, last_used "
        "FROM webauthn_credentials WHERE user_id = $1 ORDER BY id", user_id)
    return [dict(r) for r in rows]


async def has_mfa(user: dict[str, Any]) -> bool:
    if user.get("totp_enabled"):
        return True
    return bool(await db.pool().fetchval("SELECT count(*) FROM webauthn_credentials WHERE user_id = $1", user["id"]))


async def set_password(user_id: int, password: str) -> None:
    await db.pool().execute("UPDATE users SET password_hash = $2, session_version = session_version + 1 WHERE id = $1",
                            user_id, hash_password(password))


# ------------------------------------------------------------------- TOTP ---
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="MonRaider")


_used_totp: dict[tuple[int, str], float] = {}


def verify_totp(secret: str, code: str, user_id: int = 0) -> bool:
    code = "".join(ch for ch in code if ch.isdigit())
    if len(code) != 6 or not secret:
        return False
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        return False
    # reject replay of the same code inside its validity window
    now = time.time()
    for k in [k for k, t in _used_totp.items() if now - t > 120]:
        _used_totp.pop(k, None)
    if (user_id, code) in _used_totp:
        return False
    _used_totp[(user_id, code)] = now
    return True


# ------------------------------------------------------------ reset code ---
RESET_TTL = 15 * 60
_reset: dict[str, Any] = {}


def create_reset_code(username: str) -> None:
    """Generate a one-time reset code and print it to the container log (docker logs)."""
    if _reset and time.time() - _reset.get("created", 0) < 60:
        return  # at most one code per minute
    raw = secrets.token_hex(4).upper()
    code = f"{raw[:4]}-{raw[4:]}"
    _reset.clear()
    _reset.update(username=username, hash=hashlib.sha256(code.encode()).hexdigest(), created=time.time(), attempts=0)
    log.warning("=" * 72)
    log.warning("PASSWORD/MFA RESET requested for user '%s'", username)
    log.warning("Reset code: %s   (valid 15 minutes, single use, enter it at /reset)", code)
    log.warning("=" * 72)


def check_reset_code(code: str) -> str | None:
    """Return the username the code was issued for, or None. The code is consumed on success."""
    if not _reset or time.time() - _reset["created"] > RESET_TTL:
        _reset.clear()
        return None
    _reset["attempts"] += 1
    if _reset["attempts"] > 5:
        _reset.clear()
        log.warning("reset code invalidated after too many wrong attempts")
        return None
    normalized = code.strip().upper().replace(" ", "")
    if len(normalized) == 8:
        normalized = normalized[:4] + "-" + normalized[4:]
    if hmac.compare_digest(hashlib.sha256(normalized.encode()).hexdigest(), _reset["hash"]):
        user = _reset["username"]
        _reset.clear()
        return user
    return None


async def reset_user(username: str, new_password: str) -> None:
    """Set a new password and remove every MFA factor (the user must enroll MFA again)."""
    pool = db.pool()
    user = await get_user_by_name(username)
    pw_hash = await asyncio.to_thread(hash_password, new_password)
    if user is None:
        await pool.execute("INSERT INTO users (username, password_hash) VALUES ($1, $2)", username, pw_hash)
    else:
        await pool.execute(
            "UPDATE users SET password_hash = $2, totp_secret = NULL, totp_enabled = false, "
            "session_version = session_version + 1 WHERE id = $1", user["id"], pw_hash)
        await pool.execute("DELETE FROM webauthn_credentials WHERE user_id = $1", user["id"])
    log.warning("password and MFA reset for user '%s'", username)


# --------------------------------------------------------- rate limiting ---
_failures: dict[str, list[float]] = {}


def too_many_failures(key: str, limit: int = 10, window: int = 900) -> bool:
    now = time.time()
    hits = [t for t in _failures.get(key, []) if now - t < window]
    _failures[key] = hits
    return len(hits) >= limit


def record_failure(key: str) -> None:
    _failures.setdefault(key, []).append(time.time())


def clear_failures(key: str) -> None:
    _failures.pop(key, None)
