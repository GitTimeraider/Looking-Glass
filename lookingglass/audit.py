"""Audit log: who did what in the web UI (Admin › Audit log).

Recorded: logins (successful and failed), log-outs, password / MFA changes and every change made through the API
(POST / PUT / PATCH / DELETE under /api/, with the HTTP status of the answer). An endpoint can add what exactly it
changed by setting ``request.state.audit`` (a dict) - e.g. the settings page stores the names of the changed
settings, never their values. Writing the log never fails the request it records.
"""
from __future__ import annotations

import logging
from typing import Any

from . import db

log = logging.getLogger(__name__)

# API calls that change nothing worth recording: page layouts, refresh buttons, previews and connection tests
SKIP_PREFIXES = ("/api/layout/", "/api/periods/")
SKIP_SUFFIXES = ("/preview", )
SKIP_PATHS = {"/api/ai/message"}  # the conversation itself is stored (AI analyst); every question would be noise

# readable names for the most common changes; anything else is shown as "<METHOD> <path>"
LABELS = [
    ("PUT", "/api/settings", "Settings changed"),
    ("POST", "/api/alerts/status", "Alert status changed"),
    ("POST", "/api/alerts/delete", "Alerts deleted"),
    ("POST", "/api/admin/purge", "Collected data deleted"),
    ("POST", "/api/admin/backup", "Backup downloaded"),
    ("POST", "/api/blocks", "Address blocked"),
    ("DELETE", "/api/blocks/", "Block removed"),
    ("POST", "/api/blocks/sync", "Block alias synced"),
    ("POST", "/api/snoozes", "Snooze created"),
    ("PUT", "/api/snoozes/", "Snooze changed"),
    ("DELETE", "/api/snoozes/", "Snooze removed"),
    ("POST", "/api/snoozes/", "Snooze ended"),
    ("POST", "/api/alert-filters", "Alert filter created"),
    ("PUT", "/api/alert-filters/", "Alert filter changed"),
    ("DELETE", "/api/alert-filters/", "Alert filter deleted"),
    ("POST", "/api/notification-rules", "Notification rule created"),
    ("PUT", "/api/notification-rules/", "Notification rule changed"),
    ("DELETE", "/api/notification-rules/", "Notification rule deleted"),
    ("POST", "/api/devices/", "Device changed"),
    ("DELETE", "/api/devices/", "Device deleted"),
    ("POST", "/api/unraid/servers", "Unraid server added"),
    ("PUT", "/api/unraid/servers/", "Unraid server changed"),
    ("DELETE", "/api/unraid/servers/", "Unraid server removed"),
    ("POST", "/api/account/password", "Password changed"),
    ("POST", "/api/account/totp/confirm", "Authenticator app set up"),
    ("POST", "/api/account/totp/disable", "Authenticator app removed"),
    ("POST", "/api/account/passkey/verify", "Passkey added"),
    ("DELETE", "/api/account/passkey/", "Passkey removed"),
    ("POST", "/api/settings/test/", "Connection tested"),
]


def wanted(method: str, path: str) -> bool:
    """A request that changes something and is worth a line in the audit log."""
    if method in ("GET", "HEAD", "OPTIONS") or not path.startswith("/api/"):
        return False
    return not (path in SKIP_PATHS or path.startswith(SKIP_PREFIXES) or path.endswith(SKIP_SUFFIXES))


def label(method: str, path: str) -> str:
    for m, prefix, text in LABELS:
        if m == method and (path == prefix or (prefix.endswith("/") and path.startswith(prefix))):
            return text
    return f"{method} {path}"


async def record(action: str, username: str | None = None, ip: str | None = None, target: str | None = None,
                 status: int | None = None, detail: dict[str, Any] | None = None) -> None:
    """Add one line; problems (database gone ...) are logged, never raised."""
    try:
        await db.pool().execute(
            "INSERT INTO audit_log (username, ip, action, target, status, detail) VALUES ($1, $2, $3, $4, $5, $6)",
            (username or None) and str(username)[:100], (ip or None) and str(ip)[:64], action[:40],
            (target or None) and str(target)[:300], status, detail or None)
    except Exception:  # noqa: BLE001
        log.warning("audit log: could not record %s %s", action, target, exc_info=True)


async def listing(limit: int = 200, offset: int = 0, action: str | None = None, user: str | None = None,
                  q: str | None = None) -> dict[str, Any]:
    where, args = ["true"], []

    def arg(v: Any) -> str:
        args.append(v)
        return f"${len(args)}"

    if action:
        where.append(f"action = {arg(action)}")
    if user:
        where.append(f"username = {arg(user)}")
    if q:
        where.append(f"(coalesce(target, '') || ' ' || coalesce(detail::text, '') || ' ' || coalesce(ip, '')) ILIKE {arg('%' + q + '%')}")
    rows = await db.pool().fetch(
        f"SELECT id, ts, username, ip, action, target, status, detail FROM audit_log WHERE {' AND '.join(where)} "
        f"ORDER BY id DESC LIMIT {arg(limit + 1)} OFFSET {arg(offset)}", *args)
    out = db.records(rows)
    for r in out:
        method, _, path = (r.get("target") or "").partition(" ")
        r["label"] = label(method, path) if r["action"] == "change" and path else None
    users = [r["username"] for r in await db.pool().fetch(
        "SELECT DISTINCT username FROM audit_log WHERE username IS NOT NULL ORDER BY 1 LIMIT 100")]
    return {"rows": out[:limit], "has_more": len(out) > limit, "users": users}


async def cleanup(days: int = 365) -> None:
    await db.pool().execute("DELETE FROM audit_log WHERE ts < now() - make_interval(days => $1)", days)
