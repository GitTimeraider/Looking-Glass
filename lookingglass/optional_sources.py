"""Is Zenarmor set up? Its menu entry, dashboard and widgets are only shown when it is.

Zenarmor has no switch in Looking Glass: it is set up when it sends records (Elasticsearch stream or syslog). The answer
is kept in memory, so pages never wait for it: a background task asks the database every few minutes (one index
lookup), and the event writer turns it on as soon as the first Zenarmor record arrives. Unknown (not checked yet)
counts as set up, so nothing disappears by mistake right after a start.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from . import db

log = logging.getLogger(__name__)

RECENT_DAYS = 7  # no Zenarmor record for this long: treated as not (or no longer) set up
REFRESH_S = 300

_zenarmor: bool | None = None


def zenarmor() -> bool:
    """True when Zenarmor sent records in the last RECENT_DAYS days (or before the first check)."""
    return _zenarmor is not False


def set_zenarmor(value: bool | None) -> None:
    global _zenarmor
    _zenarmor = value


async def refresh() -> bool:
    global _zenarmor
    _zenarmor = bool(await db.pool().fetchval(
        "SELECT EXISTS (SELECT 1 FROM events WHERE source = 'zenarmor' AND ts > now() - make_interval(days => $1))",
        RECENT_DAYS))
    return _zenarmor


async def loop() -> None:
    """Re-check every few minutes (the first check runs at start-up, see main.py)."""
    while True:
        await asyncio.sleep(REFRESH_S)
        try:
            await refresh()
        except Exception:  # noqa: BLE001
            log.exception("checking whether Zenarmor is set up failed")


async def listener(items: list[dict[str, Any]]) -> None:
    """Event writer hook: the first Zenarmor record shows its menu entry and widgets right away."""
    global _zenarmor
    if _zenarmor is not True and any(ev.get("source") == "zenarmor" for ev in items):
        _zenarmor = True
