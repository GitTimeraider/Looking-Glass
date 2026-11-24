"""The OPNsense CrowdSec plugin and CrowdSec in Docker (next to SWAG) sharing one Local API.

OPNsense's CrowdSec can be a log processor / bouncer of another CrowdSec: it then logs in to that one's Local API, and
``cscli`` on OPNsense lists that Local API's alerts and decisions - the same ones Looking Glass already reads from it
directly (crowdsec_lapi.py). Every alert and decision would be stored twice (program ``crowdsec`` and
``crowdsec-lapi``) and counted twice: totals, attackers, correlation, and a "CrowdSec (OPNsense)" next to every
"CrowdSec (SWAG)" alert.

It works the other way round too: CrowdSec in Docker logs in to OPNsense's Local API, and Settings › SWAG & CrowdSec
points at OPNsense. Either way Looking Glass keeps the copy it reads from the Local API directly (it has more: target
site, URI, AppSec rule ...) and drops the plugin's. Which one IS the Local API only decides where Unban is offered:
Settings › OPNsense › Shared CrowdSec Local API (auto / docker / opnsense / no):

* docker: the Docker CrowdSec (SWAG) is the Local API, OPNsense's logs in to it;
* opnsense: OPNsense's is the Local API, the Docker CrowdSec logs in to it;
* no: two separate CrowdSecs;
* auto: shared when recognised (below); the Local API is OPNsense's when the URL of Settings › SWAG & CrowdSec points
  at the OPNsense host, else the Docker one.

Shared:

* the OPNsense poller stores none of the plugin's alerts / decisions (they come from the Local API), only its
  Active bans list (the same decisions, the Unban button works from either list);
* the OPNsense pages (Threats › CrowdSec, the Threats tiles) read the Local API's events instead of the plugin's;
* on becoming shared, the copies already stored are removed once and the open "CrowdSec (OPNsense)" alerts that have
  a "CrowdSec (SWAG)" twin are closed.

auto: the same alert / decision ids for the same addresses in both is a shared Local API (two separate CrowdSecs
number their alerts independently - the same id for the same address twice is no coincidence). Decided again at
every pull of the plugin; until it is known, both are kept apart as before.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from . import db, rollup

log = logging.getLogger("lookingglass.crowdsec_shared")

KEY = "crowdsec_shared"
MATCH = 2  # this many alerts / decisions with the same id and address in both: one Local API
APART = 20  # both have at least this many alerts and none matches: two CrowdSecs
# an alert / decision event -> "a|<id>|<address>" / "d|<id>|<address or value>", the same for both CrowdSecs
_EVENT_KEY = ("CASE WHEN action = 'alert' THEN 'a|' ELSE 'd|' END || coalesce(data->>'id', '') || '|' || "
              "coalesce(host(src_ip), data->>'value', '')")
# the plugin's copy of an event Looking Glass also has from the Local API (same kind, id and address)
DUPLICATE = ("source = 'crowdsec' AND program IS DISTINCT FROM 'crowdsec-lapi' AND data ? 'id' AND EXISTS ("
             "SELECT 1 FROM events l WHERE l.source = 'crowdsec' AND l.program = 'crowdsec-lapi' "
             "AND l.action IS NOT DISTINCT FROM events.action AND l.data->>'id' = events.data->>'id' "
             "AND l.src_ip IS NOT DISTINCT FROM events.src_ip)")


MODES = ("auto", "docker", "opnsense", "no")
_CACHE_SECONDS = 30.0  # dashboards ask at every refresh: the snapshot is read at most this often
_cache: tuple[float, dict[str, Any]] = (0.0, {})


def mode(settings: Any) -> str:
    m = str(getattr(settings, "crowdsec_shared_lapi", "auto") or "auto").lower()
    m = "docker" if m == "yes" else m  # the first version of the setting: yes = the Docker CrowdSec's Local API
    return m if m in MODES else "auto"


def _host(url: str | None) -> str:
    try:
        return (urlsplit(str(url or "")).hostname or "").lower()
    except ValueError:
        return ""


def primary(settings: Any) -> str:
    """Which CrowdSec is the Local API: "docker" or "opnsense" (by the setting, or auto: where the Local API URL of
    Settings › SWAG & CrowdSec points)."""
    m = mode(settings)
    if m in ("docker", "opnsense"):
        return m
    lapi = _host(getattr(settings, "crowdsec_lapi_url", ""))
    return "opnsense" if lapi and lapi == _host(getattr(settings, "opnsense_url", "")) else "docker"


def possible(settings: Any) -> bool:
    """Both CrowdSecs are read: the OPNsense plugin and a Local API (Settings › SWAG & CrowdSec)."""
    return bool(settings.opnsense_enabled and getattr(settings, "crowdsec_pull", True) and settings.crowdsec_lapi_enabled)


async def _state() -> dict[str, Any]:
    global _cache
    if time.monotonic() - _cache[0] > _CACHE_SECONDS:
        snap = await db.get_snapshot(KEY)
        _cache = (time.monotonic(), snap if isinstance(snap, dict) else {})
    return _cache[1]


async def is_shared(settings: Any) -> bool:
    if not possible(settings) or mode(settings) == "no":
        return False
    if mode(settings) in ("docker", "opnsense"):
        return True
    return bool((await _state()).get("shared"))


async def shared_primary(settings: Any) -> str | None:
    """None: two CrowdSecs (or not known yet); else which one is the Local API ("docker" / "opnsense")."""
    return primary(settings) if await is_shared(settings) else None


def event_key(ev: dict[str, Any]) -> str | None:
    """The plugin's alert / decision event -> its key (see _EVENT_KEY), None without an id."""
    data = ev.get("data") or {}
    if data.get("id") in (None, ""):
        return None
    what = ev.get("src_ip") or data.get("value") or ""
    return f"{'a' if ev.get('action') == 'alert' else 'd'}|{data['id']}|{what}"


async def detect(keys: list[str], plugin_alerts: int, prev: dict[str, Any]) -> dict[str, Any]:
    """How many of the plugin's alerts / decisions Looking Glass also has from the Local API (last 30 days)."""
    row = await db.pool().fetchrow(
        f"SELECT count(DISTINCT k) FILTER (WHERE k = ANY($1::text[])) matched, count(*) FILTER (WHERE action = 'alert') "
        f"alerts FROM (SELECT action, {_EVENT_KEY} k FROM events WHERE source = 'crowdsec' AND program = 'crowdsec-lapi' "
        f"AND ts > now() - interval '30 days') x", keys)
    shared = prev.get("shared")
    if row["matched"] >= MATCH:
        shared = True
    elif row["matched"] == 0 and row["alerts"] >= APART and plugin_alerts >= APART:
        shared = False
    return {**prev, "shared": shared, "matched": row["matched"], "checked": len(keys)}


async def sync(settings: Any, plugin_events: list[dict[str, Any]]) -> bool:
    """At every pull of the OPNsense plugin: is it the same Local API? True = store none of its events."""
    if not possible(settings) or mode(settings) == "no":
        return False
    prev = await db.get_snapshot(KEY)
    prev = prev if isinstance(prev, dict) else {}
    state = dict(prev)
    if mode(settings) == "auto":
        keys = [k for k in (event_key(e) for e in plugin_events) if k]
        if keys:
            state = await detect(keys, sum(1 for e in plugin_events if e.get("action") == "alert"), prev)
    shared = mode(settings) in ("docker", "opnsense") or bool(state.get("shared"))
    if shared and not prev.get("cleaned"):
        state["removed"] = await forget_duplicates()
        state["cleaned"] = True
    elif not shared:
        state["cleaned"] = False
    if shared != bool(prev.get("shared_now")):
        log.info("CrowdSec: the OPNsense plugin %s the Local API of Settings › SWAG & CrowdSec (%s)",
                 "uses" if shared else "does not use", mode(settings))
    state.update(mode=mode(settings), shared_now=shared, primary=primary(settings) if shared else None,
                 at=datetime.now(timezone.utc).isoformat())
    await db.set_snapshot(KEY, state)
    global _cache
    _cache = (time.monotonic(), state)
    return shared


async def forget_duplicates() -> int:
    """Once, on becoming shared: the plugin's copies stored so far go, and its open alerts with a SWAG twin close."""
    from .detections import close_alerts  # detections imports this module's is_shared

    n = await rollup.delete_events(DUPLICATE)
    twins = [r["fingerprint"] for r in await db.pool().fetch(
        "SELECT a.fingerprint FROM alerts a WHERE a.rule = 'crowdsec' AND a.fingerprint LIKE 'crowdsec:%' "
        "AND a.status <> 'closed' AND EXISTS (SELECT 1 FROM alerts b WHERE b.rule = 'crowdsec' "
        "AND b.fingerprint = 'crowdsec-lapi:' || substr(a.fingerprint, 10))")]
    if twins:
        await close_alerts("crowdsec", twins, "the same CrowdSec as CrowdSec (SWAG): OPNsense uses its Local API")
    log.info("CrowdSec shared Local API: removed %d duplicate events, closed %d duplicate alerts", n, len(twins))
    return n
