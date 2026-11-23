"""Snooze / maintenance windows: for a while, store matching alerts silently instead of showing and mailing them.

A snooze has a time window (start, end), and optionally IP addresses / networks (source or destination of the
alert) and rules. Both conditions empty = every alert. Inside a window a matching NEW alert is stored like a
"silent" one (closed, close_reason 'muted', data.snoozed): never shown as open, never mailed, but it still counts for
attack chains, corroboration and the risk score - a real attack during maintenance is not lost. Alerts that were
already open stay open; the notifier does not mail them while a snooze covers them.

Snoozes are cached (they are checked for every alert) and re-read after every change and once a minute.
"""
from __future__ import annotations

import ipaddress
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from . import alert_filters as af
from . import db, mute_schedule
from .config import get_settings

log = logging.getLogger(__name__)

MAX_DAYS = 31
_cache: dict[str, Any] = {"at": None, "rows": []}


def invalidate() -> None:
    _cache["at"] = None


def _when(value: Any, label: str) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"{label}: not a date and time") from exc
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def clean(payload: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """Validate a snooze from the web UI: start (default now), end or minutes, networks, rules, name."""
    now = now or datetime.now(timezone.utc)
    starts = _when(payload.get("starts_at"), "Start") or now
    ends = _when(payload.get("ends_at"), "End")
    if ends is None:
        try:
            minutes = int(payload.get("minutes") or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("the duration must be a number of minutes") from exc
        if minutes <= 0:
            raise ValueError("Choose how long, or an end time.")
        ends = starts + timedelta(minutes=minutes)
    if ends <= starts:
        raise ValueError("The end must be after the start.")
    if ends <= now:
        raise ValueError("The end lies in the past.")
    if ends - starts > timedelta(days=MAX_DAYS):
        raise ValueError(f"A snooze can last at most {MAX_DAYS} days - use an alert filter (Mute similar…) for longer.")
    nets = af.parse_nets(payload.get("networks"))
    rules = sorted({str(r).strip() for r in payload.get("rules") or [] if str(r).strip()})
    unknown = [r for r in rules if r not in af.RULE_NAMES]
    if unknown:
        raise ValueError(f"unknown rule {', '.join(unknown)}")
    return {"name": str(payload.get("name") or "").strip()[:100] or None, "starts_at": starts, "ends_at": ends,
            "networks": ", ".join(str(n) for n in nets) or None, "rules": rules}


async def _active() -> list[dict[str, Any]]:
    if _cache["at"] is None or time.monotonic() - _cache["at"] > 60:
        rows = await db.pool().fetch("SELECT id, name, starts_at, ends_at, networks, rules FROM snoozes "
                                     "WHERE ends_at > now() ORDER BY id")
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["_nets"] = af.parse_nets(d.get("networks"))
            except ValueError:
                continue
            out.append(d)
        _cache.update(at=time.monotonic(), rows=out)
    return _cache["rows"]


def matches(sn: dict[str, Any], rule: str, src_ip: str | None, dst_ip: str | None, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    if not (sn["starts_at"] <= now < sn["ends_at"]):
        return False
    if sn.get("rules") and rule not in sn["rules"]:
        return False
    nets = sn.get("_nets")
    if nets is None:
        nets = af.parse_nets(sn.get("networks"))
    if nets:
        addrs = []
        for ip in (src_ip, dst_ip):
            try:
                if ip:
                    addrs.append(ipaddress.ip_address(str(ip).split("/")[0]))
            except ValueError:
                pass
        if not any(a in n for a in addrs for n in nets if a.version == n.version):
            return False
    return True


async def check(rule: str, src_ip: str | None, dst_ip: str | None) -> dict[str, Any] | None:
    """The active snooze that covers this alert (and count the hit), else None. Never raises."""
    try:
        now = datetime.now(timezone.utc)
        for sn in await _active():
            if matches(sn, rule, src_ip, dst_ip, now):
                await db.pool().execute("UPDATE snoozes SET hits = hits + 1, last_hit = now() WHERE id = $1", sn["id"])
                return {"id": sn["id"], "name": sn.get("name") or f"snooze #{sn['id']}",
                        "until": sn["ends_at"].isoformat()}
        return recurring(rule, now)
    except Exception:  # noqa: BLE001 - a broken snooze must never lose an alert
        log.exception("snooze check failed")
    return None


def recurring(rule: str, now: datetime | None = None) -> dict[str, Any] | None:
    """The recurring mute window (Settings › Alert filters) that covers an alert of ``rule`` now, else None."""
    s = get_settings()
    return mute_schedule.covering(s.mute_schedule, s.timezone, rule, now)


async def covering(alerts: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    """For the notifier and the Alerts page: alert id -> the active snooze that covers it right now."""
    out: dict[int, dict[str, Any]] = {}
    try:
        active = await _active()
    except Exception:  # noqa: BLE001
        active = []
    now = datetime.now(timezone.utc)
    for a in alerts:
        for sn in active:
            if matches(sn, a.get("rule") or "", a.get("src_ip"), a.get("dst_ip"), now):
                out[a["id"]] = {"id": sn["id"], "name": sn.get("name") or f"snooze #{sn['id']}",
                                "until": sn["ends_at"].isoformat()}
                break
        else:
            try:
                if rec := recurring(a.get("rule") or "", now):
                    out[a["id"]] = rec
            except Exception:  # noqa: BLE001
                log.exception("recurring mute window check failed")
    return out


async def listing() -> list[dict[str, Any]]:
    rows = await db.pool().fetch(
        "SELECT id, created_at, created_by, name, starts_at, ends_at, networks, rules, hits, last_hit, "
        "CASE WHEN ends_at <= now() THEN 'ended' WHEN starts_at > now() THEN 'planned' ELSE 'active' END AS state "
        "FROM snoozes WHERE ends_at > now() - interval '30 days' "
        "ORDER BY (ends_at > now()) DESC, starts_at DESC LIMIT 300")
    return db.records(rows)
