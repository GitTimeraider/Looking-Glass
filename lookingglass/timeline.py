"""Incident timeline (General › Timeline): everything about one device or address over a time span, in one list.

Merged, newest first:
* alerts with the address as source or destination (with their comments),
* its events, grouped per time step, source, action, direction, remote address / domain / user and port, so a
  thousand DNS lookups of one domain in ten minutes are one line "×1000",
* blocks and snoozes that covered it,
* when the device was first seen.
A device (MAC) covers every address it had (devices.ips). The step grows with the span: 1 minute for an hour,
10 minutes for a day, an hour for a week.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any

from . import db

MAX_HOURS = 24 * 31
MAX_GROUPS = 3000

# event source -> timeline category (the filter chips of the page)
CATEGORY = {"auth": "login", "vpn": "login", "unbound": "dns", "firewall": "firewall", "nginx": "web",
            "suricata": "threat", "crowdsec": "threat", "qfeeds": "threat", "dhcp": "device", "unifi": "device"}


def category(source: str) -> str:
    return CATEGORY.get(source, "other")


def step_for(hours: float) -> int:
    """Seconds per group: about 100-150 steps over the span."""
    for limit, step in ((2, 60), (6, 300), (24, 600), (72, 1800), (168, 3600), (336, 3 * 3600)):
        if hours <= limit:
            return step
    return 6 * 3600


def span(hours: float | None = None, start: str | None = None, end: str | None = None,
         now: datetime | None = None) -> tuple[datetime, datetime]:
    now = now or datetime.now(timezone.utc)

    def parse(v: str) -> datetime:
        dt = datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    try:
        t1 = parse(end) if end else now
        t0 = parse(start) if start else t1 - timedelta(hours=float(hours or 24))
    except ValueError as exc:
        raise ValueError("start / end must be ISO timestamps") from exc
    if t1 <= t0:
        raise ValueError("the end must be after the start")
    if t1 - t0 > timedelta(hours=MAX_HOURS):
        t0 = t1 - timedelta(hours=MAX_HOURS)
    return t0, t1


async def subject(ip: str | None = None, mac: str | None = None) -> dict[str, Any]:
    """The device / address the timeline is about: its addresses and what is known of it."""
    pool = db.pool()
    dev = None
    if mac:
        dev = await pool.fetchrow("SELECT * FROM devices WHERE mac = $1", mac.strip().lower())
        if not dev:
            raise ValueError(f"unknown device {mac}")
    elif ip:
        try:
            ip = str(ipaddress.ip_address(ip.strip()))
        except ValueError as exc:
            raise ValueError(f"'{ip}' is not an IP address") from exc
        dev = await pool.fetchrow(
            "SELECT * FROM devices WHERE ip = $1::inet OR $1::inet = ANY(coalesce(ips, '{}'::inet[])) "
            "ORDER BY last_seen DESC LIMIT 1", ip)
    else:
        raise ValueError("choose a device or an IP address")
    ips: list[str] = []
    if dev:
        ips = [str(x) for x in ([dev["ip"]] + list(dev["ips"] or [])) if x]
    if ip and ip not in ips:
        ips.insert(0, ip)
    ips = list(dict.fromkeys(str(ipaddress.ip_interface(x).ip) for x in ips))
    info = None
    if dev:
        info = {k: db.jsonable(dev[k]) for k in ("mac", "hostname", "vendor", "interface", "first_seen", "last_seen",
                                                  "online", "trusted", "notes", "conn_where", "device_type")}
    return {"ips": ips, "device": info, "ip": ip or (ips[0] if ips else None)}


async def build(ip: str | None = None, mac: str | None = None, hours: float | None = 24, start: str | None = None,
                end: str | None = None) -> dict[str, Any]:
    subj = await subject(ip, mac)
    t0, t1 = span(hours, start, end)
    hrs = (t1 - t0).total_seconds() / 3600
    step = step_for(hrs)
    ips = subj["ips"]
    pool = db.pool()
    items: list[dict[str, Any]] = []
    if not ips:
        return {**subj, "start": t0.isoformat(), "end": t1.isoformat(), "step": step, "items": [], "chart": [],
                "truncated": False, "counts": {}}

    # alerts
    alerts = await pool.fetch(
        "SELECT id, created_at, last_seen, rule, severity, title, status, close_reason, host(src_ip) src_ip, "
        "host(dst_ip) dst_ip, count, data->'stages' AS stages, data->'snoozed' AS snoozed FROM alerts "
        "WHERE (src_ip = ANY($1::inet[]) OR dst_ip = ANY($1::inet[])) AND last_seen >= $2 AND created_at <= $3 "
        "ORDER BY created_at DESC LIMIT 500", ips, t0, t1)
    comments: dict[int, list] = {}
    if alerts:
        for c in await pool.fetch("SELECT alert_id, created_at, author, body FROM alert_comments "
                                  "WHERE alert_id = ANY($1::bigint[]) ORDER BY created_at", [a["id"] for a in alerts]):
            comments.setdefault(c["alert_id"], []).append(db.jsonable(dict(c)))
    for a in alerts:
        d = db.jsonable(dict(a))
        items.append({"kind": "alert", "cat": "alert", "ts": d["created_at"], "last": d["last_seen"], **d,
                      "comments": comments.get(a["id"], [])})

    # events, grouped
    async with db.heavy(hrs), pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT date_bin(make_interval(secs => $4), ts, timestamptz '2000-01-01') b, source, coalesce(action, '') action, "
            "src_ip = ANY($1::inet[]) AS outgoing, "
            "host(CASE WHEN src_ip = ANY($1::inet[]) THEN dst_ip ELSE src_ip END) peer, "
            "CASE WHEN src_ip = ANY($1::inet[]) THEN dst_country ELSE src_country END country, "
            "dst_port, domain, username, count(*) n, min(ts) first, max(ts) last, min(message) sample, "
            "min(severity) worst "
            "FROM events WHERE (src_ip = ANY($1::inet[]) OR dst_ip = ANY($1::inet[])) AND ts >= $2 AND ts < $3 "
            "GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9 ORDER BY 1 DESC, n DESC LIMIT $5",
            ips, t0, t1, step, MAX_GROUPS + 1)
        chart = await conn.fetch(
            "SELECT date_bin(make_interval(secs => $4), ts, timestamptz '2000-01-01') b, source, count(*) n FROM events "
            "WHERE (src_ip = ANY($1::inet[]) OR dst_ip = ANY($1::inet[])) AND ts >= $2 AND ts < $3 GROUP BY 1, 2 ORDER BY 1",
            ips, t0, t1, step)
    truncated = len(rows) > MAX_GROUPS
    for r in rows[:MAX_GROUPS]:
        d = db.jsonable(dict(r))
        sample = (d.pop("sample") or "")[:300]
        items.append({"kind": "events", "cat": category(d["source"]), "ts": d["first"], "bucket": d.pop("b"),
                      **d, "sample": sample})

    # blocks and snoozes
    for b in await pool.fetch(
            "SELECT id, host(ip) ip, created_at, expires_at, created_by, reason, auto, status, removed_at, removed_by "
            "FROM blocks WHERE ip >>= ANY($1::inet[]) AND created_at <= $3 "
            "AND (removed_at IS NULL OR removed_at >= $2)", ips, t0, t1):
        d = db.jsonable(dict(b))
        items.append({"kind": "block", "cat": "response", "ts": d["created_at"], **d})
    from . import snooze
    for sn in await pool.fetch("SELECT id, name, starts_at, ends_at, networks, rules, created_by, hits FROM snoozes "
                               "WHERE starts_at <= $2 AND ends_at >= $1", t0, t1):
        # only snoozes for this address (one for everything says nothing about this device)
        if sn["networks"] and any(snooze.matches({**dict(sn), "rules": []}, "", ip, None, now=sn["starts_at"]) for ip in ips):
            d = db.jsonable(dict(sn))
            items.append({"kind": "snooze", "cat": "response", "ts": d["starts_at"], **d})

    dev = subj.get("device")
    if dev and dev.get("first_seen") and t0.isoformat() <= dev["first_seen"] <= t1.isoformat():
        items.append({"kind": "first_seen", "cat": "device", "ts": dev["first_seen"]})

    items.sort(key=lambda x: x["ts"] or "", reverse=True)
    counts: dict[str, int] = {}
    for it in items:
        counts[it["cat"]] = counts.get(it["cat"], 0) + (it.get("n") or 1)
    return {**subj, "start": t0.isoformat(), "end": t1.isoformat(), "step": step, "items": items,
            "chart": [{"t": r["b"].isoformat(), "source": r["source"], "n": r["n"]} for r in chart],
            "truncated": truncated, "counts": counts}
