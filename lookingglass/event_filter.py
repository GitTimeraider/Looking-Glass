"""Event-search filters -> SQL: the Event search page, and the ports an alert shows (taken from the same events its
Events button lists).

``params``: the search's query parameters - source, ip (either side) / src / dst (comma separated IPs or CIDRs),
action ("a,b" any of, "http_4*" prefix), q (text), min_severity, hours or start / end (ISO), sport / dport (ports and
ranges: "22, 8000-8100"; ``port`` = dport, from dashboard links), program, host, domain, user, proto, iface,
direction, country and ``d_<key>`` for a key inside the event's JSON data (``none`` matches an empty value).
A wrong value raises ValueError with a message for the user.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

SIMPLE = {"program": "program", "host": "host", "domain": "domain", "user": "username", "proto": "proto",
          "iface": "interface", "direction": "direction", "country": "src_country"}


def ports(value: str, label: str) -> tuple[list[int], list[tuple[int, int]]]:
    """'22, 80 8000-8100' -> ([22, 80], [(8000, 8100)])"""
    single, ranges = [], []
    for part in re.split(r"[,\s]+", value.strip()):
        if not part:
            continue
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", part)
        lo, hi = (int(m[1]), int(m[2] or m[1])) if m else (-1, -1)
        if not m or not (0 <= lo <= hi <= 65535):
            raise ValueError(f"{label}: '{part}' is not a port (0-65535) or range (8000-8100)")
        if lo == hi:
            single.append(lo)
        else:
            ranges.append((lo, hi))
    return single, ranges


def nets(value: str, label: str) -> list[str]:
    out = []
    for part in re.split(r"[,\s]+", value.strip()):
        if not part:
            continue
        try:
            out.append(str(ipaddress.ip_network(part, strict=False)))
        except ValueError as exc:
            raise ValueError(f"{label}: '{part}' is not an IP address or CIDR") from exc
    return out


def build(params: Mapping[str, Any], args: list[Any] | None = None) -> tuple[list[str], list[Any]]:
    """(WHERE conditions, their arguments) for ``params``; ``args`` continues an argument list ($n numbering)."""
    where: list[str] = []
    args = [] if args is None else args

    def arg(v: Any) -> str:
        args.append(v)
        return f"${len(args)}"

    def get(key: str) -> str | None:
        v = params.get(key)
        return None if v is None else str(v)

    start, end = get("start"), get("end")
    if start or end:
        try:
            t0 = datetime.fromisoformat(start.replace("Z", "+00:00")) if start else None
            t1 = datetime.fromisoformat(end.replace("Z", "+00:00")) if end else None
        except ValueError as exc:
            raise ValueError("start/end must be ISO timestamps") from exc
        if t0:
            where.append(f"ts >= {arg(t0)}")
        if t1:
            where.append(f"ts < {arg(t1)}")
    else:
        where.append(f"ts > now() - make_interval(secs => {arg(float(params.get('hours') or 24) * 3600)})")
    if source := get("source"):
        where.append(f"source = ANY({arg(source.split(','))}::text[])")
    for key, cols, label in (("ip", ("src_ip", "dst_ip"), "IP"), ("src", ("src_ip",), "Source IP"),
                             ("dst", ("dst_ip",), "Destination IP")):
        if (value := get(key)) and value.strip():
            a = arg(nets(value, label))
            where.append("(" + " OR ".join(f"{c} <<= ANY({a}::inet[])" for c in cols) + ")")
    for key, col, label in (("sport", "src_port", "Source port"), ("dport", "dst_port", "Destination port"),
                            ("port", "dst_port", "Destination port")):
        if (value := get(key)) and value.strip():
            single, ranges = ports(value, label)
            conds = ([f"{col} = ANY({arg(single)}::int[])"] if single else []) + \
                    [f"{col} BETWEEN {arg(lo)} AND {arg(hi)}" for lo, hi in ranges]
            if conds:
                where.append("(" + " OR ".join(conds) + ")")
    if action := get("action"):  # "a,b" = any of; "http_4*" = prefix
        acts = action.split(",")
        exact, prefixes = [a for a in acts if not a.endswith("*")], [a[:-1] + "%" for a in acts if a.endswith("*")]
        conds = ([f"action = ANY({arg(exact)}::text[])"] if exact else []) + \
                ([f"action LIKE ANY({arg(prefixes)}::text[])"] if prefixes else [])
        where.append("(" + " OR ".join(conds) + ")")
    if q := get("q"):
        a = arg(f"%{q}%")
        where.append(f"(message ILIKE {a} OR domain ILIKE {a} OR username ILIKE {a} OR program ILIKE {a})")
    if (sev := get("min_severity")) not in (None, ""):
        where.append(f"severity <= {arg(int(sev))}")
    for param, col in SIMPLE.items():
        if (v := get(param)) is not None:
            where.append(f"{col} IS NULL" if v == "none" else f"{col} = {arg(v)}")
    for key, v in params.items():
        if key.startswith("d_") and re.fullmatch(r"d_[A-Za-z0-9_]{1,40}", key):
            k = arg(key[2:])
            where.append(f"coalesce(data->>{k}, '') = ''" if v == "none" else f"data->>{k} = {arg(str(v))}")
    return where, args
