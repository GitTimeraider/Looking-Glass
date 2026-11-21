"""Event-search filters -> SQL: the Event search page, and the ports an alert shows (taken from the same events its
Events button lists).

``params``: the search's query parameters - source, ip (either side) / src / dst (comma separated IPs or CIDRs),
action ("a,b" any of, "http_4*" prefix), q (text), min_severity, hours or start / end (ISO), sport / dport (ports and
ranges: "22, 8000-8100"; ``port`` = dport, from dashboard links), program, host, domain, user, proto, iface,
direction, country, src_scope (``local`` = the source address is a local one - private, CGNAT, loopback,
link-local - ``public`` = it is any other address; events without a source address match neither), status (web server: "2xx", "4xx,5xx", "404", "other" = not an HTTP answer), tag (web server
attack / scanner patterns: "any" = suspicious, "none", or "sqli,rce") and ``d_<key>`` for a key inside the event's
JSON data (``none`` matches an empty value).
A wrong value raises ValueError with a message for the user.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

# "local" source addresses: private (RFC 1918 / ULA), CGNAT (also Tailscale), loopback and link-local
LOCAL_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
              "fc00::/7", "fe80::/10", "::1/128"]
SRC_SCOPES = ("local", "public")

# a local source address - private, CGNAT, loopback (127.0.0.1: the SWAG host / container itself), link-local: the same
# as Event search's "Source: local" (and the honeypot alert's INTERNAL, which also counts Settings › Internal networks)
LOCAL_SRC = "(" + " OR ".join(f"src_ip <<= '{n}'" for n in LOCAL_NETS) + ")"

# page-wide From filter (dashboards with "scope": True - SWAG & CrowdSec): every query of the page reads only the events
# from local / non-local (public) source addresses. Each "FROM events" / "JOIN events" becomes a filtered subquery that
# Postgres folds into the same plan, so it costs one address test per row read. Snapshots (bans now, metrics) are not
# events and stay as they are.
SCOPE_SQL = {"local": LOCAL_SRC, "public": f"(src_ip IS NOT NULL AND NOT {LOCAL_SRC})"}
# not "IS NOT DISTINCT FROM events.dst_ip" (a column, not the table) nor "events.x"
_EVENTS_REF = re.compile(r"(?<!DISTINCT )\b(FROM|JOIN)\s+events\b(?!\s*\.)(?:\s+(?:AS\s+)?(?!(?:WHERE|GROUP|ORDER|LEFT|RIGHT|INNER|FULL|CROSS|JOIN|"
                         r"LIMIT|ON|UNION|HAVING|WINDOW|FILTER)\b)([A-Za-z_]\w*))?")


def scoped_sql(sql: str, scope: str) -> str:
    """``sql`` reading only the events of ``scope`` ("local" / "public")."""
    cond = SCOPE_SQL[scope]
    return _EVENTS_REF.sub(lambda m: f"{m.group(1)} (SELECT * FROM events WHERE {cond}) {m.group(2) or 'events'}", sql)


def src_scope_sql(scope: str, arg: Any) -> str:
    """The condition for ``src_scope`` (local / public); ``arg`` adds a query argument and returns its $n."""
    if scope not in SRC_SCOPES:
        raise ValueError("Source: use local or public")
    nets_arg = arg(LOCAL_NETS)
    return (f"src_ip <<= ANY({nets_arg}::inet[])" if scope == "local"
            else f"(src_ip IS NOT NULL AND NOT src_ip <<= ANY({nets_arg}::inet[]))")


SIMPLE = {"program": "program", "host": "host", "domain": "domain", "user": "username", "proto": "proto",
          "iface": "interface", "direction": "direction", "country": "src_country"}


def ports(value: str, label: str) -> tuple[list[int], list[tuple[int, int]]]:
    """'22, 80 8000-8100' -> ([22, 80], [(8000, 8100)]); en / em dashes and spaces around the dash are accepted
    ("19294–19344", "8000 - 8100": ranges copied from documentation)."""
    single, ranges = [], []
    value = re.sub(r"\s*[-\u2010-\u2015\u2212]\s*", "-", value.strip())
    for part in re.split(r"[,;\s]+", value):
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
    if scope := (get("src_scope") or "").strip():
        where.append(src_scope_sql(scope, arg))
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
    if (status := get("status")) and status.strip():  # web server answers: classes (4xx), codes (404), other
        exact, prefixes, other = [], [], False
        for part in re.split(r"[,\s]+", status.strip().lower()):
            if re.fullmatch(r"[1-5]xx", part):
                prefixes.append(f"http_{part[0]}%")
            elif re.fullmatch(r"[1-5]\d\d", part):
                exact.append(f"http_{part}")
            elif part == "other":
                other = True
            elif part:
                raise ValueError(f"Status: '{part}' is not a status class (2xx, 4xx …) or code (404)")
        conds = ([f"action = ANY({arg(exact)}::text[])"] if exact else []) + \
                ([f"action LIKE ANY({arg(prefixes)}::text[])"] if prefixes else []) + \
                (["coalesce(left(action, 5), '') <> 'http_'"] if other else [])
        if conds:
            where.append("(" + " OR ".join(conds) + ")")
    if (tag := get("tag")) and tag.strip():  # web server attack / scanner patterns (data.tags)
        tags = "CASE WHEN jsonb_typeof(data->'tags') = 'array' THEN data->'tags' END"
        if tag == "any":
            where.append(f"coalesce(jsonb_array_length({tags}), 0) > 0")
        elif tag == "none":
            where.append(f"coalesce(jsonb_array_length({tags}), 0) = 0")
        else:
            names = [t for t in re.split(r"[,\s]+", tag.strip()) if t]
            if not all(re.fullmatch(r"[a-z_]{1,40}", t) for t in names):
                raise ValueError("Pattern: use names like sqli, rce, scanner_probe (or any / none)")
            where.append(f"coalesce({tags}, '[]'::jsonb) ?| {arg(names)}::text[]")
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
