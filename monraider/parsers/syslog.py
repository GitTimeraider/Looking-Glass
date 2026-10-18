"""Syslog framing/header parsing (RFC 3164 "BSD" and RFC 5424)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d{1,2}) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
    r"(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (?P<msg>.*))?$",
    re.S,
)
_RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?:(?P<ts>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d)|(?P<isots>\d{4}-\d\d-\d\dT\S+)) "
    r"(?:(?P<host>[^\s:\[]+) )?(?P<tag>[^\s:\[]+)(?:\[(?P<pid>[^\]]*)\])?: ?(?P<msg>.*)$",
    re.S,
)
# some senders omit the header entirely ("<13>message")
_PRI_ONLY = re.compile(r"^<(?P<pri>\d{1,3})>(?P<msg>.*)$", re.S)


@dataclass
class SyslogMessage:
    ts: datetime
    facility: int
    severity: int
    host: str | None
    program: str | None
    pid: str | None
    message: str


def _parse_bsd_ts(value: str, now: datetime, local_tz) -> datetime:
    """BSD timestamps carry neither year nor zone: assume current year in the configured zone."""
    now_local = now.astimezone(local_tz).replace(tzinfo=None)
    parsed = datetime.strptime(f"{now_local.year} {value}", "%Y %b %d %H:%M:%S")
    # handle year rollover (message from Dec 31 received Jan 1)
    if (parsed - now_local).days > 300:
        parsed = parsed.replace(year=parsed.year - 1)
    return parsed.replace(tzinfo=local_tz).astimezone(timezone.utc)


def parse_iso(value: str) -> datetime | None:
    try:
        v = value.strip()
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def parse_syslog(raw: str, now: datetime | None = None, local_tz=timezone.utc) -> SyslogMessage:
    now = now or datetime.now(timezone.utc)
    raw = raw.rstrip("\r\n\x00")

    m = _RFC5424.match(raw)
    if m:
        pri = int(m["pri"])
        ts = parse_iso(m["ts"]) if m["ts"] != "-" else None
        msg = m["msg"] or ""
        if msg.startswith("\ufeff"):
            msg = msg[1:]
        return SyslogMessage(
            ts=ts or now, facility=pri >> 3, severity=pri & 7,
            host=None if m["host"] == "-" else m["host"],
            program=None if m["app"] == "-" else m["app"],
            pid=None if m["procid"] == "-" else m["procid"],
            message=msg,
        )

    m = _RFC3164.match(raw)
    if m:
        pri = int(m["pri"])
        if m["ts"]:
            ts = _parse_bsd_ts(m["ts"], now, local_tz)
        else:
            ts = parse_iso(m["isots"]) or now
        return SyslogMessage(ts=ts, facility=pri >> 3, severity=pri & 7, host=m["host"],
                             program=m["tag"], pid=m["pid"], message=m["msg"])

    m = _PRI_ONLY.match(raw)
    if m:
        pri = int(m["pri"])
        return SyslogMessage(ts=now, facility=pri >> 3, severity=pri & 7, host=None, program=None,
                             pid=None, message=m["msg"])
    return SyslogMessage(ts=now, facility=1, severity=6, host=None, program=None, pid=None, message=raw)
