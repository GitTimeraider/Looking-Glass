"""Route a received syslog line to the matching parser and return a normalised event dict."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from . import filterlog, nginx, security
from .syslog import parse_syslog

__all__ = ["parse_line"]


def parse_line(raw: str, sender: str | None = None, local_tz=timezone.utc, now: datetime | None = None) -> dict[str, Any] | None:
    raw = raw.strip()
    if not raw:
        return None
    sm = parse_syslog(raw, now=now, local_tz=local_tz)
    host = sm.host or sender
    prog = (sm.program or "").lower()
    msg = sm.message

    ev: dict[str, Any] | None = None
    if prog == "filterlog":
        ev = filterlog.parse(sm.ts, host, msg)
    elif prog.startswith("nginx"):
        ev = nginx.parse(sm.ts, host, sm.program, msg)
    elif prog.startswith("unbound"):
        ev = security.parse_unbound(sm.ts, host, sm.program, msg)
    elif prog.startswith("crowdsec") or prog.startswith("cs-firewall-bouncer"):
        ev = security.parse_crowdsec(sm.ts, host, sm.program, msg)
    elif prog.startswith("suricata"):
        ev = security.parse_suricata(sm.ts, host, sm.program, msg)
    elif prog.startswith(("zenarmor", "sensei", "ipdrstreamer", "eastpect")):
        ev = security.parse_zenarmor(sm.ts, host, sm.program, msg)
    elif not prog and msg.lstrip().startswith("{") and ("ip_src_saddr" in msg or "security_tags" in msg or "app_category" in msg):
        ev = security.parse_zenarmor(sm.ts, host, "zenarmor", msg)
    if ev is None:
        ev = security.parse_generic(sm.ts, host, sm.program, sm.severity, msg)
    if ev.get("severity") is None:
        ev["severity"] = sm.severity
    ev.setdefault("host", host)
    return ev
