"""fail2ban log lines (fail2ban.log, e.g. SWAG's /config/log/fail2ban/fail2ban.log).

    2024-05-01 12:00:00,123 fail2ban.filter  [512]: INFO    [nginx-http-auth] Found 1.2.3.4 - 2024-05-01 12:00:00
    2024-05-01 12:00:01,456 fail2ban.actions [512]: NOTICE  [nginx-http-auth] Ban 1.2.3.4
    2024-05-01 12:10:01,456 fail2ban.actions [512]: NOTICE  [nginx-http-auth] Unban 1.2.3.4
    2024-05-01 12:00:01,456 fail2ban.actions [512]: NOTICE  [sshd] Restore Ban 1.2.3.4
    2024-05-01 12:00:01,456 fail2ban.actions [512]: WARNING [sshd] 1.2.3.4 already banned
    2024-05-01 12:00:01,456 fail2ban.filter  [512]: INFO    [sshd] Ignore 192.168.1.5 by ip
    2024-05-01 12:00:00,001 fail2ban.jail    [512]: INFO    Jail 'nginx-http-auth' started

The time has no zone: it is the container's local time (its TZ variable) - the caller passes that zone.
Actions: found (a log line matched a jail's filter), ban, unban, restore_ban (ban re-applied after a restart),
already_banned, ignore (an ignoreip address matched), jail_start / jail_stop; anything else keeps the level only.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .common import event, find_ips

_LINE = re.compile(r"^(?P<time>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:,(?P<ms>\d+))?\s+(?P<logger>fail2ban\.[\w.]+)\s*"
                   r"(?:\[\d+\])?:\s*(?P<level>[A-Z]+)\s+(?P<msg>.*)$")
_JAIL = re.compile(r"^\[(?P<jail>[^\]]+)\]\s+(?P<rest>.*)$")
_ACTION = re.compile(r"^(?P<what>Found|Ban|Unban|Restore Ban|Ignore|Increase Ban)\s+(?P<ip>[0-9a-fA-F:.]+)(?P<tail>.*)$")
_ALREADY = re.compile(r"^(?P<ip>[0-9a-fA-F:.]+) already banned")
_JAIL_STATE = re.compile(r"^Jail '(?P<jail>[^']+)' (?P<state>started|stopped)")
_SEVERITY = {"CRITICAL": 2, "ERROR": 3, "WARNING": 4, "NOTICE": 5, "INFO": 6, "DEBUG": 7}
ACTIONS = {"Found": "found", "Ban": "ban", "Unban": "unban", "Restore Ban": "restore_ban", "Ignore": "ignore",
           "Increase Ban": "ban"}


def is_honeypot_jail(jail: str | None, honeypot_jails: set[str] | frozenset[str] = frozenset()) -> bool:
    j = (jail or "").lower()
    return bool(j) and (j in honeypot_jails or "honeypot" in j or "honey-pot" in j)


def parse(line: str, tz: Any = timezone.utc, host: str | None = None,
          honeypot_jails: set[str] | frozenset[str] = frozenset()) -> dict[str, Any] | None:
    """One fail2ban.log line -> event (source fail2ban), None for continuation / empty lines."""
    m = _LINE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m["time"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz)
        if m["ms"]:
            ts = ts.replace(microsecond=int(m["ms"][:6].ljust(6, "0")))
    except ValueError:
        return None
    level, msg = m["level"], m["msg"].strip()
    sev = _SEVERITY.get(level, 6)
    data: dict[str, Any] = {"level": level.lower(), "logger": m["logger"]}
    action = src_ip = None
    jm = _JAIL.match(msg)
    if jm:
        data["jail"] = jm["jail"]
        rest = jm["rest"].strip()
        am = _ACTION.match(rest)
        if am:
            action, src_ip = ACTIONS[am["what"]], am["ip"]
            tail = am["tail"].strip(" -")
            if action == "ban" and am["what"] == "Increase Ban":
                data["increase"] = True
            if tail and action == "found":
                data["matched_at"] = tail
            elif tail and action == "ignore":
                data["reason"] = tail
            elif tail and action in ("ban", "restore_ban"):
                data["detail"] = tail  # "(2 # 1:00:00 -> 2024-...)" with bantime increment
        elif am := _ALREADY.match(rest):
            action, src_ip = "already_banned", am["ip"]
        else:
            ips = find_ips(rest)
            src_ip = ips[0] if ips else None
    elif sm := _JAIL_STATE.match(msg):
        data["jail"] = sm["jail"]
        action = "jail_start" if sm["state"] == "started" else "jail_stop"
    if is_honeypot_jail(data.get("jail"), honeypot_jails):
        data["honeypot"] = True
    if action in ("ban", "restore_ban"):
        sev = min(sev, 5)
    return event(ts, "fail2ban", host=host, program="fail2ban", severity=sev, action=action, src_ip=src_ip,
                 message=msg[:4000], data=data)
