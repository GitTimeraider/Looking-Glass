"""Unraid Docker containers: restart loops and errors in their logs.

* Restarts: the Unraid API (and Docker) give each container a status text such as "Up 5 seconds", "Up 3 minutes
  (healthy)" or "Restarting (1) 10 seconds ago". The time a container started (or last crashed) follows from it; a new
  start time is a restart. A container that only restarted 2-3 times is fine; one that keeps restarting (N times in M
  minutes, Settings › Data & detection) raises an alert that closes by itself once the container stays up.
* Log errors: rules (Unraid › Docker › Log alert rules) say per container which lines count - text or /regex/,
  with exceptions - and how many of them in how many minutes are too many. Containers without their own rule use the
  default rule: lines with error / fatal / panic / exception / traceback / critical (Settings › Data & detection).
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

from . import db

SEVERITIES = ("info", "low", "medium", "high", "critical")

# A log line's level as a syslog severity (0 emergency ... 7 debug). An explicit level the program wrote wins over
# words in the text ("level=info msg=\"0 errors\"" is info); without one, the words decide as before.
LEVELS = {"emerg": 0, "emergency": 0, "panic": 0, "alert": 1, "crit": 2, "critical": 2, "fatal": 2, "fatl": 2,
          "error": 3, "err": 3, "eror": 3, "warn": 4, "warning": 4, "notice": 5, "info": 6, "inf": 6, "information": 6,
          "debug": 7, "dbg": 7, "trace": 7}
_LEVEL_WORDS = "|".join(sorted(LEVELS, key=len, reverse=True))
_EXPLICIT_LEVEL = re.compile(
    # [emerg] (nginx), [ERROR] / [warn] / <error>, level=error / lvl=warn (logfmt), "level":"error" (JSON),
    # ERROR: / WARNING: (php-fpm, Python logging), " ERROR " / " WRN " between spaces or pipes (most loggers)
    rf"(?:[\[<]\s*(?P<a>{_LEVEL_WORDS})\s*[\]>]"
    rf"|\b(?:level|lvl|severity|loglevel)\s*[=:]\s*\"?(?P<b>{_LEVEL_WORDS})\b"
    rf"|\"(?:level|lvl|severity)\"\s*:\s*\"(?P<c>{_LEVEL_WORDS})\""
    rf"|(?:^|[\s|])(?P<d>EMERG|ALERT|CRIT|CRITICAL|FATAL|PANIC|ERROR|ERR|WARN|WARNING|WRN|INFO|INF|NOTICE|DEBUG|DBG|TRACE)(?=[\s:|\]])"
    rf"|^(?P<e>[EWFC])\d{{4}} )",  # glog: E1117 01:22:03.123 ...
    re.IGNORECASE)
_GLOG = {"E": 3, "W": 4, "F": 2, "C": 2}
# the words that make a line without an explicit level an error line (Settings › Data & detection: default rule)
ERROR_WORDS = ("error", "fatal", "panic", "exception", "traceback", "critical", "emerg")


def line_severity(msg: str) -> int:
    """Syslog severity of one container log line: 0-2 emergency / alert / critical, 3 error, 4 warning, 6 other."""
    m = _EXPLICIT_LEVEL.search(msg[:300])
    if m:
        if m.group("e"):
            return _GLOG[m.group("e").upper()]
        word = next(g for g in m.groups() if g).lower()
        # an upper-case word between spaces only counts when it is written in capitals (not "an error occurred")
        if m.group("d") is None or m.group("d").isupper():
            return LEVELS.get(word, 6)
    low = msg.lower()
    return 3 if any(w in low for w in ERROR_WORDS) else 4 if "warn" in low else 6
UNITS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400, "week": 604800, "month": 2592000, "year": 31536000}
_STATUS = re.compile(r"^\s*(up|restarting|exited)\b(?:\s*\(-?\d+\))?\s+(.*?)\s*(?:ago)?\s*(?:\([^)]*\))?\s*$", re.I)
_AGE = re.compile(r"^(\d+|about an?|an?)\s+(second|minute|hour|day|week|month|year)s?\b", re.I)


def docker_age(text: str) -> tuple[float, float] | None:
    """Docker's human duration ("5 seconds", "About a minute", "3 hours") -> (seconds, +- uncertainty).

    Docker truncates seconds, minutes, days, weeks, months and years and rounds hours, so the real age lies in a range."""
    t = (text or "").strip().lower()
    if t.startswith("less than a second"):
        return 0.5, 1.0
    m = _AGE.match(t)
    if not m:
        return None
    n = int(m.group(1)) if m.group(1).isdigit() else 1
    unit = UNITS[m.group(2)]
    if unit == 1:
        return float(n), 2.0
    if unit == 3600:  # int(hours + 0.5)
        return n * 3600.0, 1800.0
    return n * unit + unit / 2, unit / 2


def parse_status(status: str) -> tuple[str, float, float] | None:
    """'Up 5 seconds (healthy)' -> ('up', 5, 2); 'Restarting (1) 10 seconds ago' -> ('restarting', 10, 2)."""
    m = _STATUS.match(status or "")
    if not m:
        return None
    age = docker_age(m.group(2))
    return (m.group(1).lower(), *age) if age else None


def health(status: str) -> str | None:
    """Docker's health check result in the status text: 'healthy', 'unhealthy', 'starting' or None (no health check)."""
    m = re.search(r"\((healthy|unhealthy|health: starting)\)", status or "", re.I)
    return None if not m else "starting" if "starting" in m.group(1).lower() else m.group(1).lower()


class RestartTracker:
    """Start times (from "Up …") and crash times (from "Restarting … ago") per container, merged across polls."""

    def __init__(self) -> None:
        self.events: dict[str, dict[str, list[tuple[float, float]]]] = {}  # name -> kind -> [(time, uncertainty)]

    def observe(self, name: str, status: str, now: float) -> bool:
        """Record what the status says; True when it shows a start or crash not seen before."""
        parsed = parse_status(status)
        if not parsed or parsed[0] == "exited":
            return False
        kind, age, unc = parsed
        t = now - age
        evs = self.events.setdefault(name, {}).setdefault(kind, [])
        for i, (et, eu) in enumerate(evs):
            if abs(et - t) <= unc + eu + 5:  # the same start, read again (less or more precisely)
                if unc < eu:
                    evs[i] = (t, unc)
                return False
        evs.append((t, unc))
        evs.sort()
        del evs[:-500]
        return True

    def count(self, name: str, since: float) -> int:
        """Restarts since then: a crash loop is mostly seen either running or waiting to restart, so the larger of the two."""
        kinds = self.events.get(name) or {}
        return max((sum(1 for t, _ in evs if t >= since) for evs in kinds.values()), default=0)

    def last(self, name: str) -> float | None:
        return max((t for evs in (self.events.get(name) or {}).values() for t, _ in evs), default=None)

    def forget(self, before: float) -> None:
        for kinds in self.events.values():
            for kind, evs in kinds.items():
                kinds[kind] = [e for e in evs if e[0] >= before] or evs[-1:]  # the current start stays known


# ------------------------------------------------------------------ log rules ---
@dataclass
class LogRule:
    id: int | None
    name: str
    containers: list[str] = field(default_factory=list)  # name patterns with * and ?; empty = all containers
    match: list[str] = field(default_factory=list)       # text (contains) or /regex/; empty = error lines
    ignore: list[str] = field(default_factory=list)
    threshold: int = 50                                  # lines in the window; 0 = no log alerts for these containers
    minutes: int = 10
    severity: str = "low"
    enabled: bool = True
    server_id: int | None = None                         # None = every Unraid server
    max_level: int = 3                                   # without match terms: lines of this syslog level or worse
    key: str = ""                                        # the built-in rules: "default" / "critical"

    def covers(self, container: str, server_id: int | None = None) -> bool:
        if self.server_id is not None and server_id is not None and self.server_id != server_id:
            return False
        return not self.containers or any(fnmatch.fnmatchcase(container.lower(), p.lower()) for p in self.containers)


def _lines(value: Any) -> list[str]:
    if isinstance(value, list):
        items = [str(v) for v in value]
    else:
        items = str(value or "").split("\n")
    return [i.strip() for i in items if i.strip()]


def _is_regex(term: str) -> bool:
    return len(term) > 2 and term.startswith("/") and term.endswith("/")


def clean_rule(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate a rule from the UI. Raises ValueError with a message for the user."""
    name = str(payload.get("name") or "").strip()[:100]
    if not name:
        raise ValueError("Give the rule a name.")
    containers = [c for line in _lines(payload.get("containers")) for c in line.split(",") if c.strip()]
    containers = [c.strip() for c in containers]
    match, ignore = _lines(payload.get("match")), _lines(payload.get("ignore"))
    for term in match + ignore:
        if _is_regex(term):
            try:
                re.compile(term[1:-1])
            except re.error as exc:
                raise ValueError(f"{term}: not a valid regular expression ({exc})") from exc
    try:
        threshold = int(payload.get("threshold", 50))
        minutes = int(payload.get("minutes", 10))
    except (TypeError, ValueError) as exc:
        raise ValueError("Lines and minutes must be whole numbers.") from exc
    if not 0 <= threshold <= 100000:
        raise ValueError("Lines: 0 (no log alerts for these containers) to 100000.")
    if not 1 <= minutes <= 1440:
        raise ValueError("Minutes: 1 to 1440.")
    severity = str(payload.get("severity") or "low")
    if severity not in SEVERITIES:
        raise ValueError(f"Severity must be one of {', '.join(SEVERITIES)}.")
    sid = payload.get("server_id")
    sid = int(sid) if sid not in (None, "", 0, "0") else None
    return {"name": name, "containers": containers, "match": match, "ignore": ignore, "threshold": threshold,
            "minutes": minutes, "severity": severity, "enabled": bool(payload.get("enabled", True)), "server_id": sid}


def _like(term: str) -> str:
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _pg_regex(term: str) -> str:
    # PostgreSQL regular expressions: \y is a word boundary (\b means backspace there)
    return re.sub(r"(?<!\\)\\b", r"\\y", term[1:-1])


def rule_sql(rule: LogRule, args: list[Any]) -> str:
    """The WHERE condition for the lines a rule counts (events of source 'docker')."""
    def any_of(terms: list[str]) -> str:
        parts = []
        for t in terms:
            if _is_regex(t):
                args.append(_pg_regex(t))
                parts.append(f"message ~* ${len(args)}")
            else:
                args.append(_like(t))
                parts.append(f"message ILIKE ${len(args)}")
        return "(" + " OR ".join(parts) + ")"
    cond = any_of(rule.match) if rule.match else f"severity <= {int(rule.max_level)}"
    if rule.ignore:
        cond += f" AND NOT {any_of(rule.ignore)}"
    return cond


async def check_regex(rule: dict[str, Any]) -> None:
    """Let PostgreSQL compile the regular expressions too (its dialect differs a little). Raises ValueError."""
    for term in rule["match"] + rule["ignore"]:
        if _is_regex(term):
            try:
                await db.pool().fetchval("SELECT '' ~* $1", _pg_regex(term))
            except Exception as exc:  # noqa: BLE001
                raise ValueError(f"{term}: the database cannot use this regular expression ({exc})") from exc


async def load_rules() -> list[LogRule]:
    rows = await db.pool().fetch("SELECT * FROM container_log_rules WHERE enabled ORDER BY id")
    return [LogRule(id=r["id"], name=r["name"], containers=list(r["containers"] or []), match=list(r["match"] or []),
                    ignore=list(r["ignore"] or []), threshold=r["threshold"], minutes=r["minutes"], severity=r["severity"],
                    enabled=r["enabled"], server_id=r["server_id"]) for r in rows]


def default_rule(settings: Any) -> LogRule:
    return LogRule(id=None, name="Default: error lines", threshold=settings.unraid_log_error_count,
                   minutes=settings.unraid_log_error_minutes, severity="low", key="default")


def critical_rule(settings: Any) -> LogRule:
    """Emergency / alert / critical lines ([emerg] of nginx, FATAL, PANIC ...): a container that cannot work as it
    should - an alert from the first few lines, not only from many."""
    return LogRule(id=None, name="Default: emergency / critical lines",
                   threshold=getattr(settings, "unraid_log_critical_count", 1),
                   minutes=settings.unraid_log_error_minutes, severity=getattr(settings, "unraid_log_critical_severity", "high"),
                   max_level=2, key="critical")


def rules_for(container: str, server_id: int, rules: list[LogRule], default: LogRule,
              critical: LogRule | None = None) -> list[LogRule]:
    """Every own rule that covers the container; the default rule only for containers no own rule covers. The
    critical rule for every container, except one an own rule switched off (limit 0 = no log alerts)."""
    own = [r for r in rules if r.covers(container, server_id)]
    out = own or [default]
    if critical is not None and not any(r.threshold <= 0 for r in own):
        out.append(critical)
    return out


async def count_matches(host: str, containers: list[str], rule: LogRule, minutes: int) -> list[dict[str, Any]]:
    """Per container: matching lines in the last ``minutes``, the newest time and up to three examples."""
    args: list[Any] = [host, containers, minutes]
    cond = rule_sql(rule, args)
    rows = await db.pool().fetch(
        "SELECT program, count(*) n, max(ts) last, (array_agg(left(message, 300) ORDER BY ts DESC))[1:3] examples "
        "FROM events WHERE source = 'docker' AND host = $1 AND program = ANY($2::text[]) "
        f"AND ts > now() - make_interval(mins => $3) AND {cond} GROUP BY program", *args)
    return [dict(r) for r in rows]


async def preview(host: str | None, containers: list[str] | None, rule: LogRule, hours: int) -> list[dict[str, Any]]:
    """How a rule would have done over the last hours: per container the matching lines, the busiest window of the
    rule's length and how many windows reached the threshold."""
    args: list[Any] = [hours, rule.minutes]
    where = ["source = 'docker'", "ts > now() - make_interval(hours => $1)"]
    if host:
        args.append(host)
        where.append(f"host = ${len(args)}")
    if containers is not None:
        args.append(containers)
        where.append(f"program = ANY(${len(args)}::text[])")
    where.append(rule_sql(rule, args))
    rows = await db.pool().fetch(
        "WITH m AS (SELECT host, program, ts, message, date_bin(make_interval(mins => $2), ts, "
        "'2000-01-01'::timestamptz) w FROM events WHERE " + " AND ".join(where) + "), "
        "per AS (SELECT host, program, w, count(*) n FROM m GROUP BY 1, 2, 3) "
        "SELECT p.host, p.program, sum(p.n)::bigint total, max(p.n)::bigint busiest, "
        "count(*) FILTER (WHERE p.n >= " + str(max(1, rule.threshold)) + ") over_limit, "
        "(SELECT array_agg(x) FROM (SELECT left(message, 300) x FROM m WHERE m.host = p.host AND m.program = p.program "
        "ORDER BY ts DESC LIMIT 3) e) examples FROM per p GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 200", *args)
    return [dict(r) for r in rows]
