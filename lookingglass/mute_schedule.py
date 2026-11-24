"""Recurring mute windows: at set days / times every week or month, store the alerts of some categories silently.

Settings › Alert filters (and the Snooze page) › "Recurring mute windows". One entry per line, in local time
(Settings › Display › Time zone)::

    category [days] [from-to] [every N weeks from YYYY-MM-DD]

* category: a rule (``unraid_container_errors``), a whole group (``unraid``, ``backups`` - see ``GROUPS``) or ``*``
  for every alert;
* days, several joined with ``+``: weekdays ``tue``, ``mon-fri``, ``fri-mon``; days of the month ``1st``, ``15th``,
  ``last``; a weekday of the month ``1st-tue``, ``3rd-sat``, ``last-fri``; left out = every day;
* from-to: ``01:30-04:00``, ``01-04`` (whole hours) or ``22:00-06:00`` (past midnight: it belongs to the day it
  starts on); left out = the whole day. The end time itself is not included;
* ``every N weeks from YYYY-MM-DD``: only in the week of that date and every N weeks after it (weeks start on
  Monday); without days it is the weekday of that date.

At least days or a time is required - something that should be quiet always is an alert filter. Inside a window a
matching NEW alert is handled exactly like one during a snooze (``snooze.check``): stored closed and silent, never
mailed, but it still counts for attack chains, corroboration and the risk score. Already-open alerts are not mailed
while a window covers them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta, timezone
from functools import lru_cache
from typing import Any
from zoneinfo import ZoneInfo

from . import alert_filters as af

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_DAY = {**{d: i for i, d in enumerate(DAYS)},
        **{d: i for i, d in enumerate(("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"))}}

# short names for the rule groups of the Alert filters page (never the same as a rule name - see the tests)
GROUPS: dict[str, str] = {
    "firewall": "OPNsense firewall", "logins": "Logins & VPN", "web": "Web server (nginx)",
    "swag": "SWAG & CrowdSec (Docker)", "suricata": "Suricata / CrowdSec / Q-Feeds", "dns": "DNS",
    "correlation": "Correlation", "behaviour": "Behaviour & ML", "intel": "Threat intel & traps",
    "devices": "Devices", "opnsense": "OPNsense system", "unifi": "UniFi", "backups": "Backups", "unraid": "Unraid",
}
GROUP_RULES: dict[str, frozenset[str]] = {k: frozenset(r for r, _ in af.RULES[g]) for k, g in GROUPS.items()}

FORMAT = ("write it as: category [days] [from-to] [every N weeks from YYYY-MM-DD], e.g. "
          "unraid_container_errors tue 01:00-04:00 (category: a rule, a group such as unraid or backups, or *; "
          "days: mon … sun, mon-fri, sat+sun, 1st, 15th, last, 1st-tue, last-fri; from-to: 01:30-04:00, 01-04 or "
          "22:00-06:00, local time)")

_ORD = re.compile(r"(\d{1,2})(?:st|nd|rd|th)|last")
_SPAN = re.compile(r"\d{1,2}(?::\d+)?-\d{1,2}(?::\d+)?")
_EVERY = re.compile(r"\bevery\s+(\d+)\s+weeks?\s+from\s+(\d{4}-\d{2}-\d{2})\b", re.I)


@dataclass(frozen=True)
class Days:
    """Which days a window is on: any weekday / day of the month / weekday of the month listed, and - with
    ``every`` - only in every N-th week counted from the week of ``anchor``."""
    weekdays: frozenset[int] = frozenset()
    monthdays: frozenset[int] = frozenset()  # 1 … 31, -1 = the last day of the month
    nth: frozenset[tuple[int, int]] = frozenset()  # (1 … 5 or -1 = last, weekday)
    every: int = 1
    anchor: date | None = None

    def __contains__(self, d: date) -> bool:
        if self.anchor is not None:
            weeks = ((d - timedelta(days=d.weekday())) - (self.anchor - timedelta(days=self.anchor.weekday()))).days // 7
            if weeks < 0 or weeks % self.every:
                return False
        if not (self.weekdays or self.monthdays or self.nth):
            return True
        last = (d.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
        return (d.weekday() in self.weekdays or d.day in self.monthdays or (d == last and -1 in self.monthdays)
                or (((d.day - 1) // 7 + 1, d.weekday()) in self.nth)
                or (d.day + 7 > last.day and (-1, d.weekday()) in self.nth))


Rule = tuple[str, frozenset[str] | None, Days | None, tuple[int, int] | None, str]


def _ordinal(w: str) -> int:
    m = _ORD.fullmatch(w)
    if not m:
        raise ValueError
    n = -1 if w == "last" else int(m.group(1))
    if n == 0 or n > 31:
        raise ValueError
    return n


def _dayspec(spec: str) -> Days:
    """"tue", "mon-fri", "sat+sun", "1st+15th", "last", "1st-tue", "last-fri" -> Days."""
    weekdays: set[int] = set()
    monthdays: set[int] = set()
    nth: set[tuple[int, int]] = set()
    for part in spec.split("+"):
        a, _, b = part.partition("-")
        if a in _DAY:
            weekdays |= _days(part)
        elif b:  # 1st-tue, last-fri
            n = _ordinal(a)
            if b not in _DAY or n > 5:
                raise ValueError
            nth.add((n, _DAY[b]))
        else:
            monthdays.add(_ordinal(a))
    return Days(frozenset(weekdays), frozenset(monthdays), frozenset(nth))


def _days(spec: str) -> frozenset[int]:
    """"tue", "mon-fri", "sat+sun", "fri-mon" -> weekday numbers (Monday = 0)."""
    out: set[int] = set()
    for part in spec.split("+"):
        a, _, b = part.partition("-")
        if a not in _DAY or (b and b not in _DAY):
            raise ValueError
        i, j = _DAY[a], _DAY[b or a]
        out.update(d % 7 for d in range(i, j + 1 if j >= i else j + 8))
    return frozenset(out)


def _minute(t: str) -> int:
    h, _, m = t.partition(":")
    if not h.isdigit() or (m and not (m.isdigit() and len(m) == 2)):
        raise ValueError
    h, m = int(h), int(m or 0)
    if not (0 <= h <= 24 and 0 <= m <= 59) or (h == 24 and m):
        raise ValueError
    return h * 60 + m


def _span(spec: str) -> tuple[int, int]:
    """"01:30-04:00" / "01-04" / "22:00-06:00" -> (start, end) in minutes after midnight."""
    a, sep, b = spec.partition("-")
    if not sep:
        raise ValueError
    start, end = _minute(a), _minute(b)
    if start >= 24 * 60 or start == end:
        raise ValueError
    return start, end


def parse(text: str | None) -> list[Rule]:
    """The windows of the setting; raises ValueError naming the first entry it cannot read."""
    out: list[Rule] = []
    for line in re.split(r"[,;\n]+", text or ""):
        words = line.split()
        if not words:
            continue
        cat = words[0].lower()
        if cat == "*":
            rules = None
        elif cat in GROUP_RULES:
            rules = GROUP_RULES[cat]
        elif cat in af.RULE_NAMES:
            rules = frozenset((cat,))
        else:
            raise ValueError(f"'{line.strip()}': unknown category '{words[0]}' - see Format & categories for the list")
        days = span = None
        rest = " ".join(words[1:])
        every = _EVERY.search(rest)
        if every:
            rest = rest[:every.start()] + rest[every.end():]
        try:
            for w in rest.lower().split():
                if _SPAN.fullmatch(w) and span is None:
                    span = _span(w)
                elif not _SPAN.fullmatch(w) and days is None:
                    days = _dayspec(w)
                else:
                    raise ValueError
        except ValueError:
            raise ValueError(f"'{line.strip()}' - {FORMAT}") from None
        if every:
            n = int(every.group(1))
            try:
                anchor = date.fromisoformat(every.group(2))
            except ValueError:
                raise ValueError(f"'{line.strip()}': {every.group(2)} is not a date (YYYY-MM-DD)") from None
            if not 1 <= n <= 52:
                raise ValueError(f"'{line.strip()}': every 1 … 52 weeks")
            days = replace(days or Days(weekdays=frozenset((anchor.weekday(),))), every=n, anchor=anchor)
        if days is None and span is None:
            raise ValueError(f"'{line.strip()}': add days and / or a time - to mute something always, use an "
                             "alert filter (Mute similar… on the Alerts page)")
        out.append((cat, rules, days, span, line.strip()))
    return out


@lru_cache(maxsize=8)
def _parsed(text: str) -> tuple[Rule, ...]:
    """Cached; a line that cannot be read (saved before entries were checked) is skipped, the rest still work."""
    out: list[Rule] = []
    for line in re.split(r"[,;\n]+", text):
        try:
            out += parse(line)
        except ValueError:
            pass
    return tuple(out)


def _window_end(local: datetime, days, span) -> datetime | None:
    """The end of the window around ``local`` (naive local time), or None when ``local`` is outside it."""
    day, minute = local.date(), local.hour * 60 + local.minute
    midnight = local.replace(hour=0, minute=0, second=0, microsecond=0)
    if span is None:
        start_day, end = midnight, midnight + timedelta(days=1)
    else:
        start, stop = span
        if start < stop:
            if not start <= minute < stop:
                return None
            start_day, end = midnight, midnight + timedelta(minutes=stop)
        elif minute >= start:
            start_day, end = midnight, midnight + timedelta(days=1, minutes=stop)
        elif minute < stop:  # past midnight: the window belongs to the day it started on
            day -= timedelta(days=1)
            start_day, end = midnight - timedelta(days=1), midnight + timedelta(minutes=stop)
        else:
            return None
    if days is not None and day not in days:
        return None
    if span is None and days is not None:  # whole days: run on through the next ticked days ("sat+sun")
        while end.date() in days and end - start_day < timedelta(days=7):
            end += timedelta(days=1)
    return end


def _tz(name: str | None):
    try:
        return ZoneInfo(name or "UTC")
    except Exception:  # noqa: BLE001 - unknown zone name
        return timezone.utc


def covering(text: str | None, tz_name: str | None, rule: str, now: datetime | None = None) -> dict[str, Any] | None:
    """The window of the setting that covers an alert of ``rule`` right now (snooze-shaped), else None."""
    if not text:
        return None
    tz = _tz(tz_name)
    now = (now or datetime.now(timezone.utc)).astimezone(tz)
    local = now.replace(tzinfo=None)
    for cat, rules, days, span, line in _parsed(text):
        if rules is not None and rule not in rules:
            continue
        end = _window_end(local, days, span)
        if end is not None:
            return {"id": None, "name": f"recurring mute window: {line}", "recurring": line,
                    "until": end.replace(tzinfo=tz).astimezone(timezone.utc).isoformat()}
    return None


def reference() -> dict[str, Any]:
    """For the 'Format & categories' popup."""
    return {
        "format": "category [days] [from-to] [every N weeks from YYYY-MM-DD]",
        "days": list(DAYS),
        "groups": [{"key": k, "name": g, "rules": [{"rule": r, "label": label} for r, label in af.RULES[g]]}
                   for k, g in GROUPS.items()],
        "examples": [
            ["unraid_container_errors tue 01:00-04:00", "errors in Unraid container logs, Tuesdays 01:00 to 04:00"],
            ["unraid mon+thu 03-05", "every Unraid alert, Mondays and Thursdays 03:00 to 05:00"],
            ["backups sun", "every backup alert, all day Sunday"],
            ["unraid_container_down mon-fri 23:30-01:00", "stopped containers, weeknights 23:30 to 01:00 (past midnight)"],
            ["* 04:00-04:15", "every alert, every day 04:00 to 04:15"],
            ["backups 1st 02:00-06:00", "every backup alert, on the 1st of every month 02:00 to 06:00"],
            ["unraid 1st+15th", "every Unraid alert, all day on the 1st and the 15th of every month"],
            ["unraid_parity 1st-mon", "parity check alerts, all day on the first Monday of every month"],
            ["unraid last-sun 22:00-06:00", "every Unraid alert, from 22:00 on the last Sunday of the month to 06:00"],
            ["unraid_container_errors tue 01-04 every 2 weeks from 2026-11-10",
             "container log errors, every other Tuesday (the week of 10 Nov 2026, then every 2 weeks) 01:00 to 04:00"],
            ["backups every 2 weeks from 2026-11-15", "every backup alert, all day every other Sunday (the weekday of that date)"],
        ],
    }
