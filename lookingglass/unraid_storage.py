"""Unraid array / pool handling that never wakes spun-down disks.

What touches the disks (Unraid API source, checked against unraid/api main, Oct 2026):

* ``array``, ``shares``: read from emhttp state files (``disks.ini``, ``shares.ini``) - never touches a disk.
  ``ArrayDisk.temp`` is the temperature emhttp itself reads while a disk spins (empty when spun down).
* ``disks``: always runs ``smartctl -a`` on every physical disk via systeminformation ``diskLayout()``,
  without ``-n standby`` -> wakes every spun-down disk, whatever fields are requested.
* ``metrics { temperature }``: same code path up to API 4.37.5 (unraid/api #2017, fixed by #2091 after 4.37.5).

So the ``array`` query is polled normally and the two disk-touching queries only run when every disk that can
spin down is already spinning, according to two consecutive array readings.
"""
from __future__ import annotations

import re
from typing import Any

SMART_CHOICES = (0, 60, 180, 360, 720, 1440, 10080)  # minutes; 0 = never
TEMP_MODES = ("auto", "off")
# first API version whose temperature sensors no longer run smartctl on every disk (unraid/api #2091)
TEMPS_SAFE_AFTER = (4, 37, 5)


def default_prefs() -> dict[str, Any]:
    return {"sensor_temps": "auto", "groups": {}}


def clean_prefs(raw: Any) -> dict[str, Any]:
    """Validate preferences coming from the UI / database."""
    out = default_prefs()
    if not isinstance(raw, dict):
        return out
    if raw.get("sensor_temps") in TEMP_MODES:
        out["sensor_temps"] = raw["sensor_temps"]
    for name, g in (raw.get("groups") or {}).items():
        if not isinstance(g, dict) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", str(name)):
            continue
        try:
            minutes = int(g.get("smart_minutes") or 0)
        except (TypeError, ValueError):
            minutes = 0
        out["groups"][str(name)] = {"exclude": bool(g.get("exclude")),
                                    "smart_minutes": minutes if minutes in SMART_CHOICES else 0}
    return out


def group_prefs(prefs: dict[str, Any], name: str) -> dict[str, Any]:
    return {"exclude": False, "smart_minutes": 0, **((prefs.get("groups") or {}).get(name) or {})}


def api_version(text: Any) -> tuple[int, int, int] | None:
    """'4.37.5' -> (4, 37, 5). Pre-release/build suffixes count as that release (conservative)."""
    m = re.match(r"\s*v?(\d+)\.(\d+)\.(\d+)", str(text or ""))
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def temps_never_wake(version: Any) -> bool:
    v = api_version(version)
    return bool(v and v > TEMPS_SAFE_AFTER)


def pool_name(name: str, all_names: set[str]) -> str:
    """Pool members are named <pool>, <pool>2, <pool>3 ... (same rule as the Unraid web UI)."""
    base = re.sub(r"\d+$", "", name)
    return base if base != name and base in all_names else name


def _num(v: Any) -> float | None:
    try:
        return float(v) if v is not None and v != "" else None
    except (TypeError, ValueError):
        return None


def can_sleep(d: dict[str, Any]) -> bool:
    """A present disk that may spin down (HDD, or unknown type)."""
    return bool(d.get("device")) and d.get("status") != "DISK_NP" and d.get("rotational") is not False


def spin_state(d: dict[str, Any]) -> str:
    if d.get("rotational") is False:
        return "ssd"
    if d.get("isSpinning") is True:
        return "spinning"
    if d.get("isSpinning") is False:
        return "standby"
    return "unknown"


def all_awake(arr: dict[str, Any]) -> bool:
    """True when every array/pool disk that can spin down reports isSpinning=true (unknown counts as asleep)."""
    for key in ("parities", "disks", "caches"):
        for d in arr.get(key) or []:
            if can_sleep(d) and d.get("isSpinning") is not True:
                return False
    return True


def build_groups(arr: dict[str, Any], prefs: dict[str, Any]) -> list[dict[str, Any]]:
    """Array + one entry per pool, with capacity, spin summary and members (excluded groups: summary only)."""
    groups: list[dict[str, Any]] = []
    present = lambda ds: [d for d in ds or [] if d.get("device") or d.get("status") not in (None, "DISK_NP")]  # noqa: E731

    members = [{**d, "role": "parity"} for d in present(arr.get("parities"))] + \
              [{**d, "role": "data"} for d in present(arr.get("disks"))]
    if members:
        kb = (arr.get("capacity") or {}).get("kilobytes") or {}
        groups.append({"name": "array", "kind": "array", "members": members,
                       "size": _num(kb.get("total")), "used": _num(kb.get("used")), "free": _num(kb.get("free")),
                       "fsType": _common(d.get("fsType") for d in members if d["role"] == "data")})

    caches = present(arr.get("caches"))
    names = {str(d.get("name")) for d in caches if d.get("name")}
    pools: dict[str, list[dict[str, Any]]] = {}
    for d in caches:
        pools.setdefault(pool_name(str(d.get("name") or d.get("device") or "pool"), names), []).append({**d, "role": "pool"})
    for name, ms in sorted(pools.items()):
        ms.sort(key=lambda d: d.get("idx") or 0)
        # emhttp reports the file system size of a multi-device pool on its first member only
        first = next((d for d in ms if d.get("name") == name and d.get("fsSize")), None) or \
            next((d for d in ms if d.get("fsSize")), {})
        groups.append({"name": name, "kind": "pool", "members": ms, "size": _num(first.get("fsSize")),
                       "used": _num(first.get("fsUsed")), "free": _num(first.get("fsFree")),
                       "fsType": first.get("fsType") or _common(d.get("fsType") for d in ms)})

    for g in groups:
        p = group_prefs(prefs, g["name"])
        ms = g["members"]
        states = [spin_state(d) for d in ms]
        temps = [t for t in (_num(d.get("temp")) for d in ms) if t is not None]
        g.update(excluded=p["exclude"], smart_minutes=p["smart_minutes"], disks=len(ms),
                 spinning=states.count("spinning"), standby=states.count("standby"), ssd=states.count("ssd"),
                 unknown=states.count("unknown"), max_temp=max(temps) if temps else None,
                 errors=sum(int(_num(d.get("numErrors")) or 0) for d in ms),
                 problems=[f"{d.get('name')}: {d.get('status')}" for d in ms
                           if d.get("status") and d.get("status") not in ("DISK_OK", "DISK_NP")],
                 used_pct=round(g["used"] / g["size"] * 100, 2) if g.get("size") and g.get("used") is not None else None)
        for d, st in zip(ms, states):
            d["spin"] = st
            d["used_pct"] = round(_num(d.get("fsUsed")) / _num(d["fsSize"]) * 100, 2) \
                if _num(d.get("fsSize")) and _num(d.get("fsUsed")) is not None else None
            for k in ("numReads", "numWrites", "color"):  # not provided by the API (always 0 / null)
                d.pop(k, None)
        if g["excluded"]:
            g["members"] = []
    return groups


def _common(values) -> str | None:
    vals = {v for v in values if v}
    return vals.pop() if len(vals) == 1 else ("mixed" if vals else None)


ZED_BAD = re.compile(r"class=(checksum|io|data|deadman|probe_failure|statechange|vdev\.\w+|pool_failure|zpool\.\w+)")
ZED_STATE = re.compile(r"vdev_state=(\w+)|state=(\w+)")


def zfs_problem(program: str | None, message: str) -> str | None:
    """Recognise ZFS event daemon (zed) / kernel ZFS errors in the Unraid syslog."""
    msg = message or ""
    if (program or "").lower() == "zed":
        m = ZED_BAD.search(msg)
        if not m:
            return None
        if m[1] == "statechange":
            st = ZED_STATE.search(msg)
            state = (st[1] or st[2]).upper() if st else ""
            return None if state in ("", "ONLINE") else f"ZFS device state {state}"
        return f"ZFS {m[1]} event"
    if re.search(r"\bZFS\b|\bzpool\b|\bzio\b", msg) and re.search(r"error|fault|degraded|suspended|uncorrectable", msg, re.I):
        return "ZFS error"
    return None
