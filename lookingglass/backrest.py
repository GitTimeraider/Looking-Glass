"""Backrest (web UI and scheduler for restic): plans, repositories and every backup / maintenance run.

Backrest's API is Connect RPC: ``POST <url>/v1.Backrest/<Method>`` with a JSON body (proto3 JSON: lowerCamelCase
field names, 64-bit numbers as strings, enums by name, empty values left out). Login: HTTP basic auth with a Backrest
user, or nothing when Backrest's authentication is disabled. Only calls that read are used:

* ``GetConfig``: plans, repositories, schedules and retention. It also carries the repository passwords, restic
  environment variables (cloud keys) and user password hashes - those are dropped right here and never stored.
* ``GetSummaryDashboard`` (Backrest 1.6+): 30-day counts, snapshots and the next scheduled backup per plan / repo.
* ``GetOperations``: the run history (backup, forget, prune, check, stats, restore), stored in ``backup_runs``.

Field names follow Backrest's proto files (proto/v1/service.proto, operations.proto, restic.proto, config.proto).
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from . import backups, db
from .config import Settings
from .detections import close_alerts, offline_for as _minutes, raise_alert

log = logging.getLogger("lookingglass.backrest")

SOURCE = "backrest"
STATUS = {"STATUS_SUCCESS": "success", "STATUS_WARNING": "warning", "STATUS_ERROR": "error",
          "STATUS_INPROGRESS": "running", "STATUS_PENDING": "pending", "STATUS_SYSTEM_CANCELLED": "cancelled",
          "STATUS_USER_CANCELLED": "cancelled", "STATUS_UNKNOWN": "unknown"}
STATUS_NUM = {0: "unknown", 1: "pending", 2: "running", 3: "success", 4: "error", 5: "cancelled", 6: "cancelled",
              7: "warning"}
# operation type (the "op" oneof) -> kind; index snapshot, hook and command runs are not kept
KINDS = {"operation_backup": "backup", "operation_forget": "forget", "operation_prune": "prune",
         "operation_check": "check", "operation_stats": "stats", "operation_restore": "restore"}
FIRST_FETCH, NEXT_FETCH = 5000, 500  # operations read on the first poll / on every later one


class BackrestError(Exception):
    def __init__(self, status: int, text: str) -> None:
        super().__init__(f"HTTP {status}: {text}")
        self.status = status


# ---------------------------------------------------------------- JSON helpers ---
def _camel(key: str) -> str:
    head, *rest = key.split("_")
    return head + "".join(p[:1].upper() + p[1:] for p in rest)


def g(d: Any, key: str, default: Any = None) -> Any:
    """Field ``key`` (snake_case) of a proto3 JSON object, written lowerCamelCase or as in the proto file."""
    if not isinstance(d, dict):
        return default
    for k in (_camel(key), key):
        if d.get(k) is not None:
            return d[k]
    return default


def num(d: Any, key: str) -> float | None:
    try:
        v = g(d, key)
        return float(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _int(d: Any, key: str) -> int | None:
    v = num(d, key)
    return int(v) if v is not None else None


def ms_time(v: Any) -> datetime | None:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(n / 1000, tz=timezone.utc) if n > 0 else None


def status_of(v: Any) -> str:
    if isinstance(v, int) or (isinstance(v, str) and v.isdigit()):
        return STATUS_NUM.get(int(v), "unknown")
    return STATUS.get(str(v or "STATUS_UNKNOWN"), "unknown")


# ---------------------------------------------------------------- config ---
_USERINFO = re.compile(r"(://[^/@:\s]*):[^/@\s]+@")


def redact_uri(uri: str) -> str:
    """rest:https://user:secret@host/repo -> rest:https://user:***@host/repo"""
    return _USERINFO.sub(r"\1:***@", uri or "")


DOW = {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}
MACROS = {"@yearly": 366 * 86400, "@annually": 366 * 86400, "@monthly": 31 * 86400, "@weekly": 7 * 86400,
          "@daily": 86400, "@midnight": 86400, "@hourly": 3600}


def _expand(field: str, lo: int, hi: int, names: dict[str, int] | None = None) -> set[int]:
    out: set[int] = set()
    for part in field.lower().split(","):
        step = 1
        if "/" in part:
            part, s = part.split("/", 1)
            step = max(1, int(s))
        for name, n in (names or {}).items():
            part = part.replace(name, str(n))
        if part in ("*", "?"):
            a, b = lo, hi
        elif "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
        else:
            a = int(part)
            b = hi if step > 1 else a
        out.update(range(a, b + 1, step))
    if names is DOW and 7 in out:  # 7 = Sunday too
        out.add(0)
    return {v for v in out if lo <= v <= hi}


def cron_max_gap(expr: str) -> float | None:
    """Longest normal gap between two runs of a cron schedule, in seconds (weekdays only: the weekend). None when it
    cannot be worked out (months restricted, odd syntax)."""
    expr = (expr or "").strip()
    if expr.lower() in MACROS:
        return MACROS[expr.lower()]
    f = expr.split()
    if len(f) == 6:  # with a seconds field
        f = f[1:]
    if len(f) != 5:
        return None
    minute, hour, dom, month, dow = f
    try:
        if month not in ("*", "?"):
            return None
        mins, hours = _expand(minute, 0, 59), _expand(hour, 0, 23)
        if dom not in ("*", "?") and dow in ("*", "?"):
            days, span, base = _expand(dom, 1, 31), 31 * 1440, 1
        else:
            days, span, base = _expand(dow, 0, 6, DOW), 7 * 1440, 0
    except ValueError:
        return None
    times = sorted((d - base) * 1440 + h * 60 + m for d in days for h in hours for m in mins)
    if not times:
        return None
    gaps = [b - a for a, b in zip(times, times[1:])] + [times[0] + span - times[-1]]
    return max(gaps) * 60.0


def schedule_info(s: Any) -> tuple[str, float | None, bool]:
    """(readable text, longest normal gap in seconds or None, disabled?) of a Backrest Schedule."""
    if not isinstance(s, dict) or not s:
        return "not scheduled", None, True
    after = " after the last run" if g(s, "clock") in ("CLOCK_LAST_RUN_TIME", 3) else ""
    if g(s, "disabled"):
        return "disabled", None, True
    if cron := g(s, "cron"):
        return f"cron {cron}", cron_max_gap(cron), False
    if h := _int(s, "max_frequency_hours"):
        return f"every {h} hour{'s' if h != 1 else ''}{after}", h * 3600.0, False
    if d := _int(s, "max_frequency_days"):
        return f"every {d} day{'s' if d != 1 else ''}{after}", d * 86400.0, False
    return "not scheduled", None, True


def retention_text(r: Any) -> str:
    if not isinstance(r, dict) or not r:
        return ""
    if g(r, "policy_keep_all"):
        return "keep all"
    if (n := _int(r, "policy_keep_last_n")) is not None:
        return f"keep last {n}"
    tb = g(r, "policy_time_bucketed")
    if isinstance(tb, dict):
        parts = [f"{tb[k]} {k}" for k in ("hourly", "daily", "weekly", "monthly", "yearly") if tb.get(k)]
        if n := _int(tb, "keep_last_n"):
            parts.append(f"last {n}")
        return "keep " + ", ".join(parts) if parts else ""
    return ""


def parse_config(cfg: dict[str, Any]) -> dict[str, Any]:
    """Plans and repositories from GetConfig - without passwords, environment variables, flags, hooks or users."""
    plans = []
    for p in g(cfg, "plans", []) or []:
        text, gap, disabled = schedule_info(g(p, "schedule"))
        plans.append({"id": g(p, "id", ""), "repo": g(p, "repo", ""), "paths": list(g(p, "paths", []) or []),
                      "excludes": len(g(p, "excludes", []) or []) + len(g(p, "iexcludes", []) or []),
                      "schedule": text, "gap_s": gap, "disabled": disabled,
                      "retention": retention_text(g(p, "retention")), "skip_if_unchanged": bool(g(p, "skip_if_unchanged"))})
    repos = []
    for r in g(cfg, "repos", []) or []:
        prune, check = g(r, "prune_policy") or {}, g(r, "check_policy") or {}
        forget = g(r, "forget_policy") or {}
        repos.append({"id": g(r, "id", ""), "uri": redact_uri(g(r, "uri", "")), "guid": g(r, "guid", ""),
                      "prune": schedule_info(g(prune, "schedule"))[0] if prune else "not scheduled",
                      "check": schedule_info(g(check, "schedule"))[0] if check else "not scheduled",
                      "retention": retention_text(g(forget, "retention")) if forget else "",
                      "auto_unlock": bool(g(r, "auto_unlock"))})
    auth = g(cfg, "auth") or {}
    return {"instance": g(cfg, "instance", ""), "plans": plans, "repos": repos,
            "auth": not g(auth, "disabled") and bool(g(auth, "users"))}


def parse_summary(res: dict[str, Any]) -> dict[str, Any]:
    def one(s: dict[str, Any]) -> dict[str, Any]:
        nxt = ms_time(g(s, "next_backup_time_ms"))
        return {"id": g(s, "id", ""), "success_30d": _int(s, "backups_success_last_30days") or 0,
                "warning_30d": _int(s, "backups_warning_last_30days") or 0,
                "failed_30d": _int(s, "backups_failed_30days") or 0,
                "scanned_30d": _int(s, "bytes_scanned_last_30days") or 0,
                "added_30d": _int(s, "bytes_added_last_30days") or 0,
                "snapshots": _int(s, "total_snapshots"), "scanned_avg": _int(s, "bytes_scanned_avg"),
                "added_avg": _int(s, "bytes_added_avg"), "protected_bytes": _int(s, "protected_bytes"),
                "next_backup": nxt.isoformat() if nxt else None}
    return {"repos": [one(s) for s in g(res, "repo_summaries", []) or []],
            "plans": [one(s) for s in g(res, "plan_summaries", []) or []]}


# ---------------------------------------------------------------- operations ---
def run_from_op(op: dict[str, Any]) -> dict[str, Any] | None:
    """One Backrest Operation -> a backup_runs row (None for operation types that are not kept)."""
    kind = body = None
    for key, k in KINDS.items():
        b = g(op, key)
        if b is not None:
            kind, body = k, b
            break
    if kind is None or g(op, "id") is None:
        return None
    started, ended = ms_time(g(op, "unix_time_start_ms")), ms_time(g(op, "unix_time_end_ms"))
    job = g(op, "plan_id", "") or ""
    run: dict[str, Any] = {
        "ext_id": str(g(op, "id")), "kind": kind, "job": "" if job.startswith("_") else job,  # _system_ / _unassociated_
        "repo": g(op, "repo_id", "") or "", "status": status_of(g(op, "status")), "started": started, "ended": ended,
        "duration_s": None, "bytes_processed": None, "bytes_added": None, "files_new": None, "files_changed": None,
        "files_total": None, "snapshot_id": g(op, "snapshot_id") or None,
        "message": (g(op, "display_message") or "")[:2000] or None,
        "data": {k: v for k, v in (("instance", g(op, "instance_id")), ("flow_id", g(op, "flow_id")),
                                   ("repo_guid", g(op, "repo_guid"))) if v}}
    data = run["data"]
    if kind == "backup":
        last = g(body, "last_status") or {}
        if (s := g(last, "summary")) is not None:
            run.update(bytes_processed=_int(s, "total_bytes_processed"), bytes_added=_int(s, "data_added"),
                       files_new=_int(s, "files_new"), files_changed=_int(s, "files_changed"),
                       files_total=_int(s, "total_files_processed"), duration_s=num(s, "total_duration"))
            run["snapshot_id"] = g(s, "snapshot_id") or run["snapshot_id"]
            data["files_unmodified"] = _int(s, "files_unmodified")
        elif (p := g(last, "status")) is not None:
            data["progress"] = {"percent": num(p, "percent_done") or 0.0, "bytes_done": _int(p, "bytes_done") or 0,
                                "total_bytes": _int(p, "total_bytes") or 0, "files_done": _int(p, "files_done") or 0,
                                "total_files": _int(p, "total_files") or 0}
        errs = g(body, "errors") or []
        if errs:
            data["errors"] = [{"item": g(e, "item", ""), "message": g(e, "message", "")[:300]} for e in errs[:20]]
            data["error_count"] = len(errs)
        if g(body, "dry_run"):
            data["dry_run"] = True
    elif kind == "forget":
        data["forgot"] = len(g(body, "forget") or [])
    elif kind == "stats":
        st = g(body, "stats") or {}
        data["stats"] = {"total_size": _int(st, "total_size"), "total_uncompressed_size": _int(st, "total_uncompressed_size"),
                         "compression_ratio": num(st, "compression_ratio"), "snapshot_count": _int(st, "snapshot_count"),
                         "blob_count": _int(st, "total_blob_count")}
    elif kind == "restore":
        last = g(body, "last_status") or {}
        run.update(bytes_processed=_int(last, "bytes_restored"), files_total=_int(last, "files_restored"),
                   duration_s=num(last, "seconds_elapsed"))
        data.update(path=g(body, "path"), target=g(body, "target"), percent=num(last, "percent_done"))
    if run["duration_s"] is None and started and ended:
        run["duration_s"] = max(0.0, (ended - started).total_seconds())
    if data.get("dry_run"):  # a test run: never counts as a backup
        run["kind"] = "dry-run"
    return run


# ---------------------------------------------------------------- client ---
class BackrestClient:
    def __init__(self, settings: Settings) -> None:
        self.base = settings.backrest_url.rstrip("/")
        auth = (settings.backrest_username, settings.backrest_password) if settings.backrest_username else None
        self.http = httpx.AsyncClient(verify=settings.backrest_verify_ssl, timeout=60, auth=auth,
                                      headers={"Content-Type": "application/json", "Connect-Protocol-Version": "1",
                                               "Accept": "application/json"})

    async def close(self) -> None:
        await self.http.aclose()

    async def rpc(self, method: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        r = await self.http.post(f"{self.base}/v1.Backrest/{method}", json=body or {})
        if r.status_code >= 400:
            text = r.text[:300]
            try:  # Connect errors: {"code": "unimplemented", "message": "..."}
                j = r.json()
                text = f"{j.get('code', '')}: {j.get('message', '')}".strip(": ") or text
            except ValueError:
                pass
            if r.status_code == 401:
                text += " (wrong username / password - or Backrest needs a login: set username and password)"
            elif r.status_code == 404 and "<html" in r.text[:200].lower():
                text = "not found - is this the Backrest address and port?"
            raise BackrestError(r.status_code, text)
        try:
            out = r.json()
        except ValueError as exc:
            raise BackrestError(r.status_code, "the answer is not JSON - is this the Backrest address and port?") from exc
        return out if isinstance(out, dict) else {}

    async def config(self) -> dict[str, Any]:
        return parse_config(await self.rpc("GetConfig"))

    async def summary(self) -> dict[str, Any]:
        return parse_summary(await self.rpc("GetSummaryDashboard"))

    async def operations(self, last_n: int) -> list[dict[str, Any]]:
        res = await self.rpc("GetOperations", {"selector": {}, "lastN": str(last_n)})
        return [r for r in (run_from_op(o) for o in g(res, "operations", []) or []) if r]


# ---------------------------------------------------------------- poller ---
class BackrestPoller:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = BackrestClient(settings)
        self.status: dict[str, Any] = {"ok": None, "error": None, "last": None, "instance": None, "sections": {}}
        self.first = True
        self.failures = 0
        self.unreachable_since: float | None = None
        self.unreachable_alerted = False

    async def stop(self) -> None:
        await self.client.close()

    def grace(self) -> float:
        return max(0, self.settings.backrest_offline_grace) * 60

    async def run(self) -> None:
        log.info("Backrest poller started for %s", self.settings.backrest_url)
        while True:
            try:
                await self.poll()
                self.failures = 0
                self.status.update(ok=True, error=None, last=time.time())
                await self.back()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - also bad data / database errors: report, never crash-loop
                if not isinstance(exc, (BackrestError, httpx.HTTPError, OSError)):
                    log.exception("Backrest poll failed")
                self.failures += 1
                self.status.update(ok=False, error=f"{type(exc).__name__}: {exc}", last=time.time())
                log.warning("Backrest: %s", exc)
                if isinstance(exc, (BackrestError, httpx.HTTPError, OSError)):
                    await self.down(str(exc) or type(exc).__name__)
            await db.set_snapshot("backrest:status", self.status)
            await asyncio.sleep(max(60, self.settings.backrest_poll_interval) if self.failures < 3 else 300)

    async def section(self, name: str, coro) -> Any:
        try:
            out = await coro
            self.status["sections"][name] = {"ok": True}
            return out
        except BackrestError as exc:
            self.status["sections"][name] = {"ok": False, "error": str(exc)[:200]}
            return None

    async def poll(self) -> None:
        cfg = await self.client.config()  # must work: it is the connection check as well
        self.status["instance"] = cfg["instance"]
        await db.set_snapshot("backrest:config", cfg)
        summary = await self.section("summary", self.client.summary())  # Backrest 1.6+
        if summary is not None:
            await db.set_snapshot("backrest:summary", summary)
        runs = await self.client.operations(FIRST_FETCH if self.first else NEXT_FETCH)
        self.first = False
        await backups.store_runs(SOURCE, runs, replace_pending=True)
        nxt = {p["id"]: p["next_backup"] for p in (summary or {}).get("plans", [])}
        jobs = [{"job": p["id"], "repo": p["repo"], "schedule": p["schedule"], "gap_s": p["gap_s"],
                 "threshold_s": backups.overdue_threshold(p["gap_s"], self.settings.backrest_overdue_hours),
                 "disabled": p["disabled"], "next_run": nxt.get(p["id"])} for p in cfg["plans"]]
        await db.set_snapshot(f"backup_jobs:{SOURCE}", {"label": "Backrest", "instance": cfg["instance"], "jobs": jobs})
        await backups.check_jobs(SOURCE, "Backrest", jobs, warnings=self.settings.backrest_alert_warnings)
        await backups.check_repos(SOURCE, "Backrest", [r["id"] for r in cfg["repos"]])

    async def down(self, error: str, now: float | None = None) -> None:
        now = now or time.time()
        if self.unreachable_since is None:
            self.unreachable_since = now
        if not self.unreachable_alerted and self.failures >= 2 and now - self.unreachable_since >= self.grace():
            self.unreachable_alerted = True
            await raise_alert("backup_source_unreachable", "medium", "Backrest is unreachable", "backup_down:backrest",
                              description=f"No answer from {self.settings.backrest_url} for "
                                          f"{_minutes(now - self.unreachable_since)}: {error}\n\nBackups may still run - "
                                          "Looking Glass just cannot see them. Check the Backrest container, the URL / "
                                          "port and the login under Settings › Backrest.")

    async def back(self, now: float | None = None) -> None:
        if self.unreachable_since is None:
            return
        down_for = (now or time.time()) - self.unreachable_since
        self.unreachable_since, self.unreachable_alerted = None, False
        await close_alerts("backup_source_unreachable", ["backup_down:backrest"],
                           f"Backrest answers again (it was unreachable for {_minutes(down_for)})")


async def test_connection(settings: Settings) -> dict[str, Any]:
    c = BackrestClient(settings)
    try:
        cfg = await c.config()
        ops = await c.operations(50)
        note = ""
        try:
            await c.summary()
        except BackrestError:
            note = "This Backrest version has no summary dashboard (1.6+): the 30-day counts and next run times are missing."
        return {"ok": True, "instance": cfg["instance"], "plans": len(cfg["plans"]), "repos": len(cfg["repos"]),
                "runs": len(ops), "auth": cfg["auth"], "note": note}
    except BackrestError as exc:
        return {"ok": False, "error": str(exc)}
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc} - check the URL and port"}
    finally:
        await c.close()
