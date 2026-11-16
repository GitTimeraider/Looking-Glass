"""Bichon (self-hosted email archiver): mail accounts, their sync runs, archive size and Bichon's own data backup.

Two read-only sources, both under Bichon's ``/api/v1`` with an API token (``Authorization: Bearer <token>``):

* ``GET /api/v1/metrics`` (Bichon 2.3+): Prometheus text. Always read - it works with a token made with "Metrics only"
  (Bichon › API tokens), which can call nothing else and so cannot read any mail. Per account: type, enabled, sync
  interval, whether a sync runs now, start of the latest sync, end of the latest successful one, result / duration /
  error count of the latest finished one, archived mails. Globally: mails, attachments, storage and search-index size,
  Bichon's own backup (last success, runs since its start).
* ``GET /api/v1/accounts/<id>/download-stats``: the account's recent sync sessions (Bichon keeps about 10; status
  Success / Partial / Failed / Cancelled, folders, errors). Needs the ``account:read_details`` permission, which a
  metrics-only token does not have. Tried on every poll; when refused, the runs are built from the metrics instead (one run per sync start seen, so a
  sync that starts and ends between two polls is only seen when it is the latest).

Runs go to ``backup_runs`` (source ``bichon``): a mail sync is kind ``backup`` with the account as job (so the Main
tab, the failed / overdue alerts and the reports treat it like any backup), Bichon's own backup is job ``Bichon data
backup``, and once an hour a ``stats`` row keeps the archive size and mail counts.
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

log = logging.getLogger("lookingglass.bichon")

SOURCE = "bichon"
LABEL = "Bichon"
DATA_BACKUP_JOB = "Bichon data backup"
SYNC_STATUS = {"success": "success", "partial": "warning", "failed": "error", "cancelled": "cancelled",
               "running": "running"}
SYNC_TYPES = ("imap",)  # account types that download mail (nosync = filled by import / SMTP, view = a saved search)


class BichonError(Exception):
    def __init__(self, status: int, text: str) -> None:
        super().__init__(f"HTTP {status}: {text}")
        self.status = status


# ---------------------------------------------------------------- Prometheus text ---
_LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+(\S+)(?:\s+\S+)?$')
_LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')
_UNESCAPE = {"\\\\": "\\", '\\"': '"', "\\n": "\n"}


def parse_prometheus(text: str) -> dict[str, list[tuple[dict[str, str], float]]]:
    """Prometheus / OpenMetrics text -> {metric name: [(labels, value)]}. Comments and odd lines are skipped."""
    out: dict[str, list[tuple[dict[str, str], float]]] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE.match(line)
        if not m:
            continue
        try:
            value = float(m.group(3))
        except ValueError:
            continue
        labels = {k: re.sub(r'\\[\\"n]', lambda x: _UNESCAPE[x.group(0)], v) for k, v in _LABEL.findall(m.group(2) or "")}
        out.setdefault(m.group(1), []).append((labels, value))
    return out


def _one(metrics: dict, name: str) -> float | None:
    rows = metrics.get(name) or []
    return rows[0][1] if rows else None


def _by_account(metrics: dict, name: str) -> dict[str, float]:
    return {lab.get("account_id", ""): v for lab, v in metrics.get(name) or [] if lab.get("account_id")}


def _ts(seconds: float | None) -> datetime | None:
    return datetime.fromtimestamp(seconds, tz=timezone.utc) if seconds and seconds > 0 else None


def _ms(v: Any) -> datetime | None:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(n / 1000, tz=timezone.utc) if n > 0 else None


def _int(v: float | None) -> int | None:
    return int(v) if v is not None else None


def parse_metrics(text: str) -> dict[str, Any]:
    """The metrics page -> {version, uptime_s, totals, accounts, data_backup, counters}."""
    m = parse_prometheus(text)
    if not any(k.startswith("bichon_") for k in m):
        raise BichonError(200, "no Bichon metrics in the answer - is this the Bichon address (and Bichon 2.3 or newer)?")
    version = next((lab.get("version") for lab, _ in m.get("bichon_build_info") or []), None)
    running, start = _by_account(m, "bichon_account_sync_running"), _by_account(m, "bichon_account_last_sync_start_timestamp_seconds")
    success = _by_account(m, "bichon_account_last_sync_success_timestamp_seconds")
    succeeded = _by_account(m, "bichon_account_last_sync_succeeded")
    duration, errors = _by_account(m, "bichon_account_last_sync_duration_seconds"), _by_account(m, "bichon_account_last_sync_errors")
    emails, interval = _by_account(m, "bichon_account_emails_total"), _by_account(m, "bichon_account_download_interval_minutes")
    gf_running, gf_down = _by_account(m, "bichon_account_gapfill_running"), _by_account(m, "bichon_account_last_gapfill_downloaded")
    gf_failed = _by_account(m, "bichon_account_last_gapfill_failed")
    sessions: dict[str, dict[str, float]] = {}
    for lab, v in m.get("bichon_sync_sessions_total") or []:
        a = sessions.setdefault(lab.get("account_id", ""), {})
        a[lab.get("status", "")] = a.get(lab.get("status", ""), 0) + v
    sync_errors: dict[str, dict[str, int]] = {}
    for lab, v in m.get("bichon_sync_errors_total") or []:
        if v:
            sync_errors.setdefault(lab.get("account_id", ""), {})[lab.get("kind", "?")] = int(v)
    accounts = []
    for lab, _ in m.get("bichon_account_info") or []:
        i = lab.get("account_id", "")
        accounts.append({
            "id": i, "email": lab.get("email", ""), "name": lab.get("name", ""), "type": lab.get("type", ""),
            "enabled": lab.get("enabled", "true") == "true", "interval_min": _int(interval.get(i)) or 0,
            "running": bool(running.get(i)), "last_start": start.get(i) or None, "last_success": success.get(i) or None,
            "last_succeeded": None if i not in succeeded else bool(succeeded[i]),
            "last_duration": duration.get(i), "last_errors": _int(errors.get(i)), "emails": _int(emails.get(i)),
            "gapfill_running": bool(gf_running.get(i)), "gapfill_downloaded": _int(gf_down.get(i)),
            "gapfill_failed": _int(gf_failed.get(i)), "sync_errors": sync_errors.get(i, {})})
    accounts.sort(key=lambda a: (a["email"].lower(), a["id"]))
    names = [a["email"] or a["name"] or f"account {a['id']}" for a in accounts]
    for a, n in zip(accounts, names):  # the job name: the address, made unique when two accounts share it
        a["job"] = n if names.count(n) == 1 else f"{n} (#{a['id']})"
    runs = {lab.get("outcome", ""): v for lab, v in m.get("bichon_backup_runs_total") or []}
    return {
        "version": version, "uptime_s": _one(m, "bichon_uptime_seconds"),
        "totals": {"emails": _int(_one(m, "bichon_emails_total")), "attachments": _int(_one(m, "bichon_attachments_total")),
                   "storage_bytes": _int(_one(m, "bichon_storage_usage_bytes")),
                   "index_bytes": _int(_one(m, "bichon_index_usage_bytes")),
                   "folders": _int(_one(m, "bichon_account_mailbox_folders_total")),
                   "users": _int(_one(m, "bichon_users_total")),
                   "accounts": {lab.get("type", "?"): int(v) for lab, v in m.get("bichon_accounts_total") or []}},
        "accounts": accounts,
        "data_backup": {"last_success": _one(m, "bichon_backup_last_success_timestamp_seconds") or None,
                        "success": runs.get("success", 0.0), "failed": runs.get("failed", 0.0),
                        "duration_sum": _one(m, "bichon_backup_duration_seconds_sum") or 0.0,
                        "duration_count": _one(m, "bichon_backup_duration_seconds_count") or 0.0,
                        "seen": bool(runs) or bool(_one(m, "bichon_backup_last_success_timestamp_seconds"))},
        "sessions": sessions,
    }


# ---------------------------------------------------------------- runs ---
def _field(d: Any, key: str, default: Any = None) -> Any:
    """snake_case field, also when written camelCase."""
    if not isinstance(d, dict):
        return default
    head, *rest = key.split("_")
    for k in (key, head + "".join(p[:1].upper() + p[1:] for p in rest)):
        if d.get(k) is not None:
            return d[k]
    return default


def run_from_session(account: dict[str, Any], s: dict[str, Any]) -> dict[str, Any] | None:
    """One DownloadSession of /download-stats -> a backup_runs row."""
    started = _ms(_field(s, "start_time"))
    if not started:
        return None
    ended = _ms(_field(s, "end_time"))
    status = SYNC_STATUS.get(str(_field(s, "status", "")).lower(), "unknown")
    folders = _field(s, "folder_details") or {}
    folders = list(folders.values()) if isinstance(folders, dict) else list(folders or [])
    new = planned = 0
    bad = []
    for f in folders:
        cur, filt = int(_field(f, "current", 0) or 0), int(_field(f, "filtered", 0) or 0)
        new += max(0, cur - filt)
        planned += int(_field(f, "planned", 0) or 0)
        if str(_field(f, "status", "")).lower() == "failed":
            bad.append({"item": _field(f, "folder_name", "?"), "message": (_field(f, "message") or "failed")[:300]})
    errs = [{"item": "", "message": str(_field(e, "error", ""))[:300]} for e in (_field(s, "errors") or [])
            if isinstance(e, dict)]
    data: dict[str, Any] = {"account_id": account["id"], "trigger": str(_field(s, "trigger", "") or "").lower() or None,
                            "folders": len(folders), "history": "bichon"}
    if bad or errs:
        data["errors"] = (bad + errs)[:20]
        data["error_count"] = len(bad) + len(errs)
        data["failed_folders"] = len(bad)
    if status == "running" and planned:
        data["progress"] = {"percent": min(1.0, sum(int(_field(f, "current", 0) or 0) for f in folders) / planned),
                            "files_done": sum(int(_field(f, "current", 0) or 0) for f in folders), "total_files": planned,
                            "bytes_done": 0, "total_bytes": 0}
        if cur_folder := _field(s, "current_folder"):
            data["current_folder"] = cur_folder
    message = _field(s, "message") or (bad[0]["item"] + ": " + bad[0]["message"] if bad else None) or \
        (errs[0]["message"] if errs else None)
    return {"ext_id": f"{account['id']}:{int(started.timestamp() * 1000)}", "kind": "backup", "job": account["job"],
            "repo": "", "status": status, "started": started, "ended": ended,
            "duration_s": max(0.0, (ended - started).total_seconds()) if ended else None,
            "bytes_processed": None, "bytes_added": None, "files_new": new if folders else None,
            "files_changed": None, "files_total": planned if folders else None, "snapshot_id": None,
            "message": (str(message)[:2000] or None) if message else None, "data": data}


def run_from_metrics(account: dict[str, Any], before: dict[str, float] | None) -> dict[str, Any] | None:
    """The latest sync of an account from the metrics alone. ``before``: its session counters of the previous poll -
    which one went up tells a partial or cancelled sync from a failed one (the metrics only say 'not success')."""
    started = _ts(account["last_start"])
    if not started:
        return None
    data: dict[str, Any] = {"account_id": account["id"], "history": "metrics"}
    run = {"ext_id": f"{account['id']}:{int(round(account['last_start'] * 1000))}", "kind": "backup",
           "job": account["job"], "repo": "", "status": "running", "started": started, "ended": None,
           "duration_s": None, "bytes_processed": None, "bytes_added": None, "files_new": None, "files_changed": None,
           "files_total": None, "snapshot_id": None, "message": None, "data": data}
    if account["running"]:
        return run
    if account["last_succeeded"] is None:  # started but no finished session known (yet)
        return None
    dur = account["last_duration"]
    run["duration_s"] = dur
    run["ended"] = _ts(account["last_start"] + dur) if dur is not None else None
    if account["last_errors"]:
        data["error_count"] = account["last_errors"]
    if account["last_succeeded"]:
        run["status"] = "success"
        return run
    now = account.get("_sessions") or {}
    grew = {k for k, v in now.items() if v > (before or {}).get(k, 0)} if before is not None else set()
    if "partial" in grew and "failed" not in grew:
        run["status"], what = "warning", "some folders could not be archived"
    elif "cancelled" in grew and "failed" not in grew and "partial" not in grew:
        run["status"], what = "cancelled", "the sync was cancelled"
    else:
        run["status"], what = "error", "the sync did not succeed"
    run["message"] = f"{what}" + (f" ({account['last_errors']} errors)" if account["last_errors"] else "") + \
        " - details in Bichon › the account's sync history"
    return run


def data_backup_runs(b: dict[str, Any], before: dict[str, Any] | None, now: datetime) -> list[dict[str, Any]]:
    """Bichon's own backup (of its database and archive): the last success, and failures seen as the failed counter
    going up between two polls (the metrics keep no time for those)."""
    runs = []
    if last := _ts(b.get("last_success")):
        dur = None
        if before and b["duration_count"] - before.get("duration_count", 0) == 1:
            dur = max(0.0, b["duration_sum"] - before.get("duration_sum", 0.0))
        runs.append({"ext_id": f"data-backup:{int(b['last_success'])}", "kind": "backup", "job": DATA_BACKUP_JOB,
                     "repo": "", "status": "success", "started": _ts(b["last_success"] - dur) if dur else last,
                     "ended": last, "duration_s": dur, "message": None, "data": {"history": "metrics"}})
    if before is not None and b["failed"] > before.get("failed", 0):
        n = int(b["failed"] - before.get("failed", 0))
        runs.append({"ext_id": f"data-backup-failed:{int(now.timestamp())}", "kind": "backup", "job": DATA_BACKUP_JOB,
                     "repo": "", "status": "error", "started": now, "ended": now, "duration_s": None,
                     "message": f"{n} backup run{'s' if n != 1 else ''} failed - details in Bichon › Backup",
                     "data": {"history": "metrics", "failed": n}})
    return runs


def stats_run(state: dict[str, Any], now: datetime) -> dict[str, Any]:
    """One row per hour (updated by every poll in that hour): archive size and mail counts, for the charts."""
    hour = now.replace(minute=0, second=0, microsecond=0)
    t = state["totals"]
    return {"ext_id": f"stats:{hour.strftime('%Y%m%d%H')}", "kind": "stats", "job": "", "repo": "archive",
            "status": "success", "started": hour, "ended": now, "duration_s": None, "message": None,
            "bytes_processed": t["storage_bytes"], "files_total": t["emails"],
            "data": {"stats": {"total_size": t["storage_bytes"], "index_size": t["index_bytes"], "emails": t["emails"],
                               "attachments": t["attachments"]},
                     "accounts": {a["job"]: a["emails"] for a in state["accounts"] if a["emails"] is not None}}}


def jobs_of(state: dict[str, Any], settings: Settings) -> list[dict[str, Any]]:
    """Backup jobs for the Main tab and the alerts: every account that downloads mail, and Bichon's own backup."""
    jobs = []
    for a in state["accounts"]:
        if a["type"] not in SYNC_TYPES:
            continue
        gap = a["interval_min"] * 60.0 if a["interval_min"] else None
        jobs.append({"job": a["job"], "repo": "", "account_id": a["id"], "noun": "mail sync", "unit": "account",
                     "schedule": f"every {a['interval_min']} min" if a["interval_min"] else "no automatic sync",
                     "gap_s": gap, "threshold_s": backups.overdue_threshold(gap, settings.bichon_overdue_hours),
                     "disabled": not a["enabled"] or not gap, "next_run": None})
    if state["data_backup"]["seen"]:
        h = settings.bichon_backup_overdue_hours
        jobs.append({"job": DATA_BACKUP_JOB, "repo": "", "noun": "backup", "unit": "job",
                     "schedule": "Bichon's backup schedule", "gap_s": None,
                     "threshold_s": h * 3600.0 if h else None, "disabled": not h, "next_run": None})
    return jobs


# ---------------------------------------------------------------- client ---
class BichonClient:
    def __init__(self, settings: Settings) -> None:
        self.base = settings.bichon_url.rstrip("/")
        self.http = httpx.AsyncClient(verify=settings.bichon_verify_ssl, timeout=60,
                                      headers={"Authorization": f"Bearer {settings.bichon_token}",
                                               "Accept": "application/json, text/plain"})

    async def close(self) -> None:
        await self.http.aclose()

    async def get(self, path: str) -> httpx.Response:
        r = await self.http.get(f"{self.base}/api/v1/{path}")
        if r.status_code >= 400:
            text = r.text[:300]
            try:
                j = r.json()
                text = str(j.get("message") or j.get("error") or text) if isinstance(j, dict) else text
            except ValueError:
                pass
            if r.status_code == 401:
                text += " (the API token is wrong, expired or revoked - make a new one in Bichon)"
            elif r.status_code == 403 and path == "metrics":
                text += " (the token's user lacks the system:metrics permission)"
            elif r.status_code == 404 and path == "metrics":
                text = "not found - is this the Bichon address and port, and Bichon 2.3 or newer?"
            raise BichonError(r.status_code, text)
        return r

    async def metrics(self) -> dict[str, Any]:
        return parse_metrics((await self.get("metrics")).text)

    async def history(self, account_id: str) -> list[dict[str, Any]]:
        """Sync sessions of an account, oldest first, the running one last."""
        try:
            j = (await self.get(f"accounts/{account_id}/download-stats")).json()
        except ValueError as exc:
            raise BichonError(200, "the sync history is not JSON") from exc
        sessions = list(_field(j, "history") or [])
        if active := _field(j, "active_session"):
            sessions.append(active)
        return [s for s in sessions if isinstance(s, dict)]


# ---------------------------------------------------------------- poller ---
class BichonPoller:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = BichonClient(settings)
        self.status: dict[str, Any] = {"ok": None, "error": None, "last": None, "instance": None, "history": None}
        self.failures = 0
        self.unreachable_since: float | None = None
        self.unreachable_alerted = False
        self.sessions: dict[str, dict[str, float]] | None = None  # session counters of the previous poll
        self.backup: dict[str, Any] | None = None
        self.history_ok: bool | None = None  # None: try; False: refused (tried again every hour)
        self.history_tried = 0.0

    async def stop(self) -> None:
        await self.client.close()

    def grace(self) -> float:
        return max(0, self.settings.bichon_offline_grace) * 60

    async def run(self) -> None:
        log.info("Bichon poller started for %s", self.settings.bichon_url)
        while True:
            try:
                await self.poll()
                self.failures = 0
                self.status.update(ok=True, error=None, last=time.time())
                await self.back()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - also bad data / database errors: report, never crash-loop
                if not isinstance(exc, (BichonError, httpx.HTTPError, OSError)):
                    log.exception("Bichon poll failed")
                self.failures += 1
                self.status.update(ok=False, error=f"{type(exc).__name__}: {exc}", last=time.time())
                log.warning("Bichon: %s", exc)
                if isinstance(exc, (BichonError, httpx.HTTPError, OSError)):
                    await self.down(str(exc) or type(exc).__name__)
            await db.set_snapshot("bichon:status", self.status)
            await asyncio.sleep(max(60, self.settings.bichon_poll_interval) if self.failures < 3 else 300)

    async def account_runs(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        """Runs of every syncing account: from Bichon's sync history when the token may read it, else from the
        metrics."""
        runs: list[dict[str, Any]] = []
        syncing = [a for a in state["accounts"] if a["type"] in SYNC_TYPES]
        try_history = self.history_ok is not False or time.time() - self.history_tried > 3600
        for a in syncing:
            a["_sessions"] = state["sessions"].get(a["id"], {})
            if try_history:
                try:
                    hist = await self.client.history(a["id"])
                    self.history_ok = True
                    runs += [r for r in (run_from_session(a, s) for s in hist) if r]
                    continue
                except BichonError as exc:
                    if exc.status not in (401, 403):
                        raise
                    self.history_ok, self.history_tried, try_history = False, time.time(), False
            r = run_from_metrics(a, None if self.sessions is None else self.sessions.get(a["id"], {}))
            if r:
                runs.append(r)
        self.sessions = state["sessions"]
        return runs

    async def poll(self) -> None:
        state = await self.client.metrics()
        now = datetime.now(timezone.utc)
        self.status["instance"] = f"Bichon {state['version']}" if state["version"] else "Bichon"
        runs = await self.account_runs(state)
        self.status["history"] = "bichon" if self.history_ok else "metrics"
        runs += data_backup_runs(state["data_backup"], self.backup, now)
        self.backup = state["data_backup"]
        runs.append(stats_run(state, now))
        await backups.store_runs(SOURCE, runs)
        snap = {k: v for k, v in state.items() if k != "sessions"}
        snap["accounts"] = [{k: v for k, v in a.items() if not k.startswith("_")} for a in state["accounts"]]
        snap["history"] = self.status["history"]
        await db.set_snapshot("bichon:state", snap)
        jobs = jobs_of(state, self.settings)
        await db.set_snapshot(f"backup_jobs:{SOURCE}", {"label": LABEL, "instance": self.status["instance"], "jobs": jobs})
        await backups.check_jobs(SOURCE, LABEL, jobs, warnings=self.settings.bichon_alert_warnings)

    async def down(self, error: str, now: float | None = None) -> None:
        now = now or time.time()
        if self.unreachable_since is None:
            self.unreachable_since = now
        if not self.unreachable_alerted and self.failures >= 2 and now - self.unreachable_since >= self.grace():
            self.unreachable_alerted = True
            await raise_alert("backup_source_unreachable", "medium", "Bichon is unreachable", "backup_down:bichon",
                              description=f"No answer from {self.settings.bichon_url} for "
                                          f"{_minutes(now - self.unreachable_since)}: {error}\n\nMail may still be "
                                          "archived - Looking Glass just cannot see it. Check the Bichon container, the "
                                          "URL / port and the API token under Settings › Bichon.")

    async def back(self, now: float | None = None) -> None:
        if self.unreachable_since is None:
            return
        down_for = (now or time.time()) - self.unreachable_since
        self.unreachable_since, self.unreachable_alerted = None, False
        await close_alerts("backup_source_unreachable", ["backup_down:bichon"],
                           f"Bichon answers again (it was unreachable for {_minutes(down_for)})")


async def test_connection(settings: Settings) -> dict[str, Any]:
    c = BichonClient(settings)
    try:
        state = await c.metrics()
        syncing = [a for a in state["accounts"] if a["type"] in SYNC_TYPES]
        history = None
        if syncing:
            try:
                await c.history(syncing[0]["id"])
                history = True
            except BichonError as exc:
                if exc.status not in (401, 403):
                    raise
                history = False
        return {"ok": True, "version": state["version"], "accounts": len(state["accounts"]), "syncing": len(syncing),
                "emails": state["totals"]["emails"], "history": history,
                "data_backup": state["data_backup"]["seen"]}
    except BichonError as exc:
        return {"ok": False, "error": str(exc)}
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc} - check the URL and port"}
    finally:
        await c.close()
