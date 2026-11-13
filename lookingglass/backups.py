"""Backups (Infrastructure › Backups): the part that is the same for every backup tool.

A tool's poller (backrest.py, bichon.py) stores its runs in ``backup_runs`` (store_runs), writes its jobs to the snapshot
``backup_jobs:<source>`` ({label, jobs: [{job, repo, schedule, gap_s, threshold_s, disabled, next_run}]}) and its
connection state to ``<source>:status``, and calls check_jobs / check_repos for the alerts. The Main tab (overview)
reads only these, so another tool only needs a poller.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from . import db
from .detections import Rating, close_alerts, raise_alert

GOOD = ("success", "warning")
SOURCES = {"backrest": "Backrest", "bichon": "Bichon"}  # source -> label, for the Main tab (also when the tool is not set up yet)
COLUMNS = ("ext_id", "kind", "job", "repo", "status", "started", "ended", "duration_s", "bytes_processed", "bytes_added",
           "files_new", "files_changed", "files_total", "snapshot_id", "message", "data")


def overdue_threshold(gap_s: float | None, overdue_hours: int = 0) -> float | None:
    """Seconds without a successful backup after which a job is overdue: the setting, else the schedule's longest normal
    gap plus a quarter and 2 hours (a daily backup: 32 h, hourly: 3¼ h, weekly: 8¾ days). None = no schedule known."""
    if overdue_hours and overdue_hours > 0:
        return overdue_hours * 3600.0
    if not gap_s:
        return None
    return gap_s * 1.25 + 7200


def span(seconds: float) -> str:
    """"3 days 4 hours" / "5 hours" / "20 minutes" - for alert texts."""
    s = int(seconds)
    d, h, m = s // 86400, s % 86400 // 3600, s % 3600 // 60
    plural = lambda n, w: f"{n} {w}{'s' if n != 1 else ''}"  # noqa: E731
    if d:
        return plural(d, "day") + (f" {plural(h, 'hour')}" if h else "")
    if h:
        return plural(h, "hour")
    return plural(max(m, 1), "minute")


async def store_runs(source: str, runs: list[dict[str, Any]], replace_pending: bool = False) -> None:
    """Insert / update runs. ``replace_pending``: ``runs`` is the tool's newest runs (numeric, increasing ids), so a
    stored pending run that the tool no longer lists is gone there. A pending run is only the next scheduled one: the
    tool replaces it with a new one (new id) after a restart or a schedule change, and the old one would otherwise stay
    here forever, shown twice. Removed: pending runs with an id inside the fetched range that are not in it, and
    pending runs whose start is more than a day past (older than the range, never started)."""
    cols = ", ".join(("source",) + COLUMNS)
    params = ", ".join(f"${i}" for i in range(1, len(COLUMNS) + 2))
    update = ", ".join(f"{c} = EXCLUDED.{c}" for c in COLUMNS[1:]) + ", seen_at = now()"
    ids = [int(r["ext_id"]) for r in runs if str(r.get("ext_id", "")).isdigit()]
    async with db.pool().acquire() as conn, conn.transaction():
        if replace_pending:
            await conn.execute(
                "DELETE FROM backup_runs WHERE source = $1 AND status = 'pending' AND NOT ext_id = ANY($2::text[]) "
                "AND (CASE WHEN ext_id ~ '^[0-9]{1,18}$' THEN ext_id::bigint >= $3 ELSE false END "
                "OR started < now() - interval '1 day')",
                source, [r["ext_id"] for r in runs], min(ids) if ids else 2 ** 62)
        removed = {r["ext_id"]: r["started"] for r in await conn.fetch(
            "SELECT ext_id, started FROM backup_runs_removed WHERE source = $1 AND ext_id = ANY($2::text[])",
            source, [r["ext_id"] for r in runs])}
        # removed by hand: not added again (unless the id now belongs to another run, after the tool was reset)
        runs = [r for r in runs if r["ext_id"] not in removed
                or (removed[r["ext_id"]] is not None and removed[r["ext_id"]] != r.get("started"))]
        if not runs:
            return
        await conn.executemany(f"INSERT INTO backup_runs ({cols}) VALUES ({params}) "
                               f"ON CONFLICT (source, ext_id) DO UPDATE SET {update}",
                               [(source, *(r.get(c) if c != "data" else (r.get("data") or {}) for c in COLUMNS))
                                for r in runs])


async def remove_runs(source: str, ext_ids: list[str]) -> list[dict[str, Any]]:
    """Remove runs by hand (e.g. deleted in the tool, or a test run). They are remembered, so a run the tool still lists
    is not stored again on its next poll. Returns the removed runs (kind, job, repo), for checking the alerts again."""
    async with db.pool().acquire() as conn, conn.transaction():
        rows = await conn.fetch("DELETE FROM backup_runs WHERE source = $1 AND ext_id = ANY($2::text[]) "
                                "RETURNING ext_id, kind, job, repo, started", source, ext_ids)
        started = {r["ext_id"]: r["started"] for r in rows}
        await conn.executemany("INSERT INTO backup_runs_removed (source, ext_id, started) VALUES ($1, $2, $3) "
                               "ON CONFLICT (source, ext_id) DO UPDATE SET removed_at = now(), "
                               "started = coalesce(EXCLUDED.started, backup_runs_removed.started)",
                               [(source, i, started.get(i)) for i in ext_ids])
    return db.records(rows)


def _when(t: datetime | None) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if t else "never"


async def check_jobs(source: str, label: str, jobs: list[dict[str, Any]], warnings: bool = True,
                     now: datetime | None = None) -> None:
    """Alerts per backup job from its latest runs: failed (more severe when it keeps failing), finished with warnings,
    and overdue (no successful backup for longer than its threshold_s). Each closes by itself once a backup succeeds."""
    now = now or datetime.now(timezone.utc)
    names = [j["job"] for j in jobs]
    rows = await db.pool().fetch(
        "SELECT job, status, started, ended, message, data FROM (SELECT *, row_number() OVER (PARTITION BY job "
        "ORDER BY started DESC NULLS LAST) rn FROM backup_runs WHERE source = $1 AND kind = 'backup' "
        "AND job = ANY($2::text[]) AND status IN ('success', 'warning', 'error', 'running')) x "
        "WHERE rn <= 30 ORDER BY job, started DESC NULLS LAST", source, names)
    by_job: dict[str, list[Any]] = {}
    for r in rows:
        by_job.setdefault(r["job"], []).append(r)
    for j in jobs:
        job, runs = j["job"], by_job.get(j["job"], [])
        fp = f"{source}:{job}"
        # wording: a Backrest plan's "backup"; another tool can name its own (Bichon: a mail account's "mail sync")
        noun, unit = j.get("noun") or "backup", j.get("unit") or "plan"
        what = f"{noun[:1].upper()}{noun[1:]} of {unit} '{job}'" + (f" (repository {j['repo']})" if j.get("repo") else "")
        finished = [r for r in runs if r["status"] != "running"]
        running = runs[0] if runs and runs[0]["status"] == "running" else None
        last = finished[0] if finished else None
        good = next((r for r in finished if r["status"] in GOOD), None)
        good_at = (good["ended"] or good["started"]) if good else None
        # failed
        if last and last["status"] == "error":
            fails = next((i for i, r in enumerate(finished) if r["status"] != "error"), len(finished))
            rating = Rating("medium", f"the latest {noun} failed - the data changed since the last good {noun} is not "
                                      "protected")
            if fails >= 2:
                rating.up(f"{fails} {noun}s in a row failed")
            if not good:
                rating.up(f"there is no successful {noun} at all")
            await raise_alert("backup_failed", rating, f"{label} {noun} '{job}' failed", f"backup_fail:{fp}",
                              description=f"{what} started {_when(last['started'])} failed: "
                                          f"{last['message'] or 'no message'}\n\n"
                                          f"Last successful {noun}: {_when(good_at)}.",
                              data={"source": source, "job": job, "repo": j.get("repo")}, count=fails, mode="max")
        elif last:
            await close_alerts("backup_failed", [f"backup_fail:{fp}"], f"the {noun} of {_when(last['started'])} "
                                                                        f"finished ({last['status']})")
        # warnings
        if warnings and last and last["status"] == "warning":
            errs = (last["data"] or {}).get("errors") or []
            items = "\n".join(f"- {e.get('item')}: {e.get('message')}" for e in errs[:10])
            await raise_alert("backup_warning", "low", f"{label} {noun} '{job}' finished with warnings",
                              f"backup_warn:{fp}", description=f"{what} started {_when(last['started'])}: "
                              f"{last['message'] or 'finished with warnings'}" + (f"\n\n{items}" if items else "") +
                              "\n\n" + (j.get("warning_hint") or "Usually files that could not be read (in use, "
                                                     "permissions) - they are missing from this snapshot."),
                              data={"source": source, "job": job, "repo": j.get("repo")}, mode="max")
        elif last:
            await close_alerts("backup_warning", [f"backup_warn:{fp}"], f"a newer {noun} finished without warnings"
                               if last["status"] == "success" else f"a newer {noun} replaced it")
        # overdue
        limit = j.get("threshold_s")
        if j.get("disabled") or not limit or not good_at:
            continue  # no schedule, or never succeeded (the failure alert covers that)
        late = (now - good_at).total_seconds()
        if late > limit and not (running and running["started"] and (now - running["started"]).total_seconds() < limit):
            rating = Rating("medium", f"no successful {noun} for {span(late)} (expected at least every {span(limit)})")
            if late > 2 * limit:
                rating.up("more than twice as long as expected")
            await raise_alert("backup_overdue", rating, f"{label} {noun} '{job}' is overdue", f"backup_overdue:{fp}",
                              description=f"{unit[:1].upper()}{unit[1:]} '{job}' ({j.get('schedule') or 'no schedule'}) "
                                          f"last {noun} succeeded {_when(good_at)}. Check that {label} is running and "
                                          f"the {unit}'s schedule is enabled.",
                              data={"source": source, "job": job, "repo": j.get("repo")})
        else:
            await close_alerts("backup_overdue", [f"backup_overdue:{fp}"], f"a {noun} succeeded ({_when(good_at)})")


REPO_TASKS = {"check": ("high", "Repository check failed", "the repository may be damaged - restores could fail"),
              "prune": ("medium", "Repository prune failed", "old data is not removed - the repository keeps growing"),
              "forget": ("medium", "Forgetting old snapshots failed", "the retention policy is not applied")}


async def check_repos(source: str, label: str, repos: list[str]) -> None:
    """Alerts when the latest check / prune / forget of a repository failed; closed when the next one succeeds."""
    rows = await db.pool().fetch(
        "SELECT DISTINCT ON (repo, kind) repo, kind, status, started, message FROM backup_runs WHERE source = $1 "
        "AND kind = ANY($2::text[]) AND repo = ANY($3::text[]) AND status IN ('success', 'warning', 'error') "
        "ORDER BY repo, kind, started DESC NULLS LAST", source, list(REPO_TASKS), repos)
    for r in rows:
        sev, title, why = REPO_TASKS[r["kind"]]
        fp = f"backup_repo:{source}:{r['repo']}:{r['kind']}"
        if r["status"] == "error":
            await raise_alert("backup_repo_problem", Rating(sev, why), f"{label}: {title.lower()} ({r['repo']})", fp,
                              description=f"{title} for repository '{r['repo']}' ({_when(r['started'])}): "
                                          f"{r['message'] or 'no message'}",
                              data={"source": source, "repo": r["repo"], "task": r["kind"]}, mode="max")
        else:
            await close_alerts("backup_repo_problem", [fp], f"the next {r['kind']} succeeded")


async def recheck_alerts(source: str, removed: list[dict[str, Any]], warnings: bool = True) -> None:
    """After runs were removed by hand: the alerts of their jobs / repositories follow the runs that are left, so an
    alert that came from a removed run closes now instead of on the next poll (or never, when no run is left)."""
    snap = await db.get_snapshot(f"backup_jobs:{source}") or {}
    label = snap.get("label") or SOURCES.get(source, source)
    names = {r["job"] for r in removed if r["kind"] == "backup" and r["job"]}
    repos = sorted({r["repo"] for r in removed if r["kind"] in REPO_TASKS and r["repo"]})
    left = {(r["kind"], r["job"], r["repo"]) for r in await db.pool().fetch(
        "SELECT DISTINCT kind, CASE WHEN kind = 'backup' THEN job ELSE '' END job, "
        "CASE WHEN kind = 'backup' THEN '' ELSE repo END repo FROM backup_runs WHERE source = $1 "
        "AND status IN ('success', 'warning', 'error') AND (job = ANY($2::text[]) OR repo = ANY($3::text[]))",
        source, list(names), repos)}
    jobs = [j for j in snap.get("jobs", []) if j["job"] in names]
    if jobs:
        await check_jobs(source, label, jobs, warnings=warnings)
    for job in names:
        if ("backup", job, "") not in left:  # no finished backup left: nothing to alert on
            fp = f"{source}:{job}"
            await close_alerts("backup_failed", [f"backup_fail:{fp}"], "its runs were removed")
            await close_alerts("backup_warning", [f"backup_warn:{fp}"], "its runs were removed")
            await close_alerts("backup_overdue", [f"backup_overdue:{fp}"], "its runs were removed")
    if repos:
        await check_repos(source, label, repos)
    for repo in repos:
        for kind in REPO_TASKS:
            if (kind, "", repo) not in left:
                await close_alerts("backup_repo_problem", [f"backup_repo:{source}:{repo}:{kind}"], "its runs were removed")


# ---------------------------------------------------------------- web UI ---
def job_state(j: dict[str, Any], now: datetime) -> str:
    if j.get("last_status") == "running":
        return "running"
    if not j.get("runs_total"):
        return "never"
    if j.get("last_finished_status") == "error":
        return "failed"
    good = j.get("last_good")
    if not j.get("disabled") and j.get("threshold_s") and good and \
            (now - good).total_seconds() > j["threshold_s"]:
        return "overdue"
    if j.get("last_finished_status") == "warning":
        return "warning"
    return "ok"


async def overview(days: int, tz: str = "UTC") -> dict[str, Any]:
    """Main tab: every backup job of every tool with its state, outcomes per day and the latest runs. Pending runs (the
    next scheduled one, which Backrest lists with its future start time) are left out: they have no result yet."""
    pool = db.pool()
    now = datetime.now(timezone.utc)
    snaps = {r["key"]: r for r in await pool.fetch(
        "SELECT key, ts, data FROM snapshots WHERE key LIKE 'backup_jobs:%' OR key = ANY($1::text[])",
        [f"{s}:status" for s in SOURCES])}
    stats = {(r["source"], r["job"]): dict(r) for r in await pool.fetch(
        "SELECT source, job, max(repo) repo, count(*) runs_total, "
        "(array_agg(status ORDER BY started DESC NULLS LAST))[1] last_status, max(started) last_started, "
        "(array_agg(status ORDER BY started DESC NULLS LAST) FILTER (WHERE status <> 'running'))[1] last_finished_status, "
        "(array_agg(message ORDER BY started DESC NULLS LAST) FILTER (WHERE status <> 'running'))[1] last_message, "
        "(array_agg(data ORDER BY started DESC NULLS LAST))[1] last_data, "
        "max(coalesce(ended, started)) FILTER (WHERE status IN ('success', 'warning')) last_good, "
        "count(*) FILTER (WHERE status = 'success' AND started > now() - make_interval(days => $1)) ok, "
        "count(*) FILTER (WHERE status = 'warning' AND started > now() - make_interval(days => $1)) warned, "
        "count(*) FILTER (WHERE status = 'error' AND started > now() - make_interval(days => $1)) failed, "
        "avg(duration_s) FILTER (WHERE status IN ('success', 'warning') AND started > now() - make_interval(days => $1)) avg_duration, "
        "sum(bytes_added) FILTER (WHERE status IN ('success', 'warning') AND started > now() - make_interval(days => $1)) added, "
        "(array_agg(bytes_processed ORDER BY started DESC NULLS LAST) FILTER (WHERE status IN ('success', 'warning')))[1] last_size "
        "FROM backup_runs WHERE kind = 'backup' AND job <> '' AND status <> 'pending' GROUP BY 1, 2", days)}
    jobs: list[dict[str, Any]] = []
    seen = set()
    for key, snap in snaps.items():
        if not key.startswith("backup_jobs:"):
            continue
        source = key.split(":", 1)[1]
        for j in (snap["data"] or {}).get("jobs", []):
            seen.add((source, j["job"]))
            jobs.append({"source": source, "source_label": SOURCES.get(source, source), **j,
                         **stats.get((source, j["job"]), {}), "configured": True})
    for (source, job), st in stats.items():  # removed from the tool, but runs are known
        if (source, job) not in seen:
            jobs.append({"source": source, "source_label": SOURCES.get(source, source), "job": job, **st,
                         "configured": False, "disabled": True})
    for j in jobs:
        j["state"] = job_state(j, now)
    order = ["failed", "overdue", "warning", "running", "never", "ok"]
    jobs.sort(key=lambda j: (order.index(j["state"]), j["source"], j["job"]))
    daily = await pool.fetch(
        "SELECT to_char(date_trunc('day', started AT TIME ZONE $2), 'YYYY-MM-DD') d, status, count(*) n FROM backup_runs "
        "WHERE kind = 'backup' AND started > now() - make_interval(days => $1) AND status IN ('success', 'warning', 'error') "
        "GROUP BY 1, 2 ORDER BY 1", days, tz)
    recent = await pool.fetch(
        "SELECT source, ext_id, kind, job, repo, status, started, ended, duration_s, bytes_processed, bytes_added, "
        "files_new, files_changed, message FROM backup_runs WHERE started > now() - make_interval(days => $1) "
        "AND status <> 'pending' "
        "AND (kind = 'backup' OR (kind IN ('check', 'prune', 'forget', 'restore') AND status IN ('error', 'warning'))) "
        "ORDER BY started DESC LIMIT 100", days)
    sources = []
    for s, label in SOURCES.items():
        st = snaps.get(f"{s}:status")
        sources.append({"source": s, "label": label, "status": st["data"] if st else None,
                        "jobs": sum(1 for j in jobs if j["source"] == s)})
    return {"days": days, "now": now.isoformat(), "sources": sources, "jobs": [db.jsonable(j) for j in jobs],
            "daily": db.records(daily), "recent": db.records(recent)}


SPEED = ("CASE WHEN duration_s > 0 THEN bytes_processed / duration_s END speed_bps, "
         "CASE WHEN duration_s > 0 THEN bytes_added / duration_s END added_bps")


async def source_detail(source: str, days: int) -> dict[str, Any]:
    """Runs of one tool for its own tab: backups with their speed, maintenance, repository size over time and per-job
    figures."""
    pool = db.pool()
    runs = await pool.fetch(
        f"SELECT ext_id, job, repo, status, started, ended, duration_s, bytes_processed, bytes_added, files_new, "
        f"files_changed, files_total, snapshot_id, message, data, {SPEED} FROM backup_runs WHERE source = $1 "
        "AND kind = 'backup' AND (started > now() - make_interval(days => $2) OR status = 'running') "
        "ORDER BY started DESC LIMIT 3000", source, days)
    maintenance = await pool.fetch(
        "SELECT ext_id, kind, job, repo, status, started, ended, duration_s, bytes_processed, message, data "
        "FROM backup_runs WHERE source = $1 AND kind NOT IN ('backup', 'stats') "
        "AND started > now() - make_interval(days => $2) ORDER BY started DESC LIMIT 500", source, days)
    stats = await pool.fetch(
        "SELECT repo, started t, (data->'stats'->>'total_size')::bigint total_size, "
        "(data->'stats'->>'total_uncompressed_size')::bigint uncompressed, "
        "(data->'stats'->>'compression_ratio')::float ratio, (data->'stats'->>'snapshot_count')::int snapshots "
        "FROM backup_runs WHERE source = $1 AND kind = 'stats' AND status = 'success' "
        "AND started > now() - make_interval(days => $2) ORDER BY started", source, days)
    latest_stats = await pool.fetch(
        "SELECT DISTINCT ON (repo) repo, started t, (data->'stats'->>'total_size')::bigint total_size, "
        "(data->'stats'->>'total_uncompressed_size')::bigint uncompressed, "
        "(data->'stats'->>'compression_ratio')::float ratio, (data->'stats'->>'snapshot_count')::int snapshots "
        "FROM backup_runs WHERE source = $1 AND kind = 'stats' AND status = 'success' ORDER BY repo, started DESC", source)
    last_tasks = await pool.fetch(
        "SELECT DISTINCT ON (repo, kind) repo, kind, status, started, message FROM backup_runs WHERE source = $1 "
        "AND kind IN ('check', 'prune', 'forget') AND status NOT IN ('running', 'pending') "
        "ORDER BY repo, kind, started DESC", source)
    per_job = await pool.fetch(
        "SELECT job, count(*) FILTER (WHERE status IN ('success', 'warning', 'error')) runs, "
        "count(*) FILTER (WHERE status = 'success') ok, count(*) FILTER (WHERE status = 'warning') warned, "
        "count(*) FILTER (WHERE status = 'error') failed, "
        "avg(duration_s) FILTER (WHERE status IN ('success', 'warning')) avg_duration, "
        "max(duration_s) FILTER (WHERE status IN ('success', 'warning')) max_duration, "
        "sum(bytes_added) FILTER (WHERE status IN ('success', 'warning')) added, "
        "sum(bytes_processed) FILTER (WHERE status IN ('success', 'warning') AND duration_s > 0) "
        "  / nullif(sum(duration_s) FILTER (WHERE status IN ('success', 'warning') AND duration_s > 0 "
        "  AND bytes_processed IS NOT NULL), 0) speed_bps, "
        "sum(bytes_added) FILTER (WHERE status IN ('success', 'warning') AND duration_s > 0) "
        "  / nullif(sum(duration_s) FILTER (WHERE status IN ('success', 'warning') AND duration_s > 0 "
        "  AND bytes_added IS NOT NULL), 0) added_bps, "
        "(array_agg(bytes_processed ORDER BY started DESC) FILTER (WHERE status IN ('success', 'warning')))[1] last_size "
        "FROM backup_runs WHERE source = $1 AND kind = 'backup' AND started > now() - make_interval(days => $2) "
        "GROUP BY job", source, days)
    return {"runs": db.records(runs), "maintenance": db.records(maintenance), "repo_stats": db.records(stats),
            "latest_stats": db.records(latest_stats), "last_tasks": db.records(last_tasks), "per_job": db.records(per_job)}
