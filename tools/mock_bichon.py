#!/usr/bin/env python3
"""Fake Bichon (mail archiver) for local testing of the Bichon poller and the Backups › Bichon tab.

    python tools/mock_bichon.py --port 15630                  # token test-token may also read the sync history
    python tools/mock_bichon.py --port 15630 --metrics-only   # a "Metrics only" token: the history answers 403

Three accounts: work@example.com (IMAP, every 30 min, a partial and a failed sync in its history), private@example.com
(IMAP, every 60 min, syncing now) and an import-only account. Bichon's own backup ran daily, one failed.
POST /mock/fail/<account_id> makes the next sync of an account fail, /mock/ok/<account_id> succeed (a new sync is added).
"""
from __future__ import annotations

import argparse
import random
import time

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse

app = FastAPI()
TOKEN = "test-token"
CFG = {"history": True}
ACCOUNTS = [
    {"id": 101, "email": "work@example.com", "name": "Work", "type": "imap", "enabled": True, "interval": 30, "emails": 48210},
    {"id": 102, "email": "private@example.com", "name": "Private", "type": "imap", "enabled": True, "interval": 60, "emails": 12904},
    {"id": 103, "email": "archive-import@local", "name": "Old PST import", "type": "nosync", "enabled": True, "interval": 0, "emails": 30551},
]
HISTORY: dict[int, list[dict]] = {}
ACTIVE: dict[int, dict | None] = {}
COUNTERS: dict[tuple[int, str], int] = {}
BACKUP = {"last": time.time() - 5 * 3600, "success": 6, "failed": 1}


def session(start_ms: int, status: str, secs: float, new: int) -> dict:
    folders = {"INBOX": {"folder_name": "INBOX", "planned": new, "current": new, "filtered": 0, "status": "Success", "message": None},
               "Sent": {"folder_name": "Sent", "planned": 1, "current": 1, "filtered": 0, "status": "Success", "message": None}}
    if status == "Partial":
        folders["Junk"] = {"folder_name": "Junk", "planned": 5, "current": 0, "filtered": 0, "status": "Failed",
                           "message": "NO [UNAVAILABLE] Server busy, try again later"}
    return {"start_time": start_ms, "end_time": start_ms + int(secs * 1000), "status": status, "trigger": "Scheduled",
            "message": "IMAP login failed: authentication failed" if status == "Failed" else None,
            "folder_details": folders, "current_folder": None,
            "errors": [{"error": "LOGIN rejected by server", "at": start_ms}] if status == "Failed" else []}


def build() -> None:
    now = time.time()
    for a in ACCOUNTS:
        if a["type"] != "imap":
            continue
        hist = []
        for i in range(10, 0, -1):
            start = now - i * a["interval"] * 60
            status = "Failed" if (a["id"] == 101 and i == 7) else "Partial" if (a["id"] == 101 and i == 3) else "Success"
            hist.append(session(int(start * 1000), status, random.uniform(4, 90), random.randint(0, 40)))
            COUNTERS[(a["id"], status.lower())] = COUNTERS.get((a["id"], status.lower()), 0) + 1
        HISTORY[a["id"]] = hist
        ACTIVE[a["id"]] = None
    ACTIVE[102] = {"start_time": int((now - 40) * 1000), "end_time": None, "status": "Running", "trigger": "Scheduled",
                   "message": None, "current_folder": "INBOX", "errors": [],
                   "folder_details": {"INBOX": {"folder_name": "INBOX", "planned": 120, "current": 45, "filtered": 0,
                                                "status": "Downloading", "message": None}}}


def auth(request: Request, metrics: bool = False) -> None:
    h = request.headers.get("authorization", "")
    if h != f"Bearer {TOKEN}" and request.query_params.get("access_token") != TOKEN:
        raise HTTPException(401, "Valid access token not found")
    if not metrics and not CFG["history"]:
        raise HTTPException(403, "Missing permission: account:read_details")


@app.get("/api/v1/metrics", response_class=PlainTextResponse)
def metrics(request: Request):
    auth(request, metrics=True)
    lines = ['bichon_build_info{version="2.4.1"} 1', f"bichon_uptime_seconds {int(time.time() % 864000)}"]
    for t in ("imap", "nosync", "view"):
        lines.append(f'bichon_accounts_total{{type="{t}"}} {sum(1 for a in ACCOUNTS if a["type"] == t)}')
    total = sum(a["emails"] for a in ACCOUNTS)
    lines += ["bichon_users_total 2", "bichon_account_mailbox_folders_total 23", f"bichon_emails_total {total}",
              f"bichon_attachments_total {total // 7}", f"bichon_storage_usage_bytes {total * 61_000}",
              f"bichon_index_usage_bytes {total * 4_100}"]
    for a in ACCOUNTS:
        i = a["id"]
        lines.append(f'bichon_account_info{{account_id="{i}",email="{a["email"]}",enabled="{str(a["enabled"]).lower()}",'
                     f'name="{a["name"]}",type="{a["type"]}"}} 1')
        lines.append(f'bichon_account_download_interval_minutes{{account_id="{i}"}} {a["interval"]}')
        lines.append(f'bichon_account_emails_total{{account_id="{i}"}} {a["emails"]}')
        hist, active = HISTORY.get(i), ACTIVE.get(i)
        if not hist:
            continue
        last = hist[-1]
        good = next((s for s in reversed(hist) if s["status"] == "Success"), None)
        lines += [f'bichon_account_sync_running{{account_id="{i}"}} {1 if active else 0}',
                  f'bichon_account_last_sync_start_timestamp_seconds{{account_id="{i}"}} {(active or last)["start_time"] / 1000}',
                  f'bichon_account_last_sync_success_timestamp_seconds{{account_id="{i}"}} {good["end_time"] / 1000 if good else 0}',
                  f'bichon_account_last_sync_succeeded{{account_id="{i}"}} {1 if last["status"] == "Success" else 0}',
                  f'bichon_account_last_sync_duration_seconds{{account_id="{i}"}} {(last["end_time"] - last["start_time"]) / 1000}',
                  f'bichon_account_last_sync_errors{{account_id="{i}"}} {len(last["errors"])}',
                  f'bichon_account_last_gapfill_downloaded{{account_id="{i}"}} 12',
                  f'bichon_account_last_gapfill_failed{{account_id="{i}"}} {1 if i == 101 else 0}']
        for (acc, status), n in COUNTERS.items():
            if acc == i:
                lines.append(f'bichon_sync_sessions_total{{account_id="{i}",status="{status}",trigger="scheduled"}} {n}')
        if i == 101:
            lines.append(f'bichon_sync_errors_total{{account_id="{i}",kind="auth"}} 1')
    lines += [f'bichon_backup_runs_total{{outcome="success"}} {BACKUP["success"]}',
              f'bichon_backup_runs_total{{outcome="failed"}} {BACKUP["failed"]}',
              f"bichon_backup_duration_seconds_sum {(BACKUP['success'] + BACKUP['failed']) * 420}",
              f"bichon_backup_duration_seconds_count {BACKUP['success'] + BACKUP['failed']}",
              f"bichon_backup_last_success_timestamp_seconds {BACKUP['last']}"]
    return "\n".join(lines) + "\n"


@app.get("/api/v1/accounts/{account_id}/download-stats")
def download_stats(account_id: int, request: Request):
    auth(request)
    if account_id not in {a["id"] for a in ACCOUNTS}:
        raise HTTPException(404, "account not found")
    return {"account_id": account_id, "active_session": ACTIVE.get(account_id), "history": HISTORY.get(account_id, []),
            "last_trigger_at": int(time.time() * 1000), "last_finished_at": None, "retry_after": None, "throttle_streak": 0}


@app.post("/mock/{what}/{account_id}")
def mock(what: str, account_id: int):
    status = "Failed" if what == "fail" else "Success"
    HISTORY.setdefault(account_id, []).append(session(int(time.time() * 1000) - 5000, status, 5, 3))
    HISTORY[account_id] = HISTORY[account_id][-10:]
    ACTIVE[account_id] = None
    COUNTERS[(account_id, status.lower())] = COUNTERS.get((account_id, status.lower()), 0) + 1
    return {"ok": True}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=15630)
    ap.add_argument("--metrics-only", action="store_true", help="the token is a 'Metrics only' token")
    a = ap.parse_args()
    CFG["history"] = not a.metrics_only
    build()
    uvicorn.run(app, host="0.0.0.0", port=a.port, log_level="warning")
