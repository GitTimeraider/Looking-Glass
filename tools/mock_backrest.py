#!/usr/bin/env python3
"""Fake Backrest for local testing of the Backrest poller and the Backups page.

    python tools/mock_backrest.py --port 9898                 # login admin / admin-pass, Backrest 1.6+ (summary dashboard)
    python tools/mock_backrest.py --port 9898 --no-auth       # authentication disabled in Backrest
    python tools/mock_backrest.py --port 9898 --no-summary    # older Backrest: no GetSummaryDashboard

30 days of history: plan "documents" (daily, cron) and "photos" (every 6 hours) to two repositories, with a failed
and a warning backup, a failed repository check, one backup running now, forget / prune / check / stats runs.
POST /mock/fail/<plan> makes the next backup of a plan fail, /mock/ok/<plan> succeed again (a new run is added).
Answers in proto3 JSON as Backrest does (lowerCamelCase, 64-bit numbers as strings, enums by name).
"""
from __future__ import annotations

import argparse
import base64
import random
import time

import uvicorn
from fastapi import FastAPI, HTTPException, Request

app = FastAPI()
USER, PASSWORD = "admin", "admin-pass"
CFG = {"auth": True, "summary": True}
OPS: list[dict] = []
NEXT_ID = [1000]

CONFIG = {
    "modno": 7, "version": 4, "instance": "unraid-backrest",
    "repos": [
        {"id": "b2-cloud", "uri": "s3:s3.eu-central-003.backblazeb2.com/my-bucket/restic", "guid": "a1b2c3",
         "password": "REPO-PASSWORD-MUST-NOT-LEAK", "env": ["AWS_ACCESS_KEY_ID=KEY-MUST-NOT-LEAK", "AWS_SECRET_ACCESS_KEY=SECRET-MUST-NOT-LEAK"],
         "prunePolicy": {"schedule": {"maxFrequencyDays": 7, "clock": "CLOCK_LAST_RUN_TIME"}, "maxUnusedPercent": 10},
         "checkPolicy": {"schedule": {"maxFrequencyDays": 7}, "readDataSubsetPercent": 5}},
        {"id": "nas", "uri": "rest:https://restic:NAS-PASSWORD-MUST-NOT-LEAK@nas.lan:8000/backups", "guid": "d4e5f6",
         "password": "ANOTHER-SECRET", "prunePolicy": {"schedule": {"cron": "0 4 * * 0"}}},
    ],
    "plans": [
        {"id": "documents", "repo": "b2-cloud", "paths": ["/mnt/user/documents", "/mnt/user/appdata"], "excludes": ["*.tmp"],
         "schedule": {"cron": "0 2 * * *", "clock": "CLOCK_LOCAL"},
         "retention": {"policyTimeBucketed": {"daily": 7, "weekly": 4, "monthly": 12, "keepLastN": 3}}},
        {"id": "photos", "repo": "nas", "paths": ["/mnt/user/photos"],
         "schedule": {"maxFrequencyHours": 6, "clock": "CLOCK_LAST_RUN_TIME"}, "retention": {"policyKeepLastN": 30}},
    ],
    "auth": {"disabled": False, "users": [{"name": "admin", "passwordBcrypt": "$2a$10$HASH-MUST-NOT-LEAK"}]},
}


def op(kind: str, body: dict, plan: str, repo: str, start: float, secs: float, status: str = "STATUS_SUCCESS",
       msg: str = "") -> dict:
    NEXT_ID[0] += 1
    o = {"id": str(NEXT_ID[0]), "flowId": str(NEXT_ID[0]), "repoId": repo, "repoGuid": "x" + repo, "planId": plan,
         "instanceId": "unraid-backrest", "status": status, "unixTimeStartMs": str(int(start * 1000)),
         "unixTimeEndMs": str(int((start + secs) * 1000)) if status not in ("STATUS_INPROGRESS", "STATUS_PENDING") else "0",
         kind: body}
    if msg:
        o["displayMessage"] = msg
    OPS.append(o)
    return o


def backup(plan: str, repo: str, start: float, size: float, added: float, speed: float, status: str = "STATUS_SUCCESS",
           msg: str = "") -> None:
    secs = size / speed
    if status == "STATUS_ERROR":
        op("operationBackup", {}, plan, repo, start, 40, status, msg or "repository is already locked by PID 1234")
        return
    body = {"lastStatus": {"summary": {"filesNew": str(random.randint(0, 80)), "filesChanged": str(random.randint(0, 40)),
                                       "filesUnmodified": "15000", "dataAdded": str(int(added)),
                                       "totalFilesProcessed": str(15000 + random.randint(0, 120)),
                                       "totalBytesProcessed": str(int(size)), "totalDuration": round(secs, 2),
                                       "snapshotId": f"{random.getrandbits(64):016x}"}}}
    if status == "STATUS_WARNING":
        body["errors"] = [{"item": "/mnt/user/appdata/plex/db.sqlite", "during": "archival", "message": "read: input/output error"}]
        msg = msg or "Partial backup, 1 errors"
    op("operationBackup", body, plan, repo, start, secs, status, msg)
    op("operationIndexSnapshot", {"snapshot": {"id": "x", "unixTimeMs": str(int(start * 1000))}}, plan, repo, start + secs, 1)
    op("operationForget", {"forget": [{"id": "old"}] * random.randint(0, 2)}, plan, repo, start + secs + 2, 3)


def build() -> None:
    random.seed(7)
    now = time.time()
    day = 86400
    doc_size = 42e9
    for d in range(30, 0, -1):
        t = now - d * day
        doc_size += random.uniform(5e7, 4e8)
        status = "STATUS_ERROR" if d == 12 else "STATUS_WARNING" if d == 5 else "STATUS_SUCCESS"
        backup("documents", "b2-cloud", t, doc_size, random.uniform(2e8, 1.5e9), random.uniform(35e6, 60e6), status)
        for h in (0, 6, 12, 18):
            backup("photos", "nas", t + h * 3600, 380e9 + d * 1e8, random.uniform(0, 3e9), random.uniform(180e6, 260e6))
        op("operationStats", {"stats": {"totalSize": str(int(doc_size * 0.62)), "totalUncompressedSize": str(int(doc_size * 1.05)),
                                        "compressionRatio": 1.69, "totalBlobCount": "220000", "snapshotCount": str(40 + 30 - d)}},
           "_system_", "b2-cloud", t + 3 * 3600, 30)
        op("operationStats", {"stats": {"totalSize": str(int(395e9 + (30 - d) * 2e9)), "totalUncompressedSize": str(int(401e9 + (30 - d) * 2e9)),
                                        "compressionRatio": 1.02, "snapshotCount": "30"}}, "_system_", "nas", t + 3 * 3600, 60)
        if d % 7 == 0:
            op("operationPrune", {"outputLogref": "x"}, "_system_", "b2-cloud", t + 4 * 3600, 600)
            check_status = "STATUS_ERROR" if d == 7 else "STATUS_SUCCESS"
            op("operationCheck", {"outputLogref": "y"}, "_system_", "b2-cloud", t + 5 * 3600, 900, check_status,
               "error: pack 3f2a… contains 1 errors" if d == 7 else "")
            op("operationCheck", {}, "_system_", "nas", t + 5 * 3600, 1200)
        op("operationRunHook", {"name": "plan/documents/hook/0"}, "documents", "b2-cloud", t, 1)
    # running now
    op("operationBackup", {"lastStatus": {"status": {"percentDone": 0.42, "totalFiles": "15100", "totalBytes": str(int(doc_size)),
                                                      "filesDone": "6300", "bytesDone": str(int(doc_size * 0.42)),
                                                      "currentFile": ["/mnt/user/documents/x.pdf"]}}},
       "documents", "b2-cloud", now - doc_size * 0.42 / 48e6, 0, "STATUS_INPROGRESS")
    # the next scheduled runs: pending, with their start time in the future
    op("operationBackup", {}, "photos", "nas", now + 5 * 3600, 0, "STATUS_PENDING")
    op("operationBackup", {}, "documents", "b2-cloud", now + 11 * 3600, 0, "STATUS_PENDING")
    op("operationCheck", {}, "_system_", "nas", now + 2 * day, 0, "STATUS_PENDING")


def check_auth(request: Request) -> None:
    if not CFG["auth"]:
        return
    h = request.headers.get("authorization", "")
    if h.startswith("Basic "):
        user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
        if (user, pw) == (USER, PASSWORD):
            return
    raise HTTPException(401, "Unauthorized (No Authorization Header)")


def summary(kind: str, key: str) -> list[dict]:
    out = []
    for item in CONFIG[kind]:
        ops = [o for o in OPS if "operationBackup" in o and o[key] == item["id"] and int(o["unixTimeStartMs"]) > (time.time() - 30 * 86400) * 1000]
        s = {"id": item["id"], "backupsSuccessLast30days": str(sum(o["status"] == "STATUS_SUCCESS" for o in ops)),
             "backupsWarningLast30days": str(sum(o["status"] == "STATUS_WARNING" for o in ops)),
             "backupsFailed30days": str(sum(o["status"] == "STATUS_ERROR" for o in ops)), "totalSnapshots": str(len(ops))}
        if kind == "plans":
            s["nextBackupTimeMs"] = str(int((time.time() + (3 * 3600 if item["id"] == "documents" else 5 * 3600)) * 1000))
        out.append(s)
    return out


@app.post("/v1.Backrest/{method}")
async def rpc(method: str, request: Request):
    check_auth(request)
    body = await request.json() if (await request.body()) else {}
    if method == "GetConfig":
        return CONFIG
    if method == "GetSummaryDashboard":
        if not CFG["summary"]:
            raise HTTPException(404, "404 page not found")
        return {"repoSummaries": summary("repos", "repoId"), "planSummaries": summary("plans", "planId")}
    if method == "GetOperations":
        n = int(body.get("lastN") or 0)
        ops = sorted(OPS, key=lambda o: int(o["id"]))
        return {"operations": ops[-n:] if n else ops}
    raise HTTPException(404, f"unimplemented: {method}")


@app.post("/mock/{what}/{plan}")
def mock(what: str, plan: str):
    p = next(p for p in CONFIG["plans"] if p["id"] == plan)
    backup(plan, p["repo"], time.time(), 43e9, 5e8, 45e6, "STATUS_ERROR" if what == "fail" else "STATUS_SUCCESS")
    return {"ok": True}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9898)
    ap.add_argument("--no-auth", action="store_true")
    ap.add_argument("--no-summary", action="store_true")
    a = ap.parse_args()
    CFG.update(auth=not a.no_auth, summary=not a.no_summary)
    if a.no_auth:
        CONFIG["auth"] = {"disabled": True}
    build()
    uvicorn.run(app, host="0.0.0.0", port=a.port, log_level="warning")
