#!/usr/bin/env python3
"""Tiny fake Unraid API (GraphQL) + Docker API for local development / testing.

    python tools/mock_unraid.py --port 18500       # GraphQL at http://127.0.0.1:18500/graphql, Docker API at the same port
    python tools/mock_unraid.py --api 4.37.5       # old API: temperature sensors wake the disks like the real one
Answers are chosen by looking at which root field the query asks for (not a real GraphQL engine).

Disk spin-down is simulated like the real API: the array HDDs can be spun down with POST /mock/spindown, and the
`disks` query (always) and `metrics { temperature }` (API <= 4.37.5) wake them, counted in GET /mock/stats.
"""
from __future__ import annotations

import argparse
import random
import time
from datetime import datetime, timedelta, timezone

import uvicorn
import asyncio

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect

app = FastAPI()
KEY = "test-key"
SYSLOG = [f"Oct 18 22:{i % 60:02d}:00 Tower kernel: eth0: link up {i}" for i in range(50)]
SYSLOG.append("Oct 18 23:00:00 Tower zed[4242]: eid=77 class=statechange pool='ssd' vdev=nvme1n1p1 vdev_state=DEGRADED")
STATE = {"api": "4.25.0", "spinning": True, "wakeups": 0, "queries": {}}


def disk(idx, name, typ, temp, status="DISK_OK", errors=0, rotational=True, fs="xfs", size=8_000_000_000, fs_size=True):
    spinning = STATE["spinning"] or not rotational
    return {"id": f"d{idx}", "idx": idx, "name": name, "device": f"sd{chr(97 + idx % 26)}" if rotational else f"nvme{idx}n1",
            "size": size, "status": status, "rotational": rotational, "temp": temp if spinning else None, "numErrors": errors,
            "fsSize": int(size * .97) if typ != "PARITY" and fs_size else None, "fsFree": int(size * .35) if fs_size and typ != "PARITY" else None,
            "fsUsed": int(size * .62) if fs_size and typ != "PARITY" else None, "type": typ, "warning": 45, "critical": 55,
            "fsType": fs if typ != "PARITY" else None, "isSpinning": spinning, "transport": "sata" if rotational else "nvme", "comment": ""}


def wake(reason: str) -> None:
    if not STATE["spinning"]:
        STATE["wakeups"] += 1
        STATE["spinning"] = True
        print(f"!!! disks woken by {reason}", flush=True)


def old_api() -> bool:
    return tuple(int(x) for x in STATE["api"].split(".")[:3]) <= (4, 37, 5)


def answer(q: str, variables: dict) -> dict:
    now = datetime.now(timezone.utc)
    root = q.split("{", 2)[1].strip().split()[0] if "{" in q else "?"
    STATE["queries"][root] = STATE["queries"].get(root, 0) + 1
    if "logFile" in q:
        lines = variables.get("lines") or 1
        start = variables.get("start") or len(SYSLOG)
        chunk = SYSLOG[start - 1:start - 1 + lines]
        return {"logFile": {"totalLines": len(SYSLOG), "startLine": start, "content": "\n".join(chunk)}}
    if "logs(" in q:
        return {"docker": {"logs": {"cursor": now.isoformat(), "lines": [
            {"timestamp": (now - timedelta(seconds=10)).isoformat(), "message": f"[{variables.get('id')}] GET /health 200"},
            {"timestamp": (now - timedelta(seconds=5)).isoformat(), "message": "ERROR database connection refused, retrying"}]}}}
    if "info" in q and "os" in q:
        return {"info": {"os": {"hostname": "Tower", "distro": "Unraid OS", "release": "7.2.0", "kernel": "6.12.24-Unraid", "arch": "x64",
                                "uptime": (now - timedelta(days=12)).isoformat(), "uefi": True},
                         "cpu": {"manufacturer": "AMD", "brand": "Ryzen 7 5700G", "cores": 8, "threads": 16, "speed": 3.8, "speedmax": 4.6, "socket": "AM4",
                                 "packages": {"temp": [52.0], "totalPower": 41.5}},
                         "system": {"manufacturer": "ASRock", "model": "B550M Pro4", "virtual": False},
                         "baseboard": {"manufacturer": "ASRock", "model": "B550M Pro4", "memMax": 128e9, "memSlots": 4},
                         "versions": {"core": {"unraid": "7.2.0", "api": STATE["api"], "kernel": "6.12.24-Unraid"}},
                         "memory": {"layout": [{"size": 17179869184, "type": "DDR4", "clockSpeed": 3200, "manufacturer": "Kingston"}] * 2}}}
    if "metrics" in q:
        if "temperature" in q and old_api():
            wake("metrics.temperature (API <= 4.37.5)")
        cpus = [{"percentTotal": random.random() * 40} for _ in range(16)]
        return {"metrics": {"cpu": {"percentTotal": sum(c["percentTotal"] for c in cpus) / 16, "cpus": cpus},
                            "memory": {"total": 34359738368, "used": 12e9, "available": 22e9, "percentTotal": 35 + random.random() * 5,
                                       "swapTotal": 0, "swapUsed": 0, "percentSwapTotal": 0},
                            "temperature": {"sensors": [{"name": "CPU Tctl", "type": "CPU_PACKAGE", "current": {"value": 50 + random.random() * 5, "status": "NORMAL"}, "warning": 80, "critical": 95},
                                                        {"name": "Motherboard", "type": "MOTHERBOARD", "current": {"value": 38.0, "status": "NORMAL"}, "warning": None, "critical": None}]},
                            "network": [{"name": "eth0", "operstate": "up", "rxSec": random.random() * 2e6, "txSec": random.random() * 5e5, "receiveErrors": 0, "transmitErrors": 0}]}}
    if "array" in q:
        return {"array": {"state": "STARTED", "capacity": {"kilobytes": {"free": "9000000000", "used": "15000000000", "total": "24000000000"},
                                                           "disks": {"free": "1", "used": "3", "total": "4"}},
                          "parityCheckStatus": {"status": "COMPLETED", "progress": 100, "errors": 0, "running": False, "paused": False, "speed": "180 MB/s",
                                                "date": (now - timedelta(days=20)).isoformat(), "duration": 50000},
                          "parities": [disk(0, "parity", "PARITY", 35)],
                          "disks": [disk(1, "disk1", "DATA", 36), disk(2, "disk2", "DATA", 47), disk(3, "disk3", "DATA", 39, errors=3)],
                          # two pools like a real 7.x server: btrfs "cache" mirror and a zfs "ssd" mirror (first member carries fs size)
                          "caches": [disk(30, "cache", "CACHE", 41, rotational=False, fs="btrfs", size=1_000_000_000),
                                     disk(31, "cache2", "CACHE", 40, rotational=False, fs="btrfs", size=1_000_000_000, fs_size=False),
                                     disk(32, "ssd", "CACHE", 38, rotational=False, fs="zfs", size=2_000_000_000),
                                     disk(33, "ssd2", "CACHE", 37, rotational=False, fs="zfs", size=2_000_000_000, fs_size=False)],
                          "boot": {**disk(40, "flash", "FLASH", None, rotational=False, fs="vfat", size=32_000_000), "device": "sda"}}}
    if "docker" in q:
        def c(cid, name, image, state, auto=True):
            return {"id": "srv1:" + cid, "names": ["/" + name], "image": image, "state": state, "status": "Up 3 days" if state == "RUNNING" else "Exited (1) 2 hours ago",
                    "autoStart": auto, "webUiUrl": f"http://tower:8080/{name}" if state == "RUNNING" else None,
                    "iconUrl": None, "created": int(time.time()) - 86400 * 30,
                    "ports": [{"ip": "0.0.0.0", "privatePort": 80, "publicPort": 8080, "type": "TCP"}] if name == "nginx-proxy" else []}
        return {"docker": {"containers": [c("c1", "plex", "plexinc/pms-docker", "RUNNING"), c("c2", "nginx-proxy", "jc21/nginx-proxy-manager", "RUNNING"),
                                          c("c3", "homeassistant", "ghcr.io/home-assistant/home-assistant", "RUNNING"), c("c4", "nextcloud", "nextcloud", "EXITED")]}}
    if "notifications" in q:
        return {"notifications": {"overview": {"unread": {"info": 1, "warning": 1, "alert": 1, "total": 3}, "archive": {"total": 40}},
                                  "list": [{"id": "n1", "title": "Unraid Status", "subject": "Parity check finished (0 errors)", "description": "Duration 13h", "importance": "INFO",
                                            "timestamp": now.isoformat(), "link": None},
                                           {"id": "n2", "title": "Unraid disk3 SMART health", "subject": "Warning [TOWER] - reported uncorrect is 3", "description": "WDC_WD80 (sdd)",
                                            "importance": "WARNING", "timestamp": now.isoformat(), "link": None},
                                           {"id": "n3", "title": "Fix Common Problems", "subject": "Docker image file is getting full (85%)", "description": "Increase docker.img", "importance": "ALERT",
                                            "timestamp": now.isoformat(), "link": None}]}}
    if "vms" in q:
        return {"vms": {"domains": [{"id": "v1", "name": "Windows 11", "state": "SHUTOFF"}, {"id": "v2", "name": "HAOS", "state": "RUNNING"}]}}
    if "upsDevices" in q:
        return {"upsDevices": [{"id": "ups", "name": "APC", "model": "Back-UPS 900", "status": "Online", "battery": {"chargeLevel": 100, "estimatedRuntime": 2400, "health": "Good"},
                                "power": {"loadPercentage": 22, "currentPower": 118.8, "inputVoltage": 231.0, "outputVoltage": 231.0}}]}
    if "shares" in q:
        return {"shares": [{"name": "media", "free": 9000000000, "used": 12000000000, "size": 0, "comment": "Movies", "cache": False},
                           {"name": "appdata", "free": 400000000, "used": 120000000, "size": 0, "comment": "", "cache": True}]}
    if "disks" in q:
        wake("disks query (smartctl -a on every disk)")
        return {"disks": [{"id": f"p{i}", "device": f"/dev/sd{chr(97 + i)}", "name": "WDC WD80EFZZ", "vendor": "WDC", "size": 8e12, "type": "HD",
                           "interfaceType": "SATA", "smartStatus": "OK", "temperature": 36, "isSpinning": True, "serialNum": f"X{i}",
                           "firmwareRevision": "1"} for i in range(4)] +
                          [{"id": f"n{i}", "device": f"/dev/nvme{i}n1", "name": "Samsung 990", "vendor": "Samsung", "size": 2e12, "type": "SSD",
                            "interfaceType": "PCIE", "smartStatus": "OK", "temperature": 41, "isSpinning": False, "serialNum": f"N{i}",
                            "firmwareRevision": "1"} for i in (30, 31, 32, 33)]}
    raise HTTPException(400, "unknown query")


@app.post("/graphql")
async def graphql(request: Request):
    if request.headers.get("x-api-key") != KEY:
        return {"errors": [{"message": "Unauthorized"}]}
    body = await request.json()
    try:
        return {"data": answer(body["query"], body.get("variables") or {})}
    except HTTPException:
        return {"errors": [{"message": "Cannot query field"}]}


STREAM = {"active": 0, "sessions": 0}


@app.websocket("/graphql")
async def graphql_ws(ws: WebSocket):
    """graphql-ws: dockerContainerStats like the real API (one 'docker stats' line per running container per tick)."""
    await ws.accept(subprotocol="graphql-transport-ws")
    init = await ws.receive_json()
    if init.get("type") != "connection_init" or (init.get("payload") or {}).get("x-api-key") != KEY:
        await ws.close(4403)
        return
    await ws.send_json({"type": "connection_ack"})
    sub = await ws.receive_json()
    if "dockerContainerStats" not in sub["payload"]["query"]:
        await ws.send_json({"id": sub["id"], "type": "error", "payload": [{"message": "Cannot query field \"x\" on type \"Subscription\"."}]})
        return
    STREAM["active"] += 1
    STREAM["sessions"] += 1
    usage = {"c1": (35.5, "1.5GiB / 31.27GiB", 4.8), "c2": (0.4, "120MiB / 31.27GiB", 0.37), "c3": (2.25, "512MiB / 31.27GiB", 1.6)}
    try:
        tick = 0
        while True:
            for cid, (cpu, mem, mp) in usage.items():
                await ws.send_json({"id": sub["id"], "type": "next", "payload": {"data": {"dockerContainerStats": {
                    "id": f"srv1:{cid}", "cpuPercent": 0.0 if tick == 0 else cpu, "memUsage": mem, "memPercent": mp,
                    "netIO": "1.2MB / 300kB", "blockIO": "45MB / 2.1GB"}}}})
            tick += 1
            try:
                msg = await asyncio.wait_for(ws.receive_json(), 0.5)
                if msg.get("type") == "complete":
                    break
            except asyncio.TimeoutError:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        STREAM["active"] -= 1


@app.post("/mock/spindown")
async def spindown():
    STATE["spinning"] = False
    return STATE


@app.get("/mock/stats")
async def mock_stats():
    return {**STATE, "docker_stats_stream": STREAM}


@app.get("/version")
async def version():
    return {"Version": "27.5.1"}


@app.get("/containers/json")
async def containers():
    return [{"Id": "c1", "Names": ["/plex"], "Image": "plexinc/pms-docker", "State": "running", "Status": "Up"},
            {"Id": "c2", "Names": ["/nginx-proxy"], "Image": "jc21/nginx-proxy-manager", "State": "running", "Status": "Up"}]


@app.get("/containers/{cid}/stats")
async def stats(cid: str):
    base = 10**9
    return {"cpu_stats": {"cpu_usage": {"total_usage": base + random.randint(10**7, 10**8)}, "system_cpu_usage": 10**12 + 10**9, "online_cpus": 16},
            "precpu_stats": {"cpu_usage": {"total_usage": base}, "system_cpu_usage": 10**12},
            "memory_stats": {"usage": random.randint(200, 900) * 2**20, "limit": 32 * 2**30, "stats": {"inactive_file": 50 * 2**20}},
            "networks": {"eth0": {"rx_bytes": 123456, "tx_bytes": 654321}}, "pids_stats": {"current": 12}}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18500)
    ap.add_argument("--api", default="4.25.0", help="Unraid API version to report (<= 4.37.5: temperatures wake disks)")
    args = ap.parse_args()
    STATE["api"] = args.api
    uvicorn.run(app, port=args.port, log_level="warning")
