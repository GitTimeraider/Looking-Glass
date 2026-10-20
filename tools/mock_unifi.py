#!/usr/bin/env python3
"""Fake UniFi Network controller for local testing of the UniFi poller.

    python tools/mock_unifi.py --port 18600                      # UniFi OS console, Network 10.x (API key test-key, admin/admin-pass)
    python tools/mock_unifi.py --port 18600 --version 11.0.89    # Network 11: no stat/event, system-log instead
    python tools/mock_unifi.py --port 18600 --selfhosted         # self-hosted app: /api/login, no API key, no integration API
    python tools/mock_unifi.py --port 18600 --no-legacy-key      # API key works on the integration API only

POST /mock/offline/<name> takes a device offline, /mock/online/<name> brings it back.
Field names follow the controller OpenAPI specs (integration v1) and aiounifi / unpoller (classic API).
"""
from __future__ import annotations

import argparse
import time

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response

app = FastAPI()
KEY, USER, PASSWORD = "test-key", "admin", "admin-pass"
CFG = {"selfhosted": False, "version": "10.3.58", "legacy_key": True}
STATE = {"offline": set(), "logins": 0}
SITE_ID = "88f7af54-98f8-306a-a1c7-c9349722b1f6"

DEVICES = [
    {"_id": "d1", "mac": "f4:e2:c6:00:00:01", "name": "Living room", "model": "U7PRO", "type": "uap", "ip": "192.168.1.21",
     "version": "8.0.24.15000", "upgradable": False, "uptime": 864000, "adopted": True, "num_sta": 3, "satisfaction": 96,
     "system-stats": {"cpu": "7.5", "mem": "41.2"}, "general_temperature": 52,
     "uplink": {"type": "wire", "uplink_mac": "f4:e2:c6:00:00:10", "uplink_remote_port": 1, "tx_bytes-r": 120000, "rx_bytes-r": 950000},
     "radio_table_stats": [{"radio": "ng", "channel": 6, "num_sta": 1, "cu_total": 34, "satisfaction": 92, "tx_power": 17},
                           {"radio": "na", "channel": 44, "num_sta": 2, "cu_total": 12, "satisfaction": 98, "tx_power": 20}],
     "vap_table": [{"essid": "Home", "num_sta": 2}, {"essid": "IoT", "num_sta": 1}]},
    {"_id": "d2", "mac": "f4:e2:c6:00:00:02", "name": "Attic", "model": "U6LR", "type": "uap", "ip": "192.168.1.22",
     "version": "6.7.31", "upgradable": True, "uptime": 120000, "adopted": True, "num_sta": 1, "satisfaction": 71,
     "system-stats": {"cpu": "3.1", "mem": "55.0"},
     "uplink": {"type": "wire", "uplink_mac": "f4:e2:c6:00:00:10", "uplink_remote_port": 2, "tx_bytes-r": 5000, "rx_bytes-r": 20000},
     "radio_table_stats": [{"radio": "na", "channel": 149, "num_sta": 1, "cu_total": 8, "satisfaction": 71, "tx_power": 23}],
     "vap_table": [{"essid": "Home", "num_sta": 1}]},
    {"_id": "d3", "mac": "f4:e2:c6:00:00:10", "name": "Office switch", "model": "USL16LP", "type": "usw", "ip": "192.168.1.20",
     "version": "7.1.26", "upgradable": False, "uptime": 2592000, "adopted": True, "num_sta": 2,
     "system-stats": {"cpu": "12.0", "mem": "38.0"}, "general_temperature": 45,
     "uplink": {"type": "wire", "uplink_mac": "", "tx_bytes-r": 1500000, "rx_bytes-r": 900000},
     "port_table": [
         {"port_idx": 1, "name": "Living room AP", "up": True, "enable": True, "speed": 2500, "is_uplink": False, "poe_enable": True, "poe_power": "12.40", "rx_bytes": 9e9, "tx_bytes": 2e10, "rx_errors": 0, "tx_errors": 0, "rx_dropped": 0, "tx_dropped": 0},
         {"port_idx": 2, "name": "Attic AP", "up": True, "enable": True, "speed": 1000, "poe_enable": True, "poe_power": "8.10", "rx_bytes": 1e9, "tx_bytes": 3e9, "rx_errors": 4, "tx_errors": 0, "rx_dropped": 2, "tx_dropped": 0},
         {"port_idx": 3, "name": "NAS", "up": True, "enable": True, "speed": 1000, "rx_bytes": 5e10, "tx_bytes": 8e10, "rx_errors": 0, "tx_errors": 0},
         {"port_idx": 4, "name": "Port 4", "up": False, "enable": True, "speed": 0},
         {"port_idx": 16, "name": "OPNsense", "up": True, "enable": True, "speed": 1000, "is_uplink": True, "rx_bytes": 2e11, "tx_bytes": 1e11}]},
]
CLIENTS = [
    {"mac": "aa:aa:aa:aa:aa:33", "ip": "192.168.1.33", "name": "Office laptop", "hostname": "laptop", "oui": "Dell Inc.",
     "is_wired": False, "essid": "Home", "ap_mac": "f4:e2:c6:00:00:01", "radio": "na", "channel": 44, "signal": -54,
     "satisfaction": 98, "tx_bytes": 3.2e9, "rx_bytes": 2.1e10, "uptime": 36000, "network": "LAN", "vlan": 0},
    {"mac": "aa:aa:aa:aa:aa:63", "ip": "192.168.1.63", "hostname": "pixel-7", "oui": "Google, Inc.", "is_wired": False,
     "essid": "Home", "ap_mac": "f4:e2:c6:00:00:02", "radio": "na", "channel": 149, "signal": -78, "satisfaction": 64,
     "tx_bytes": 2e8, "rx_bytes": 1.5e9, "uptime": 7200, "network": "LAN"},
    {"mac": "aa:aa:aa:aa:aa:62", "ip": "192.168.1.62", "hostname": "*", "oui": "Tuya Smart Inc.", "is_wired": False,
     "essid": "IoT", "ap_mac": "f4:e2:c6:00:00:01", "radio": "ng", "channel": 6, "signal": -67, "satisfaction": 88,
     "tx_bytes": 4e6, "rx_bytes": 9e6, "uptime": 86400, "network": "IoT", "vlan": 30},
    {"mac": "aa:aa:aa:aa:aa:01", "ip": "192.168.1.50", "name": "NAS", "hostname": "nas", "oui": "Synology Incorporated",
     "is_wired": True, "sw_mac": "f4:e2:c6:00:00:10", "sw_port": 3, "wired-tx_bytes": 8e10, "wired-rx_bytes": 5e10,
     "uptime": 2592000, "network": "LAN"},
    {"mac": "aa:aa:aa:aa:aa:44", "ip": "192.168.1.44", "hostname": "unknown-pc", "oui": "Intel Corporate", "is_wired": True,
     "sw_mac": "f4:e2:c6:00:00:10", "sw_port": 4, "uptime": 600, "network": "LAN"},
]
ROGUE = [
    {"bssid": "3c:84:6a:11:22:33", "essid": "Neighbour-5G", "channel": 36, "band": "na", "signal": -84, "security": "wpa2",
     "oui": "TP-LINK", "ap_mac": "f4:e2:c6:00:00:02", "is_rogue": False, "is_ubnt": False, "last_seen": int(time.time())},
    {"bssid": "de:ad:be:ef:00:01", "essid": "Home", "channel": 6, "band": "ng", "signal": -61, "security": "open",
     "oui": "", "ap_mac": "f4:e2:c6:00:00:01", "is_rogue": True, "is_ubnt": False, "last_seen": int(time.time())},
]


def now_ms() -> int:
    return int(time.time() * 1000)


def events() -> list[dict]:
    t = now_ms()
    return [
        {"_id": "e1", "key": "EVT_WU_Connected", "user": "aa:aa:aa:aa:aa:63", "ssid": "Home", "ap": "f4:e2:c6:00:00:02",
         "time": t - 60000, "subsystem": "wlan", "msg": "User[aa:aa:aa:aa:aa:63] has connected to AP[f4:e2:c6:00:00:02] with SSID \"Home\""},
        {"_id": "e2", "key": "EVT_WU_Roam", "user": "aa:aa:aa:aa:aa:33", "ap_from": "f4:e2:c6:00:00:02", "ap_to": "f4:e2:c6:00:00:01",
         "time": t - 50000, "subsystem": "wlan", "msg": "User[aa:aa:aa:aa:aa:33] roams from AP[f4:e2:c6:00:00:02] to AP[f4:e2:c6:00:00:01]"},
        {"_id": "e3", "key": "EVT_AP_DetectRogueAP", "ap": "f4:e2:c6:00:00:01", "time": t - 40000, "subsystem": "wlan",
         "msg": "AP[f4:e2:c6:00:00:01] detected rogue AP de:ad:be:ef:00:01 on channel 6"},
        {"_id": "e4", "key": "EVT_SW_DetectRogueDHCP", "sw": "f4:e2:c6:00:00:10", "port": 4, "time": t - 30000, "subsystem": "lan",
         "msg": "Switch[f4:e2:c6:00:00:10] detected rogue DHCP server on port 4"},
        {"_id": "e5", "key": "EVT_LU_Connected", "user": "aa:aa:aa:aa:aa:44", "sw": "f4:e2:c6:00:00:10", "port": 4,
         "time": t - 20000, "subsystem": "lan", "msg": "User[aa:aa:aa:aa:aa:44] has connected to Switch port 4"},
    ]


def system_log() -> list[dict]:
    t = now_ms()
    return [
        {"id": "s1", "key": "CLIENT_CONNECTED_WIRELESS", "category": "CLIENT_DEVICES", "subcategory": "WIFI", "severity": "INFO",
         "title_raw": "WiFi Client Connected", "message_raw": "{client} connected to {wlan} on {device}", "timestamp": t - 60000,
         "parameters": {"client": {"id": "aa:aa:aa:aa:aa:63", "name": "pixel-7", "type": "CLIENT", "ip": "192.168.1.63"},
                        "wlan": {"name": "Home"}, "device": {"name": "Attic"}}},
        {"id": "s2", "key": "DEVICE_OFFLINE", "category": "DEVICES", "subcategory": "WIFI", "severity": "HIGH",
         "title_raw": "Device Offline", "message_raw": "{device} is offline", "timestamp": t - 30000,
         "parameters": {"device": {"name": "Attic", "type": "DEVICE"}}},
    ]


def dev(d: dict) -> dict:
    off = d["name"] in STATE["offline"]
    return {**d, "state": 0 if off else 1, "num_sta": 0 if off else d.get("num_sta")}


def authed(request: Request, legacy: bool) -> None:
    if request.headers.get("x-api-key") == KEY and not CFG["selfhosted"] and (CFG["legacy_key"] or not legacy):
        return
    cookie = request.cookies.get("unifises" if CFG["selfhosted"] else "TOKEN")
    if legacy and cookie == "ok":
        return
    raise HTTPException(401, "api.err.LoginRequired")


@app.get("/")
async def root():
    if CFG["selfhosted"]:
        return Response(status_code=302, headers={"location": "/manage"})
    return {"unifi_os": True}


@app.post("/api/auth/login")
async def os_login(request: Request):
    if CFG["selfhosted"]:
        # a self-hosted controller treats this as just another protected /api path
        return Response('{"meta":{"rc":"error","msg":"api.err.LoginRequired"},"data":[]}', 401, media_type="application/json")
    body = await request.json()
    if (body.get("username"), body.get("password")) != (USER, PASSWORD):
        raise HTTPException(401, "AUTHENTICATION_FAILED")
    STATE["logins"] += 1
    r = Response('{"username": "admin"}', media_type="application/json", headers={"x-csrf-token": "csrf-1"})
    r.set_cookie("TOKEN", "ok")
    return r


@app.post("/api/login")
async def classic_login(request: Request):
    if not CFG["selfhosted"]:
        raise HTTPException(404)
    body = await request.json()
    if (body.get("username"), body.get("password")) != (USER, PASSWORD):
        return Response('{"meta":{"rc":"error","msg":"api.err.Invalid"},"data":[]}', 400, media_type="application/json")
    STATE["logins"] += 1
    r = Response('{"meta":{"rc":"ok"},"data":[]}', media_type="application/json")
    r.set_cookie("unifises", "ok")
    r.set_cookie("csrf_token", "csrf-selfhosted")
    return r


# ----------------------------------------------------------- integration v1 ---
@app.get("/proxy/network/integration/v1/{path:path}")
async def v1(path: str, request: Request):
    if CFG["selfhosted"] or request.headers.get("x-api-key") != KEY:
        raise HTTPException(401, "UNAUTHORIZED")
    if path == "info":
        return {"applicationVersion": CFG["version"]}
    if path == "sites":
        return {"offset": 0, "limit": 25, "count": 1, "totalCount": 1, "data": [{"id": SITE_ID, "internalReference": "default", "name": "Default"}]}
    parts = path.split("/")
    if parts[:2] == ["sites", SITE_ID]:
        if parts[2:] == ["devices"]:
            data = [{"id": d["_id"], "macAddress": d["mac"], "ipAddress": d["ip"], "name": d["name"], "model": d["model"],
                     "state": "OFFLINE" if d["name"] in STATE["offline"] else "ONLINE", "supported": True,
                     "firmwareVersion": d["version"], "firmwareUpdatable": d["upgradable"],
                     "features": ["accessPoint"] if d["type"] == "uap" else ["switching"],
                     "interfaces": ["radios"] if d["type"] == "uap" else ["ports"]} for d in DEVICES]
            return {"offset": 0, "limit": 200, "count": len(data), "totalCount": len(data), "data": data}
        if len(parts) == 6 and parts[2] == "devices" and parts[4:] == ["statistics", "latest"]:
            d = next(x for x in DEVICES if x["_id"] == parts[3])
            return {"uptimeSec": d["uptime"], "cpuUtilizationPct": float(d["system-stats"]["cpu"]),
                    "memoryUtilizationPct": float(d["system-stats"]["mem"]),
                    "uplink": {"txRateBps": d["uplink"]["tx_bytes-r"] * 8, "rxRateBps": d["uplink"]["rx_bytes-r"] * 8}}
        if parts[2:] == ["clients"]:
            ids = {d["mac"]: d["_id"] for d in DEVICES}
            data = [{"type": "WIRED" if c["is_wired"] else "WIRELESS", "id": c["mac"], "name": c.get("name") or c.get("hostname"),
                     "connectedAt": "2026-10-19T08:00:00Z", "ipAddress": c["ip"], "macAddress": c["mac"],
                     "uplinkDeviceId": ids.get(c.get("ap_mac") or c.get("sw_mac")), "access": {"type": "DEFAULT"}} for c in CLIENTS]
            return {"offset": 0, "limit": 200, "count": len(data), "totalCount": len(data), "data": data}
    raise HTTPException(404, "api.resource-not-found")


# ----------------------------------------------------------- classic API ---
async def classic(path: str, request: Request):
    authed(request, legacy=True)
    if CFG["selfhosted"] and request.method == "POST" and request.headers.get("x-csrf-token") != "csrf-selfhosted":
        return Response('{"meta":{"rc":"error","msg":"api.err.InvalidCSRFToken"},"data":[]}', 403, media_type="application/json")
    ok = lambda data: {"meta": {"rc": "ok"}, "data": data}  # noqa: E731
    if path == "stat/sysinfo":
        return ok([{"version": CFG["version"], "hostname": "unifi", "timezone": "Europe/Amsterdam", "update_available": False}])
    if path == "stat/device":
        return ok([dev(d) for d in DEVICES])
    if path == "stat/sta":
        off = {d["mac"] for d in DEVICES if d["name"] in STATE["offline"]}
        return ok([c for c in CLIENTS if c.get("ap_mac") not in off])
    if path == "stat/health":
        return ok([{"subsystem": "wlan", "status": "ok", "num_ap": 2, "num_adopted": 2, "num_disconnected": len(STATE["offline"]),
                    "num_user": 3, "num_guest": 0, "tx_bytes-r": 125000, "rx_bytes-r": 970000},
                   {"subsystem": "lan", "status": "ok", "num_sw": 1, "num_adopted": 1, "num_user": 2, "num_guest": 0},
                   {"subsystem": "wan", "status": "unknown"}, {"subsystem": "www", "status": "unknown"},
                   {"subsystem": "vpn", "status": "unknown"}])
    if path == "stat/rogueap":
        return ok(ROGUE)
    if path == "stat/event":
        if CFG["version"].startswith("11"):
            raise HTTPException(404)
        return ok(events())
    raise HTTPException(404)


@app.api_route("/proxy/network/api/s/default/{path:path}", methods=["GET", "POST"])
async def os_classic(path: str, request: Request):
    if CFG["selfhosted"]:
        raise HTTPException(404)
    return await classic(path, request)


@app.api_route("/api/s/default/{path:path}", methods=["GET", "POST"])
async def self_classic(path: str, request: Request):
    if not CFG["selfhosted"]:
        raise HTTPException(404)
    return await classic(path, request)


@app.post("/proxy/network/v2/api/site/default/system-log/all")
async def system_log_all(request: Request):
    authed(request, legacy=True)
    if not CFG["version"].startswith("11"):
        raise HTTPException(404)
    data = system_log()
    return {"data": data, "page_number": 0, "total_element_count": len(data), "total_page_count": 1}


@app.post("/mock/offline/{name}")
async def offline(name: str):
    STATE["offline"].add(name)
    return {"offline": sorted(STATE["offline"])}


@app.post("/mock/online/{name}")
async def online(name: str):
    STATE["offline"].discard(name)
    return {"offline": sorted(STATE["offline"])}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18600)
    ap.add_argument("--version", default="10.3.58")
    ap.add_argument("--selfhosted", action="store_true")
    ap.add_argument("--no-legacy-key", action="store_true", help="API key only accepted by the integration API")
    a = ap.parse_args()
    CFG.update(version=a.version, selfhosted=a.selfhosted, legacy_key=not a.no_legacy_key)
    uvicorn.run(app, port=a.port, log_level="warning")
