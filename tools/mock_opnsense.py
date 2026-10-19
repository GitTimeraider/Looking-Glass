#!/usr/bin/env python3
"""Tiny fake OPNsense API for local development / testing of the poller.

    python tools/mock_opnsense.py --port 18443
    OPNSENSE_URL=http://127.0.0.1:18443 OPNSENSE_API_KEY=x OPNSENSE_API_SECRET=y python -m lookingglass.main
"""
from __future__ import annotations

import argparse
import random
import time

import uvicorn
from fastapi import FastAPI, HTTPException, Request

app = FastAPI()
STATE = {"wg_phone": "online"}
START = time.time()


def data() -> dict:
    now = int(time.time())
    up = now - START
    return {
        "diagnostics/system/systemResources": {"memory": {"total": "8000000000", "used": 2_000_000_000 + random.randint(0, 5) * 10**8, "arc": "900000000"}},
        "diagnostics/system/systemInformation": {"name": "fw.home.lan", "versions": ["OPNsense 26.7.4-amd64", "FreeBSD 14.3-RELEASE-p4", "OpenSSL 3.0.17"]},
        "diagnostics/system/systemTime": {"uptime": "3 days, 04:12:09", "datetime": time.ctime(), "boottime": "Wed Oct 15 18:00:00 CEST 2026",
                                          "config": "Sat Oct 18 10:00:00 CEST 2026", "loadavg": f"{random.random():.2f}, 0.25, 0.20"},
        "diagnostics/system/systemDisk": {"devices": [{"device": "zroot/ROOT/default", "type": "zfs", "blocks": "100G", "used": "12G", "available": "88G", "used_pct": 12, "mountpoint": "/"}]},
        "diagnostics/system/systemTemperature": [{"device": f"dev.cpu.{i}.temperature", "temperature": f"{44 + random.random() * 6:.1f}", "type_translated": "CPU"} for i in range(4)],
        "diagnostics/system/systemSwap": {"swap": [{"device": "/dev/ada0p3", "total": "2097152", "used": str(random.randint(0, 200000))}]},
        "diagnostics/firewall/pf_states": {"current": str(1200 + random.randint(0, 300)), "limit": "800000"},
        "diagnostics/cpu_usage/getCPUType": ["Intel(R) N100 (4 cores, 4 threads)"],
        "diagnostics/activity/getActivity": {
            "headers": ["last pid: 12345;  load averages:  0.31,  0.25,  0.20  up 3+04:12:09",
                        "120 processes: 1 running, 119 sleeping",
                        f"CPU:  {random.random() * 10:.1f}% user,  0.0% nice,  {random.random() * 5:.1f}% system,  0.3% interrupt, {85 + random.random() * 5:.1f}% idle",
                        "Mem: 300M Active, 1200M Inact, 2000M Wired, 4000M Free"],
            "details": [{"PID": "1234", "USERNAME": "root", "THR": "1", "PRI": "20", "NICE": "0", "SIZE": "120M", "RES": "80M", "STATE": "select",
                         "C": "1", "TIME": "12:01", "WCPU": "3.20%", "COMMAND": "suricata"},
                        {"PID": "999", "USERNAME": "unbound", "THR": "4", "PRI": "20", "NICE": "0", "SIZE": "60M", "RES": "40M", "STATE": "kqread",
                         "C": "0", "TIME": "5:10", "WCPU": "1.10%", "COMMAND": "unbound"}]},
        "routes/gateway/status": {"items": [{"name": "WAN_DHCP", "address": "1.2.3.4", "status": "none", "status_translated": "Online",
                                             "delay": f"{2 + random.random() * 3:.1f} ms", "loss": "0.0 %", "stddev": "0.2 ms"}]},
        "diagnostics/interface/getInterfaceStatistics": {"statistics": {
            "[WAN] (igb0) / 00:11:22:33:44:55": {"name": "igb0", "received-bytes": str(int(up * 250_000)), "sent-bytes": str(int(up * 60_000)),
                                                 "received-errors": "0", "send-errors": "0", "dropped-packets": "0"},
            "[LAN] (igb1) / 00:11:22:33:44:56": {"name": "igb1", "received-bytes": str(int(up * 70_000)), "sent-bytes": str(int(up * 240_000)),
                                                 "received-errors": "0", "send-errors": "0", "dropped-packets": "2"}}},
        "core/firmware/status": {"status": "update", "status_msg": "There are 3 updates available", "product": {"product_name": "OPNsense", "product_version": "26.7.4"}},
        "diagnostics/firewall/list_rule_ids": {"items": [{"id": "02f4bab031b57d1e30553ce08e0ec131", "descr": "Default deny / state violation rule"}]},
        "diagnostics/interface/getArp": [
            {"mac": "aa:aa:aa:aa:aa:01", "ip": "192.168.1.50", "hostname": "nas", "intf": "igb1", "intf_description": "LAN", "manufacturer": "Synology Incorporated"},
            {"mac": "aa:aa:aa:aa:aa:02", "ip": "192.168.1.10", "hostname": "tower", "intf": "igb1", "intf_description": "LAN", "manufacturer": "ASRock Incorporation"},
            {"mac": "aa:aa:aa:aa:aa:33", "ip": "192.168.1.33", "hostname": "laptop", "intf": "igb1", "intf_description": "LAN", "manufacturer": "Dell Inc."}],
        "diagnostics/firewall/log": [],
        # real format (core: scripts/unbound/stats.py): numeric codes, and client = hostname when Unbound knows one
        "unbound/overview/searchQueries": [{"uuid": "u-block", "time": now, "client": "192.168.1.20", "domain": "malware.example.", "type": "A",
                                            "action": 1, "rcode": 3, "source": 1, "blocklist": "malware", "resolve_time_ms": 0, "ttl": 0,
                                            "dnssec_status": 0, "family": "IPv4"}]
                                          + [{"uuid": f"u-nx-{i}", "time": now - i, "client": "laptop.home.lan", "domain": f"wpad-{i % 7}.home.lan.",
                                              "type": "A", "action": 0, "rcode": 3, "source": 0, "blocklist": None, "resolve_time_ms": 3}
                                             for i in range(200)],
        "unbound/overview/Rolling/1/1": {str(now - 60): {"192.168.1.33": {"count": 200, "hostname": "laptop.home.lan"}}},
        # os-nginx log API
        "nginx/logs/accesses": [{"id": "srv-1", "server_name": "www.example.com"}, {"id": "perm_ban", "server_name": "Auto-ban"}],
        "nginx/logs/accesses/srv-1/-1/1/1000": {"lines": [
            {"remote_ip": "203.0.113.5", "username": "-", "time": "19/Oct/2026:10:00:00 +0200", "status": "404", "size": "153",
             "user_agent": "zgrab/0.x", "request_line": "GET /.env HTTP/1.1", "forwarded_for": "-", "http_referer": "-"},
            {"remote_ip": "198.51.100.20", "username": "-", "time": "19/Oct/2026:10:00:05 +0200", "status": "200", "size": "5120",
             "user_agent": "Mozilla/5.0", "request_line": "GET / HTTP/2.0", "forwarded_for": "-", "http_referer": "-"}],
            "pages": 1, "total": 2, "found": 2, "returned": 2, "query": ""},
        "nginx/logs/errors": [{"id": "global", "server_name": "global"}],
        "nginx/logs/errors/global/-1/1/1000": {"lines": [{"date": "2026/10/19", "time": "10:00:01", "severity": "error", "number": "12#0",
            "message": "*5 limiting requests, excess: 10.5 by zone \"one\", client: 198.51.100.7, server: www.example.com, request: \"GET / HTTP/1.1\""}],
            "pages": 1},
        "nginx/logs/streamaccesses": [],
        # VPN status (core: Wireguard ServiceController::show, OpenVPN search_sessions, IPsec search_phase1)
        "wireguard/service/show": {"rows": [
            {"if": "wg0", "type": "interface", "public-key": "srvkey", "listen-port": "51820", "status": "up", "name": "home", "ifname": "home",
             "peer-status": "offline"},
            {"if": "wg0", "type": "peer", "public-key": "phonekey", "endpoint": "198.51.100.30:40000", "allowed-ips": "10.10.0.2/32",
             "latest-handshake": now - 30, "transfer-rx": 1048576, "transfer-tx": 524288, "persistent-keepalive": "off",
             "name": "phone", "latest-handshake-age": 30, "peer-status": STATE["wg_phone"], "ifname": "home"},
            {"if": "wg0", "type": "peer", "public-key": "laptopkey", "endpoint": "(none)", "allowed-ips": "10.10.0.3/32",
             "latest-handshake": 0, "transfer-rx": 0, "transfer-tx": 0, "name": "laptop", "latest-handshake-age": None,
             "peer-status": "offline", "ifname": "home"}]},
        "unbound/overview/totals/25": {"total": 10, "blocked": 1},
        "q_feeds/settings/stats": {"feeds": 3},
    }


SEARCH = {
    "core/service/search": [{"name": "unbound", "description": "Unbound DNS", "running": 1}, {"name": "suricata", "description": "Intrusion Detection", "running": 1}],
    "crowdsec/alerts/search": [{"id": 7, "created_at": "2026-10-18T22:00:00Z", "scenario": "crowdsecurity/http-probing", "source": {"ip": "45.9.9.9", "cn": "NL"}, "events_count": 12, "decisions": "ban"}],
    # OPNsense format: scope_value / action / source (origin)
    "crowdsec/decisions/search": [{"id": 99, "source": "crowdsec", "scope_value": "45.9.9.9", "reason": "crowdsecurity/http-probing",
                                   "action": "ban", "country": "NL", "as": "AS1234", "events_count": 12, "expiration": "3h", "alert_id": 7}],
    "openvpn/service/search_sessions": [
        {"type": "server", "id": "1_198.51.100.40:1194", "description": "Road warrior", "is_client": True, "common_name": "bob",
         "real_address": "198.51.100.40:51234", "virtual_address": "10.8.0.6", "bytes_received": "204800", "bytes_sent": "409600",
         "connected_since": "2026-10-19 09:00:00", "connected_since__time_t_": "1792400000", "username": "bob"},
        {"id": "2", "service_id": "openvpn/2", "type": "server", "description": "Disabled site"}],
    "ipsec/sessions/search_phase1": [{"name": "con1", "phase1desc": "Office", "remote-addrs": "198.51.100.7", "local-addrs": "192.0.2.1",
                                      "connected": True, "bytes-in": 1000, "bytes-out": 2000}],
    "q_feeds/settings/search_events": [{"timestamp": "2026-10-18T22:01:00+00:00", "interface": "LAN", "direction": "out", "source": "192.168.1.44",
                                        "destination": "91.92.1.1", "source_port": "50000", "destination_port": "443"}],
    "ids/service/queryAlerts": [{"timestamp": "2026-10-18T22:02:00.000000+0000", "flow_id": 5, "src_ip": "192.168.1.44", "src_port": 50000, "dest_ip": "91.92.1.1",
                                 "dest_port": 443, "proto": "TCP", "alert": "ET MALWARE Possible C2", "alert_sid": 2030000, "alert_action": "allowed"}],
    "kea/leases4/search": [
        {"address": "192.168.1.50", "hwaddr": "aa:aa:aa:aa:aa:01", "hostname": "nas", "expire": "2026-10-19 10:00", "if_descr": "LAN", "mac_info": "Synology Incorporated", "lease_type": "static"},
        {"address": "192.168.1.77", "hwaddr": "aa:aa:aa:aa:aa:77", "hostname": "unknown-phone", "expire": "2026-10-19 09:00", "if_descr": "GUEST", "mac_info": "Apple, Inc.", "lease_type": "dynamic"}],
}


@app.post("/mock/wg/{status}")
async def wg(status: str):
    STATE["wg_phone"] = status
    return STATE


@app.api_route("/api/{path:path}", methods=["GET", "POST"])
async def handler(path: str, request: Request):
    if not request.headers.get("authorization", "").startswith("Basic "):
        raise HTTPException(401)
    d = data()
    if path in d:
        return d[path]
    if path in SEARCH:
        return {"rows": SEARCH[path], "total": len(SEARCH[path])}
    raise HTTPException(404, "not found")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18443)
    uvicorn.run(app, port=ap.parse_args().port, log_level="warning")
