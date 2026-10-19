#!/usr/bin/env python3
"""Tiny fake OPNsense API for local development / testing of the poller.

    python tools/mock_opnsense.py --port 18443
    OPNSENSE_URL=http://127.0.0.1:18443 OPNSENSE_API_KEY=x OPNSENSE_API_SECRET=y python -m monraider.main
"""
from __future__ import annotations

import argparse
import random
import time

import uvicorn
from fastapi import FastAPI, HTTPException, Request

app = FastAPI()
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
            {"mac": "aa:aa:aa:aa:aa:02", "ip": "192.168.1.10", "hostname": "tower", "intf": "igb1", "intf_description": "LAN", "manufacturer": "ASRock Incorporation"}],
        "diagnostics/firewall/log": [],
        "unbound/overview/searchQueries": [{"time": now, "client": "192.168.1.20", "domain": "malware.example.", "type": "A", "action": "Block",
                                            "rcode": "NXDOMAIN", "source": "Local", "blocklist": "malware"}],
        "unbound/overview/totals/25": {"total": 10, "blocked": 1},
        "q_feeds/settings/stats": {"feeds": 3},
    }


SEARCH = {
    "core/service/search": [{"name": "unbound", "description": "Unbound DNS", "running": 1}, {"name": "suricata", "description": "Intrusion Detection", "running": 1}],
    "crowdsec/alerts/search": [{"id": 7, "created_at": "2026-10-18T22:00:00Z", "scenario": "crowdsecurity/http-probing", "source": {"ip": "45.9.9.9", "cn": "NL"}, "events_count": 12, "decisions": "ban"}],
    "crowdsec/decisions/search": [{"id": 99, "type": "ban", "scope": "Ip", "value": "45.9.9.9", "reason": "crowdsecurity/http-probing", "origin": "crowdsec", "expiration": "3h"}],
    "q_feeds/settings/search_events": [{"timestamp": "2026-10-18T22:01:00+00:00", "interface": "LAN", "direction": "out", "source": "192.168.1.44",
                                        "destination": "91.92.1.1", "source_port": "50000", "destination_port": "443"}],
    "ids/service/queryAlerts": [{"timestamp": "2026-10-18T22:02:00.000000+0000", "flow_id": 5, "src_ip": "192.168.1.44", "src_port": 50000, "dest_ip": "91.92.1.1",
                                 "dest_port": 443, "proto": "TCP", "alert": "ET MALWARE Possible C2", "alert_sid": 2030000, "alert_action": "allowed"}],
    "kea/leases4/search": [
        {"address": "192.168.1.50", "hwaddr": "aa:aa:aa:aa:aa:01", "hostname": "nas", "expire": "2026-10-19 10:00", "if_descr": "LAN", "mac_info": "Synology Incorporated", "lease_type": "static"},
        {"address": "192.168.1.77", "hwaddr": "aa:aa:aa:aa:aa:77", "hostname": "unknown-phone", "expire": "2026-10-19 09:00", "if_descr": "GUEST", "mac_info": "Apple, Inc.", "lease_type": "dynamic"}],
}


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
