#!/usr/bin/env python3
"""Fake CrowdSec Local API + metrics for local testing of the CrowdSec (Docker) poller and SWAG & CrowdSec › CrowdSec.

    python tools/mock_crowdsec.py --port 18080
    # Settings › SWAG & CrowdSec: Local API URL http://127.0.0.1:18080, machine lookingglass / test-pass,
    #                             bouncer key test-bouncer-key, metrics URL http://127.0.0.1:18080/metrics

Alerts: HTTP probing / crawling / a WordPress scan / an AppSec virtual patch (each with decisions and event meta)
and an SSH brute force. /v1/decisions also lists 2 000 community-blocklist (CAPI) decisions.
POST /mock/alert adds a new http-probing alert from a random address.
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse

app = FastAPI()
MACHINE, PASSWORD, BOUNCER_KEY, TOKEN = "lookingglass", "test-pass", "test-bouncer-key", "jwt-test-token"
ALERTS: list[dict] = []
NEXT = {"alert": 1, "decision": 1}


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}123Z"  # CrowdSec writes nanoseconds


def add_alert(ip: str, cn: str, as_name: str, scenario: str, ago_min: float, meta: list[tuple[str, str]],
              events: int = 10, dtype: str = "ban") -> None:
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=ago_min)
    aid, did = NEXT["alert"], NEXT["decision"]
    NEXT["alert"] += 1
    NEXT["decision"] += 1
    ALERTS.append({
        "id": aid, "uuid": f"alert-{aid}", "machine_id": "crowdsec-docker", "scenario": scenario, "scenario_version": "0.3",
        "scenario_hash": "abc", "message": f"Ip {ip} performed '{scenario}' ({events} events over 2s) at {iso(start)}",
        "events_count": events, "capacity": 5, "leakspeed": "10s", "simulated": False, "remediation": True,
        "start_at": iso(start), "stop_at": iso(start + timedelta(seconds=2)), "created_at": iso(start + timedelta(seconds=3)),
        "source": {"scope": "Ip", "value": ip, "ip": ip, "range": ip.rsplit(".", 1)[0] + ".0/24", "cn": cn,
                   "as_name": as_name, "as_number": str(random.randint(1000, 60000)), "latitude": 0, "longitude": 0},
        "events": [{"timestamp": iso(start), "meta": [{"key": k, "value": v} for k, v in meta]}],
        "meta": [],
        "decisions": [{"id": did, "uuid": f"dec-{did}", "origin": "crowdsec", "type": dtype, "scope": "Ip", "value": ip,
                       "scenario": scenario, "duration": "3h59m", "until": iso(start + timedelta(hours=4)), "simulated": False}],
    })


def build() -> None:
    add_alert("45.148.10.81", "NL", "Techoff Srv Limited", "crowdsecurity/http-probing", 50,
              [("target_fqdn", "cloud.example.com"), ("target_uri", "/.env"), ("http_verb", "GET"), ("http_status", "404"),
               ("http_user_agent", "Mozilla/5.0 zgrab/0.x"), ("log_type", "http_access-log"), ("service", "http")], 12)
    add_alert("185.224.128.17", "RU", "Hostglobal.plus Ltd", "crowdsecurity/http-crawl-non_statics", 30,
              [("target_fqdn", "photos.example.com"), ("target_uri", "/admin"), ("http_status", "403")], 40)
    add_alert("103.152.220.4", "ID", "PT Cloud Hosting", "LePresidente/http-generic-403-bf", 20,
              [("target_fqdn", "blog.example.com"), ("target_uri", "/wp-login.php"), ("http_verb", "POST")], 25)
    add_alert("194.26.29.102", "SC", "Unmanaged Ltd", "crowdsecurity/vpatch-CVE-2023-22515", 10,
              [("target_fqdn", "wiki.example.com"), ("target_uri", "/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false"),
               ("rule_name", "crowdsecurity/vpatch-CVE-2023-22515"), ("appsec_action", "ban"), ("log_type", "appsec-block")], 1)
    add_alert("218.92.0.112", "CN", "CHINANET jiangsu", "crowdsecurity/ssh-bf", 5,
              [("target_user", "root"), ("service", "ssh"), ("log_type", "ssh_failed-auth")], 6)


def auth(authorization: str | None) -> None:
    if authorization != f"Bearer {TOKEN}":
        raise HTTPException(401, "cookie token is empty")


@app.post("/v1/watchers/login")
async def login(request: Request):
    body = await request.json()
    # like CrowdSec: a User-Agent that is not exactly "name/version" fails like a wrong password
    if body.get("machine_id") != MACHINE or body.get("password") != PASSWORD or \
            len(request.headers.get("user-agent", "").split("/")) != 2:
        raise HTTPException(401, "incorrect Username or Password")
    return {"code": 200, "expire": iso(datetime.now(timezone.utc) + timedelta(hours=1)), "token": TOKEN}


@app.get("/v1/alerts")
def alerts(authorization: str | None = Header(None), has_active_decision: str | None = None, limit: int = 100):
    auth(authorization)
    rows = ALERTS
    if has_active_decision == "true":
        rows = [a for a in rows if a["decisions"]]
    return list(reversed(rows))[:limit]


@app.delete("/v1/decisions/{decision_id}")
def delete_decision(decision_id: int, authorization: str | None = Header(None)):
    """Unban (cscli decisions delete --id): machine login only, like CrowdSec."""
    auth(authorization)
    n = 0
    for a in ALERTS:
        keep = [d for d in a["decisions"] if d["id"] != decision_id]
        n += len(a["decisions"]) - len(keep)
        a["decisions"] = keep
    return {"nbDeleted": str(n)}


@app.get("/v1/decisions")
def decisions(x_api_key: str | None = Header(None)):
    if x_api_key != BOUNCER_KEY:
        raise HTTPException(403, "access forbidden")
    own = [d for a in ALERTS for d in a["decisions"]]
    capi = [{"id": 100000 + i, "origin": "CAPI", "type": "ban", "scope": "Ip", "value": f"192.0.{i // 250}.{i % 250 + 1}",
             "scenario": "crowdsecurity/http-probing", "duration": "160h"} for i in range(2000)]
    return own + capi


@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    return "\n".join([
        '# HELP cs_info Information about Crowdsec.',
        'cs_info{version="v1.6.4"} 1',
        'cs_filesource_hits_total{source="/var/log/swag/nginx/access.log",type="file"} 182345',
        'cs_filesource_hits_total{source="/var/log/swag/nginx/error.log",type="file"} 2310',
        'cs_filesource_hits_total{source="/var/log/auth.log",type="file"} 912',
        'cs_parser_hits_ok_total{source="/var/log/swag/nginx/access.log",type="nginx"} 182001',
        'cs_parser_hits_ko_total{source="/var/log/swag/nginx/access.log",type="nginx"} 344',
        'cs_parser_hits_ok_total{source="/var/log/auth.log",type="syslog"} 912',
        'cs_bucket_overflowed_total{name="crowdsecurity/http-probing"} 31',
        'cs_bucket_overflowed_total{name="crowdsecurity/ssh-bf"} 4',
        'cs_appsec_reqs_total{appsec_engine="127.0.0.1:7422",source="127.0.0.1"} 50123',
        'cs_appsec_block_total{appsec_engine="127.0.0.1:7422",source="127.0.0.1"} 17',
        'cs_appsec_rule_hits{appsec_engine="127.0.0.1:7422",rule_name="crowdsecurity/vpatch-CVE-2023-22515",type="inband"} 3',
        'cs_lapi_bouncer_requests_total{bouncer="swag-nginx",route="/v1/decisions/stream",method="GET"} 8640',
        'cs_lapi_bouncer_requests_total{bouncer="lookingglass",route="/v1/decisions",method="GET"} 12',
        'cs_lapi_machine_requests_total{machine="lookingglass",route="/v1/alerts",method="GET"} 30',
        'cs_active_decisions{origin="CAPI",action="ban",reason="crowdsecurity/http-probing"} 2000',
        'cs_active_decisions{origin="crowdsec",action="ban",reason="crowdsecurity/ssh-bf"} 1',
        '',
    ])


@app.get("/health")
def health():
    return {"status": "up"}


@app.post("/mock/alert")
def mock_alert():
    ip = f"203.0.113.{random.randint(1, 254)}"
    add_alert(ip, "US", "Example Hosting", "crowdsecurity/http-probing", 0.5,
              [("target_fqdn", "cloud.example.com"), ("target_uri", "/phpmyadmin/")])
    return {"ok": True, "ip": ip}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18080)
    a = ap.parse_args()
    build()
    uvicorn.run(app, host="0.0.0.0", port=a.port, log_level="warning")
