"""Aggregated statistics used by dashboards, reports and the AI analyst."""
from __future__ import annotations

import asyncio
from typing import Any

from . import db

# name -> (sql, description). $1 = window in seconds
QUERIES: dict[str, str] = {
    "totals_by_source": "SELECT source, count(*) n FROM events WHERE ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC",
    "firewall_actions": "SELECT action, count(*) n FROM events WHERE source = 'firewall' AND ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC",
    "top_blocked_sources": "SELECT host(src_ip) ip, src_country country, count(*) n, count(DISTINCT dst_port) ports FROM events "
                           "WHERE source = 'firewall' AND action = 'block' AND ts > now() - make_interval(secs => $1) AND src_ip IS NOT NULL "
                           "GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15",
    "top_blocked_ports": "SELECT dst_port port, proto, count(*) n, count(DISTINCT src_ip) sources FROM events WHERE source = 'firewall' "
                         "AND action = 'block' AND ts > now() - make_interval(secs => $1) AND dst_port IS NOT NULL "
                         "GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15",
    "top_blocked_countries": "SELECT src_country country, count(*) n, count(DISTINCT src_ip) ips FROM events WHERE action = 'block' "
                             "AND src_country IS NOT NULL AND ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC LIMIT 15",
    "top_passed_inbound": "SELECT host(dst_ip) dst, dst_port port, proto, count(*) n, count(DISTINCT src_ip) sources FROM events "
                          "WHERE source = 'firewall' AND action = 'pass' AND direction = 'in' AND ts > now() - make_interval(secs => $1) "
                          "AND NOT (src_ip << '10.0.0.0/8' OR src_ip << '172.16.0.0/12' OR src_ip << '192.168.0.0/16' OR src_ip << 'fc00::/7' "
                          "OR src_ip << 'fe80::/10' OR src_ip << '127.0.0.0/8') GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT 15",
    "top_talkers_internal": "SELECT host(src_ip) ip, count(*) n, count(DISTINCT dst_ip) peers FROM events WHERE source IN ('firewall', 'zenarmor') "
                            "AND ts > now() - make_interval(secs => $1) AND (src_ip << '10.0.0.0/8' OR src_ip << '172.16.0.0/12' "
                            "OR src_ip << '192.168.0.0/16') GROUP BY 1 ORDER BY 2 DESC LIMIT 15",
    "dns_top_domains": "SELECT domain, count(*) n, count(DISTINCT src_ip) clients FROM events WHERE source = 'unbound' AND ts > now() - make_interval(secs => $1) "
                       "AND domain IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 15",
    "dns_blocked": "SELECT domain, coalesce(data->>'blocklist', '') blocklist, count(*) n FROM events WHERE source = 'unbound' AND action IN ('block', 'drop') "
                   "AND ts > now() - make_interval(secs => $1) GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15",
    "dns_clients": "SELECT host(src_ip) client, count(*) n, count(*) FILTER (WHERE action IN ('block', 'drop')) blocked FROM events "
                   "WHERE source = 'unbound' AND ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC LIMIT 15",
    "web_status": "SELECT action status, count(*) n FROM events WHERE source = 'nginx' AND ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC LIMIT 15",
    "web_top_clients": "SELECT host(src_ip) ip, src_country country, count(*) n, count(*) FILTER (WHERE action ~ '^http_[45]') errors FROM events "
                       "WHERE source = 'nginx' AND ts > now() - make_interval(secs => $1) GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15",
    "web_attack_tags": "SELECT tag, count(*) n, count(DISTINCT src_ip) ips FROM (SELECT src_ip, jsonb_array_elements_text(data->'tags') tag FROM events "
                       "WHERE source = 'nginx' AND ts > now() - make_interval(secs => $1) AND jsonb_typeof(data->'tags') = 'array') t GROUP BY 1 ORDER BY 2 DESC",
    "auth_failures": "SELECT host(src_ip) ip, source, count(*) n, array_agg(DISTINCT username) FILTER (WHERE username IS NOT NULL) users FROM events "
                     "WHERE action = 'login_failed' AND ts > now() - make_interval(secs => $1) GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15",
    "auth_success": "SELECT host(src_ip) ip, username, program, count(*) n, max(ts) last FROM events WHERE action = 'login_success' "
                    "AND ts > now() - make_interval(secs => $1) GROUP BY 1, 2, 3 ORDER BY 5 DESC LIMIT 15",
    "ids_signatures": "SELECT message signature, max(data->>'classification') classification, count(*) n, count(DISTINCT src_ip) sources FROM events "
                      "WHERE source = 'suricata' AND ts > now() - make_interval(secs => $1) AND action IS NOT NULL GROUP BY 1 ORDER BY 3 DESC LIMIT 15",
    "crowdsec_scenarios": "SELECT coalesce(data->>'scenario', data->>'reason') scenario, count(*) n, count(DISTINCT src_ip) ips FROM events "
                          "WHERE source = 'crowdsec' AND ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC LIMIT 15",
    "zenarmor_top": "SELECT coalesce(data->>'app_name', data->>'app_category', action) app, action, count(*) n FROM events "
                    "WHERE source = 'zenarmor' AND ts > now() - make_interval(secs => $1) GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15",
    "qfeeds_hits": "SELECT host(src_ip) src, host(dst_ip) dst, direction, count(*) n FROM events WHERE source = 'qfeeds' "
                   "AND ts > now() - make_interval(secs => $1) GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT 15",
    "alerts_by_severity": "SELECT severity, count(*) n FROM alerts WHERE last_seen > now() - make_interval(secs => $1) GROUP BY 1 "
                          "ORDER BY array_position(ARRAY['critical','high','medium','low','info'], severity)",
    "alerts": "SELECT id, severity, rule, title, host(src_ip) src, count, status, last_seen FROM alerts WHERE last_seen > now() - make_interval(secs => $1) "
              "ORDER BY array_position(ARRAY['critical','high','medium','low','info'], severity), last_seen DESC LIMIT 50",
    "new_devices": "SELECT mac, host(ip) ip, hostname, conn_where, first_seen FROM devices WHERE first_seen > now() - make_interval(secs => $1) "
                   "ORDER BY first_seen DESC LIMIT 25",
    "unifi_events": "SELECT action, count(*) n, count(DISTINCT data->>'mac') clients FROM events WHERE source = 'unifi' "
                    "AND ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC",
    # UniFi location + OPNsense findings: which device, where it is connected and what it did
    "clients_with_security_events": "WITH ev AS (SELECT src_ip, count(*) FILTER (WHERE source = 'firewall' AND action = 'block') fw, "
        "count(*) FILTER (WHERE source = 'unbound' AND action IN ('block', 'drop')) dns, "
        "count(*) FILTER (WHERE source IN ('suricata', 'crowdsec', 'qfeeds') OR (source = 'zenarmor' AND action = 'block')) threats "
        "FROM events WHERE ts > now() - make_interval(secs => $1) AND src_ip IS NOT NULL "
        "AND source IN ('firewall', 'unbound', 'suricata', 'crowdsec', 'qfeeds', 'zenarmor') GROUP BY 1) "
        "SELECT coalesce(d.hostname, d.mac) name, host(d.ip) ip, d.conn_where, ev.fw, ev.dns, ev.threats FROM devices d "
        "JOIN ev ON ev.src_ip = d.ip WHERE d.conn_where IS NOT NULL ORDER BY 6 DESC, 4 + 5 DESC LIMIT 15",
}


async def build_report(hours: float = 24) -> dict[str, Any]:
    secs = float(hours) * 3600

    async def run(name: str, sql: str) -> tuple[str, list[dict[str, Any]]]:
        async with db.pool().acquire() as conn:
            return name, db.records(await conn.fetch(sql, secs))

    results = await asyncio.gather(*(run(n, q) for n, q in QUERIES.items()))
    report: dict[str, Any] = {"hours": hours, **dict(results)}
    report["totals"] = {r["source"]: r["n"] for r in report["totals_by_source"]}
    return report


async def timeline(hours: float = 24, buckets: int = 48) -> dict[str, Any]:
    secs = float(hours) * 3600
    step = max(60, int(secs / buckets))
    rows = await db.pool().fetch(
        "SELECT to_timestamp(floor(extract(epoch FROM ts) / $2) * $2) AS bucket, source, count(*) n FROM events "
        "WHERE ts > now() - make_interval(secs => $1) GROUP BY 1, 2 ORDER BY 1", secs, step)
    blocked = await db.pool().fetch(
        "SELECT to_timestamp(floor(extract(epoch FROM ts) / $2) * $2) AS bucket, count(*) n FROM events "
        "WHERE ts > now() - make_interval(secs => $1) AND action IN ('block', 'drop', 'ban') GROUP BY 1 ORDER BY 1", secs, step)
    return {"step": step, "series": db.records(rows), "blocked": db.records(blocked)}
