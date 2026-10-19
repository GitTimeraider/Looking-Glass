"""Declarative per-function dashboards.

Every panel is one SQL query. Parameters: $1 = window in seconds, $2 = bucket size in seconds (timeseries).
Panel types (rendered by templates/dash.html):
  stat        -> one row; every column becomes a tile
  timeseries  -> rows (t, series, v): stacked bars / lines over time
  bar / hbar  -> rows (label, v)
  pie         -> rows (label, v)
  table       -> any rows; ``cols`` describes formatting (ip, flag, ago, time, num, sev, src, bytes)
  log         -> raw recent events (table with the standard event columns)
"""
from __future__ import annotations

import asyncio
from typing import Any

from . import db

W = "ts > now() - make_interval(secs => $1)"
B = "to_timestamp(floor(extract(epoch FROM ts) / $2) * $2)"
PRIV = ("(src_ip << '10.0.0.0/8' OR src_ip << '172.16.0.0/12' OR src_ip << '192.168.0.0/16' "
        "OR src_ip << 'fc00::/7' OR src_ip << '100.64.0.0/10')")


def log_panel(where: str, title: str = "Live log", limit: int = 150) -> dict[str, Any]:
    return {"id": "log", "title": title, "type": "log", "span": 3,
            "sql": f"SELECT ts, source, action, host(src_ip) src_ip, src_port, host(dst_ip) dst_ip, dst_port, domain, "
                   f"username, src_country, message FROM events WHERE {W} AND {where} ORDER BY ts DESC LIMIT {limit}"}


DASHBOARDS: dict[str, dict[str, Any]] = {
    "firewall": {
        "title": "Firewall", "source": "firewall", "panels": [
            {"id": "kpi", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) AS \"Events\", count(*) FILTER (WHERE action = 'block') AS \"Blocked\", "
                f"count(*) FILTER (WHERE action = 'pass') AS \"Passed (logged)\", "
                f"count(DISTINCT src_ip) FILTER (WHERE action = 'block') AS \"Blocked sources\", "
                f"count(DISTINCT dst_port) FILTER (WHERE action = 'block') AS \"Ports targeted\", "
                f"count(*) FILTER (WHERE action = 'block' AND {PRIV}) AS \"Internal blocked\" "
                f"FROM events WHERE source = 'firewall' AND {W}"},
            {"id": "actions", "title": "Traffic by action", "type": "timeseries", "span": 2,
             "sql": f"SELECT {B} t, action series, count(*) v FROM events WHERE source = 'firewall' AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "proto", "title": "Protocols", "type": "pie",
             "sql": f"SELECT coalesce(proto, '?') label, count(*) v FROM events WHERE source = 'firewall' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 8"},
            {"id": "iface", "title": "Blocked per interface", "type": "timeseries", "span": 2, "stack": True,
             "sql": f"SELECT {B} t, coalesce(interface, '?') series, count(*) v FROM events WHERE source = 'firewall' AND action = 'block' AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "dir", "title": "Direction", "type": "pie",
             "sql": f"SELECT coalesce(direction, '?') || ' / ' || action label, count(*) v FROM events WHERE source = 'firewall' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 8"},
            {"id": "ports", "title": "Top blocked destination ports", "type": "hbar",
             "sql": f"SELECT dst_port::text || '/' || coalesce(proto, '') label, count(*) v FROM events WHERE source = 'firewall' AND action = 'block' AND dst_port IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 15"},
            {"id": "countries", "title": "Blocked by country", "type": "hbar",
             "sql": f"SELECT src_country label, count(*) v FROM events WHERE source = 'firewall' AND action = 'block' AND src_country IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 15"},
            {"id": "hour", "title": "Blocks by hour of day", "type": "bar",
             "sql": f"SELECT lpad(extract(hour FROM ts)::int::text, 2, '0') label, count(*) v FROM events WHERE source = 'firewall' AND action = 'block' AND {W} GROUP BY 1 ORDER BY 1"},
            {"id": "srcs", "title": "Top blocked sources", "type": "table",
             "cols": [["ip", "Source", "ip"], ["country", "", "flag"], ["ports", "Ports", "num"], ["hosts", "Hosts", "num"], ["n", "Hits", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(src_ip) ip, max(src_country) country, count(DISTINCT dst_port) ports, count(DISTINCT dst_ip) hosts, count(*) n, max(ts) last FROM events WHERE source = 'firewall' AND action = 'block' AND {W} AND src_ip IS NOT NULL GROUP BY 1 ORDER BY 5 DESC LIMIT 25"},
            {"id": "rules", "title": "Top rules", "type": "table",
             "cols": [["rule", "Rule"], ["action", "Action"], ["n", "Hits", "num"]],
             "sql": f"SELECT coalesce(nullif(data->>'label', ''), 'rule ' || coalesce(data->>'rulenr', '?')) rule, action, count(*) n FROM events WHERE source = 'firewall' AND {W} GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 25"},
            {"id": "inbound", "title": "Allowed inbound from the internet", "type": "table",
             "cols": [["dst", "Destination", "ip"], ["port", "Port"], ["proto", "Proto"], ["srcs", "Sources", "num"], ["n", "Hits", "num"]],
             "sql": f"SELECT host(dst_ip) dst, dst_port port, proto, count(DISTINCT src_ip) srcs, count(*) n FROM events WHERE source = 'firewall' AND action = 'pass' AND direction = 'in' AND {W} AND NOT {PRIV} GROUP BY 1, 2, 3 ORDER BY 5 DESC LIMIT 25"},
            {"id": "internal", "title": "Internal hosts being blocked", "type": "table",
             "cols": [["ip", "Host", "ip"], ["dsts", "Destinations", "num"], ["ports", "Ports"], ["n", "Blocks", "num"]],
             "sql": f"SELECT host(src_ip) ip, count(DISTINCT dst_ip) dsts, (array_agg(DISTINCT dst_port))[1:8] ports, count(*) n FROM events WHERE source = 'firewall' AND action = 'block' AND {W} AND {PRIV} GROUP BY 1 ORDER BY 4 DESC LIMIT 25"},
            log_panel("source = 'firewall'"),
        ]},
    "dns": {
        "title": "DNS (Unbound)", "source": "unbound", "panels": [
            {"id": "kpi", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) AS \"Queries\", count(*) FILTER (WHERE action IN ('block', 'drop')) AS \"Blocked\", "
                f"count(*) FILTER (WHERE action = 'nxdomain' OR data->>'rcode' = 'NXDOMAIN') AS \"NXDOMAIN\", "
                f"count(DISTINCT src_ip) AS \"Clients\", count(DISTINCT domain) AS \"Unique domains\" "
                f"FROM events WHERE source = 'unbound' AND {W}"},
            {"id": "q", "title": "Queries over time", "type": "timeseries", "span": 2,
             "sql": f"SELECT {B} t, CASE WHEN action IN ('block', 'drop') THEN 'blocked' WHEN action IN ('query', 'reply') THEN 'resolved' ELSE action END series, count(*) v FROM events WHERE source = 'unbound' AND action IS NOT NULL AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "qtype", "title": "Query types", "type": "pie",
             "sql": f"SELECT coalesce(data->>'qtype', data->>'type', '?') label, count(*) v FROM events WHERE source = 'unbound' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 8"},
            {"id": "clients", "title": "Top clients", "type": "hbar",
             "sql": f"SELECT host(src_ip) label, count(*) v FROM events WHERE source = 'unbound' AND src_ip IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 15"},
            {"id": "rcode", "title": "Response codes", "type": "pie",
             "sql": f"SELECT coalesce(data->>'rcode', 'n/a') label, count(*) v FROM events WHERE source = 'unbound' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 8"},
            {"id": "lists", "title": "Blocklists hit", "type": "pie",
             "sql": f"SELECT coalesce(nullif(data->>'blocklist', ''), 'local') label, count(*) v FROM events WHERE source = 'unbound' AND action IN ('block', 'drop') AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 8"},
            {"id": "top", "title": "Top domains", "type": "table", "cols": [["domain", "Domain"], ["clients", "Clients", "num"], ["n", "Queries", "num"]],
             "sql": f"SELECT domain, count(DISTINCT src_ip) clients, count(*) n FROM events WHERE source = 'unbound' AND domain IS NOT NULL AND {W} GROUP BY 1 ORDER BY 3 DESC LIMIT 25"},
            {"id": "blocked", "title": "Top blocked domains", "type": "table", "cols": [["domain", "Domain"], ["list", "List"], ["clients", "Clients", "num"], ["n", "Hits", "num"]],
             "sql": f"SELECT domain, max(data->>'blocklist') list, count(DISTINCT src_ip) clients, count(*) n FROM events WHERE source = 'unbound' AND action IN ('block', 'drop') AND {W} GROUP BY 1 ORDER BY 4 DESC LIMIT 25"},
            {"id": "nx", "title": "Top NXDOMAIN", "type": "table", "cols": [["domain", "Domain"], ["client", "Client", "ip"], ["n", "Count", "num"]],
             "sql": f"SELECT domain, host(src_ip) client, count(*) n FROM events WHERE source = 'unbound' AND (action = 'nxdomain' OR data->>'rcode' = 'NXDOMAIN') AND {W} GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 25"},
            {"id": "long", "title": "Longest / unusual names (tunneling check)", "type": "table", "cols": [["domain", "Domain"], ["client", "Client", "ip"], ["len", "Length", "num"]],
             "sql": f"SELECT domain, host(src_ip) client, max(length(domain)) len FROM events WHERE source = 'unbound' AND length(domain) > 50 AND {W} GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 25"},
            log_panel("source = 'unbound'"),
        ]},
    "web": {
        "title": "Web server (nginx)", "source": "nginx", "panels": [
            {"id": "kpi", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) AS \"Requests\", count(*) FILTER (WHERE action ~ '^http_4') AS \"4xx\", "
                f"count(*) FILTER (WHERE action ~ '^http_5') AS \"5xx\", "
                f"count(*) FILTER (WHERE jsonb_array_length(coalesce(data->'tags', '[]'::jsonb)) > 0) AS \"Suspicious\", "
                f"count(DISTINCT src_ip) AS \"Clients\", count(*) FILTER (WHERE action IN ('waf_block', 'rate_limited')) AS \"WAF / rate limited\" "
                f"FROM events WHERE source = 'nginx' AND {W}"},
            {"id": "status", "title": "Responses by class", "type": "timeseries", "span": 2,
             "sql": f"SELECT {B} t, CASE WHEN action ~ '^http_2' THEN '2xx' WHEN action ~ '^http_3' THEN '3xx' WHEN action ~ '^http_4' THEN '4xx' WHEN action ~ '^http_5' THEN '5xx' ELSE coalesce(action, 'other') END series, count(*) v FROM events WHERE source = 'nginx' AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "codes", "title": "Status codes", "type": "pie",
             "sql": f"SELECT replace(coalesce(action, '?'), 'http_', '') label, count(*) v FROM events WHERE source = 'nginx' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 10"},
            {"id": "attacks", "title": "Attack patterns over time", "type": "timeseries", "span": 2,
             "sql": f"SELECT {B} t, tag series, count(*) v FROM (SELECT ts, jsonb_array_elements_text(data->'tags') tag FROM events WHERE source = 'nginx' AND {W} AND jsonb_typeof(data->'tags') = 'array') x GROUP BY 1, 2 ORDER BY 1"},
            {"id": "vhosts", "title": "Virtual hosts", "type": "pie",
             "sql": f"SELECT coalesce(domain, '?') label, count(*) v FROM events WHERE source = 'nginx' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 8"},
            {"id": "paths", "title": "Top paths", "type": "table", "cols": [["path", "Path"], ["n", "Requests", "num"], ["err", "Errors", "num"]],
             "sql": f"SELECT left(data->>'path', 120) path, count(*) n, count(*) FILTER (WHERE action ~ '^http_[45]') err FROM events WHERE source = 'nginx' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 25"},
            {"id": "404", "title": "Top 4xx paths (probing)", "type": "table", "cols": [["path", "Path"], ["ips", "IPs", "num"], ["n", "Hits", "num"]],
             "sql": f"SELECT left(data->>'path', 120) path, count(DISTINCT src_ip) ips, count(*) n FROM events WHERE source = 'nginx' AND action ~ '^http_4' AND {W} GROUP BY 1 ORDER BY 3 DESC LIMIT 25"},
            {"id": "clients", "title": "Top clients", "type": "table", "cols": [["ip", "Client", "ip"], ["country", "", "flag"], ["err", "Errors", "num"], ["sus", "Suspicious", "num"], ["n", "Requests", "num"]],
             "sql": f"SELECT host(src_ip) ip, max(src_country) country, count(*) FILTER (WHERE action ~ '^http_[45]') err, count(*) FILTER (WHERE jsonb_array_length(coalesce(data->'tags', '[]'::jsonb)) > 0) sus, count(*) n FROM events WHERE source = 'nginx' AND {W} GROUP BY 1 ORDER BY 5 DESC LIMIT 25"},
            {"id": "ua", "title": "Top user agents", "type": "table", "cols": [["ua", "User agent"], ["n", "Requests", "num"]],
             "sql": f"SELECT left(coalesce(data->>'user_agent', '-'), 120) ua, count(*) n FROM events WHERE source = 'nginx' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 20"},
            {"id": "countries", "title": "Requests by country", "type": "hbar",
             "sql": f"SELECT src_country label, count(*) v FROM events WHERE source = 'nginx' AND src_country IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 15"},
            log_panel("source = 'nginx'"),
        ]},
    "threats": {
        "title": "Threats (IDS · CrowdSec · Q-Feeds)", "source": "suricata,crowdsec,qfeeds", "panels": [
            {"id": "kpi", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) FILTER (WHERE source = 'suricata') AS \"IDS events\", "
                f"count(*) FILTER (WHERE source = 'crowdsec' AND action = 'alert') AS \"CrowdSec alerts\", "
                f"count(*) FILTER (WHERE source = 'crowdsec' AND action IN ('ban', 'captcha')) AS \"CrowdSec decisions\", "
                f"count(*) FILTER (WHERE source = 'qfeeds') AS \"Q-Feeds hits\", "
                f"count(*) FILTER (WHERE source = 'qfeeds' AND {PRIV}) AS \"Outbound threat-intel hits\", "
                f"(SELECT count(*) FROM alerts WHERE status = 'open' AND severity IN ('high', 'critical')) AS \"Open high/critical alerts\" "
                f"FROM events WHERE source IN ('suricata', 'crowdsec', 'qfeeds') AND {W}"},
            {"id": "src", "title": "Threat events by source", "type": "timeseries", "span": 2,
             "sql": f"SELECT {B} t, source series, count(*) v FROM events WHERE source IN ('suricata', 'crowdsec', 'qfeeds', 'zenarmor') AND (source <> 'zenarmor' OR action IN ('threat', 'block')) AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "alerts", "title": "Alerts by rule", "type": "pie",
             "sql": "SELECT rule label, count(*) v FROM alerts WHERE last_seen > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC LIMIT 10"},
            {"id": "sev", "title": "Alerts over time by severity", "type": "timeseries", "span": 2,
             "sql": "SELECT to_timestamp(floor(extract(epoch FROM created_at) / $2) * $2) t, severity series, count(*) v FROM alerts WHERE created_at > now() - make_interval(secs => $1) GROUP BY 1, 2 ORDER BY 1"},
            {"id": "cls", "title": "IDS classifications", "type": "pie",
             "sql": f"SELECT coalesce(data->>'classification', data->>'category', '?') label, count(*) v FROM events WHERE source = 'suricata' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 8"},
            {"id": "sigs", "title": "IDS signatures", "type": "table", "cols": [["sig", "Signature"], ["srcs", "Sources", "num"], ["n", "Hits", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT message sig, count(DISTINCT src_ip) srcs, count(*) n, max(ts) last FROM events WHERE source = 'suricata' AND action IS NOT NULL AND {W} GROUP BY 1 ORDER BY 3 DESC LIMIT 25"},
            {"id": "cs", "title": "CrowdSec scenarios", "type": "table", "cols": [["scenario", "Scenario"], ["ips", "IPs", "num"], ["n", "Events", "num"]],
             "sql": f"SELECT coalesce(data->>'scenario', data->>'reason', '?') scenario, count(DISTINCT src_ip) ips, count(*) n FROM events WHERE source = 'crowdsec' AND {W} GROUP BY 1 ORDER BY 3 DESC LIMIT 25"},
            {"id": "attackers", "title": "Top attackers across all sources", "type": "table",
             "cols": [["ip", "IP", "ip"], ["country", "", "flag"], ["sources", "Seen by"], ["n", "Events", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(src_ip) ip, max(src_country) country, array_agg(DISTINCT source) sources, count(*) n, max(ts) last FROM events WHERE {W} AND src_ip IS NOT NULL AND NOT {PRIV} AND (source IN ('suricata', 'crowdsec', 'qfeeds') OR action IN ('block', 'login_failed', 'waf_block')) GROUP BY 1 ORDER BY 4 DESC LIMIT 25"},
            {"id": "qf", "title": "Q-Feeds matches", "type": "table", "cols": [["src", "Source", "ip"], ["dst", "Destination", "ip"], ["dir", "Dir"], ["port", "Port"], ["n", "Hits", "num"]],
             "sql": f"SELECT host(src_ip) src, host(dst_ip) dst, direction dir, dst_port port, count(*) n FROM events WHERE source = 'qfeeds' AND {W} GROUP BY 1, 2, 3, 4 ORDER BY 5 DESC LIMIT 25"},
            {"id": "decisions", "title": "Active CrowdSec decisions", "type": "table", "cols": [["value", "Value"], ["type", "Type"], ["reason", "Reason"], ["origin", "Origin"], ["expiration", "Expires"]],
             "sql": "SELECT d->>'value' value, d->>'type' type, coalesce(d->>'reason', d->>'scenario') reason, d->>'origin' origin, coalesce(d->>'expiration', d->>'duration') expiration "
                    "FROM snapshots, jsonb_array_elements(CASE WHEN jsonb_typeof(data) = 'array' THEN data ELSE '[]'::jsonb END) d WHERE key = 'crowdsec_decisions' AND $1::float8 > 0 LIMIT 200"},
            log_panel("source IN ('suricata', 'crowdsec', 'qfeeds')"),
        ]},
    "zenarmor": {
        "title": "Zenarmor", "source": "zenarmor", "panels": [
            {"id": "kpi", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) AS \"Events\", count(*) FILTER (WHERE action = 'block') AS \"Blocked\", "
                f"count(*) FILTER (WHERE data->>'family' = 'alert' OR coalesce(data->>'security', '') <> '') AS \"Threats\", "
                f"count(DISTINCT src_ip) AS \"Hosts\", count(DISTINCT coalesce(data->>'app_name', '')) AS \"Applications\" "
                f"FROM events WHERE source = 'zenarmor' AND {W}"},
            {"id": "act", "title": "Events by action", "type": "timeseries", "span": 2,
             "sql": f"SELECT {B} t, coalesce(action, '?') series, count(*) v FROM events WHERE source = 'zenarmor' AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "cat", "title": "Categories", "type": "pie",
             "sql": f"SELECT coalesce(data->>'app_category', data->>'category', data->>'web_category', '?') label, count(*) v FROM events WHERE source = 'zenarmor' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 10"},
            {"id": "apps", "title": "Top applications", "type": "hbar",
             "sql": f"SELECT coalesce(data->>'app_name', '?') label, count(*) v FROM events WHERE source = 'zenarmor' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 15"},
            {"id": "hosts", "title": "Top local hosts", "type": "hbar",
             "sql": f"SELECT coalesce(data->>'src_hostname', host(src_ip)) label, count(*) v FROM events WHERE source = 'zenarmor' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 15"},
            {"id": "blocked", "title": "Blocked destinations", "type": "table", "cols": [["dest", "Destination"], ["cat", "Category"], ["n", "Hits", "num"]],
             "sql": f"SELECT coalesce(domain, host(dst_ip)) dest, max(coalesce(data->>'app_category', data->>'category')) cat, count(*) n FROM events WHERE source = 'zenarmor' AND action = 'block' AND {W} GROUP BY 1 ORDER BY 3 DESC LIMIT 25"},
            {"id": "threats", "title": "Threats", "type": "table", "cols": [["src", "Host", "ip"], ["dest", "Destination"], ["tags", "Tags"], ["n", "Hits", "num"]],
             "sql": f"SELECT host(src_ip) src, coalesce(domain, host(dst_ip)) dest, coalesce(data->>'security', data->>'security_tags') tags, count(*) n FROM events WHERE source = 'zenarmor' AND (data->>'family' = 'alert' OR coalesce(data->>'security', '') <> '') AND {W} GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT 25"},
            {"id": "fam", "title": "Records per family", "type": "pie",
             "sql": f"SELECT coalesce(data->>'family', '?') label, count(*) v FROM events WHERE source = 'zenarmor' AND {W} GROUP BY 1 ORDER BY 2 DESC"},
            {"id": "tls", "title": "Top TLS server names (SNI)", "type": "table", "cols": [["sni", "Server name"], ["cat", "Category"], ["n", "Sessions", "num"]],
             "sql": f"SELECT domain sni, max(data->>'category') cat, count(*) n FROM events WHERE source = 'zenarmor' AND data->>'family' = 'tls' AND {W} GROUP BY 1 ORDER BY 3 DESC LIMIT 25"},
            {"id": "devices", "title": "Devices seen by Zenarmor", "type": "table",
             "cols": [["name", "Device"], ["os", "OS"], ["vendor", "Vendor"], ["ip", "IP", "ip"], ["n", "Records", "num"]],
             "sql": f"SELECT coalesce(data->'device'->>'name', data->>'src_hostname') name, max(data->'device'->>'os') os, max(data->'device'->>'vendor') vendor, max(host(src_ip)) ip, count(*) n FROM events WHERE source = 'zenarmor' AND (data ? 'device' OR data ? 'src_hostname') AND {W} GROUP BY 1 ORDER BY 5 DESC LIMIT 30"},
            {"id": "bytes", "title": "Top talkers by volume, MB (flows)", "type": "hbar",
             "sql": f"SELECT coalesce(data->>'src_hostname', host(src_ip)) label, round(sum(coalesce((data->>'src_nbytes')::numeric, 0) + coalesce((data->>'dst_nbytes')::numeric, 0)) / 1048576, 1) v FROM events WHERE source = 'zenarmor' AND data->>'family' = 'conn' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 15"},
            log_panel("source = 'zenarmor'"),
        ]},
    "auth": {
        "title": "Authentication & VPN", "source": "auth,vpn", "panels": [
            {"id": "kpi", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) FILTER (WHERE action = 'login_failed') AS \"Failed logins\", "
                f"count(*) FILTER (WHERE action = 'login_success') AS \"Successful logins\", "
                f"count(DISTINCT src_ip) FILTER (WHERE action = 'login_failed') AS \"Attacking IPs\", "
                f"count(DISTINCT username) FILTER (WHERE action = 'login_failed') AS \"Usernames tried\", "
                f"count(*) FILTER (WHERE action = 'config_change') AS \"Config changes\" "
                f"FROM events WHERE source IN ('auth', 'vpn', 'system') AND {W}"},
            {"id": "ts", "title": "Logins over time", "type": "timeseries", "span": 2,
             "sql": f"SELECT {B} t, source || ' ' || action series, count(*) v FROM events WHERE action IN ('login_failed', 'login_success', 'vpn_connect') AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "users", "title": "Usernames tried", "type": "pie",
             "sql": f"SELECT coalesce(username, '?') label, count(*) v FROM events WHERE action = 'login_failed' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 10"},
            {"id": "fails", "title": "Failed logins per source IP", "type": "table", "cols": [["ip", "IP", "ip"], ["country", "", "flag"], ["svc", "Service"], ["users", "Users"], ["n", "Failures", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(src_ip) ip, max(src_country) country, max(coalesce(program, source)) svc, (array_agg(DISTINCT username))[1:6] users, count(*) n, max(ts) last FROM events WHERE action = 'login_failed' AND {W} GROUP BY 1 ORDER BY 5 DESC LIMIT 25"},
            {"id": "ok", "title": "Successful logins", "type": "table", "cols": [["ts", "Time", "time"], ["username", "User"], ["ip", "From", "ip"], ["prog", "Via"]],
             "sql": f"SELECT ts, username, host(src_ip) ip, coalesce(program, source) prog FROM events WHERE action IN ('login_success', 'vpn_connect') AND {W} ORDER BY ts DESC LIMIT 50"},
            {"id": "cfg", "title": "Configuration changes", "type": "table", "cols": [["ts", "Time", "time"], ["host", "Host"], ["message", "Message"]],
             "sql": f"SELECT ts, host, left(message, 200) message FROM events WHERE action = 'config_change' AND {W} ORDER BY ts DESC LIMIT 50"},
            log_panel("source IN ('auth', 'vpn')"),
        ]},
    "syslog": {
        "title": "System logs", "source": "system,dhcp", "panels": [
            {"id": "kpi", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) AS \"Messages\", count(*) FILTER (WHERE severity <= 3) AS \"Errors+\", count(*) FILTER (WHERE severity = 4) AS \"Warnings\", "
                f"count(DISTINCT program) AS \"Programs\", count(DISTINCT host) AS \"Hosts\" FROM events WHERE source IN ('system', 'dhcp', 'unraid') AND {W}"},
            {"id": "sev", "title": "Messages by severity", "type": "timeseries", "span": 2,
             "sql": f"SELECT {B} t, (ARRAY['emerg','alert','crit','error','warning','notice','info','debug'])[severity + 1] series, count(*) v FROM events WHERE source IN ('system', 'dhcp', 'unraid') AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "prog", "title": "Top programs", "type": "pie",
             "sql": f"SELECT coalesce(program, '?') label, count(*) v FROM events WHERE source IN ('system', 'dhcp', 'unraid') AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 10"},
            {"id": "errors", "title": "Recent warnings and errors", "type": "table", "span": 3,
             "cols": [["ts", "Time", "time"], ["host", "Host"], ["program", "Program"], ["sev", "Sev"], ["message", "Message"]],
             "sql": f"SELECT ts, host, program, (ARRAY['emerg','alert','crit','error','warning','notice','info','debug'])[severity + 1] sev, left(message, 300) message FROM events WHERE source IN ('system', 'dhcp', 'unraid') AND severity <= 4 AND {W} ORDER BY ts DESC LIMIT 100"},
            log_panel("source IN ('system', 'dhcp')"),
        ]},
}


def step_for(hours: float) -> int:
    return max(60, int(hours * 3600 / 60))


async def run_dashboard(name: str, hours: float) -> dict[str, Any]:
    spec = DASHBOARDS[name]
    secs, step = hours * 3600, step_for(hours)

    async def run(panel: dict[str, Any]) -> dict[str, Any]:
        sql = panel["sql"]
        args = [secs, step] if "$2" in sql else [secs]
        out = {k: v for k, v in panel.items() if k != "sql"}
        try:
            async with db.pool().acquire() as conn:
                out["rows"] = db.records(await conn.fetch(sql, *args))
        except Exception as exc:  # noqa: BLE001 - one broken panel must not break the page
            out["rows"], out["error"] = [], str(exc)
        return out

    panels = await asyncio.gather(*(run(p) for p in spec["panels"]))
    return {"name": name, "title": spec["title"], "source": spec.get("source"), "step": step, "panels": panels}
