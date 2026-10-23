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
import re
from typing import Any

from . import db

W = "ts > now() - make_interval(secs => $1)"
B = "to_timestamp(floor(extract(epoch FROM ts) / $2) * $2)"
PRIV = ("(src_ip << '10.0.0.0/8' OR src_ip << '172.16.0.0/12' OR src_ip << '192.168.0.0/16' "
        "OR src_ip << 'fc00::/7' OR src_ip << '100.64.0.0/10')")


# firewall log lines of the rules that use the CrowdSec aliases (Settings › OPNsense › Blocklist aliases, marked
# data.blocklist by the poller) - the plugin's own rules log only with Services › CrowdSec › Settings › "Enable log for
# rules". The rule names catch lines stored before the marking existed.
CS_FW = "(source = 'firewall' AND (lower(data->>'blocklist') = 'crowdsec' OR data->>'label' LIKE 'CrowdSec (%'))"
# one blocklist of that setting from the poller's snapshot (lower-case name)
BL = "(SELECT data->'{0}' FROM snapshots WHERE key = 'blocklists')"


def log_panel(where: str, title: str = "Live log", limit: int = 150) -> dict[str, Any]:
    return {"id": "log", "title": title, "type": "log", "span": 3,
            "sql": f"SELECT ts, source, action, host(src_ip) src_ip, src_port, host(dst_ip) dst_ip, dst_port, domain, "
                   f"username, src_country, message FROM events WHERE {W} AND {where} ORDER BY ts DESC LIMIT {limit}"}


DASHBOARDS: dict[str, dict[str, Any]] = {
    "firewall": {
        "title": "Firewall", "source": "firewall", "group": "opnsense", "panels": [
            {"id": "kpi", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) AS \"Events\", count(*) FILTER (WHERE action = 'block') AS \"Blocked\", "
                f"count(*) FILTER (WHERE action = 'pass') AS \"Passed (logged)\", "
                f"count(DISTINCT src_ip) FILTER (WHERE action = 'block') AS \"Blocked sources\", "
                f"count(DISTINCT dst_port) FILTER (WHERE action = 'block') AS \"Ports targeted\", "
                f"count(*) FILTER (WHERE action = 'block' AND {PRIV}) AS \"Internal blocked\" "
                f"FROM events WHERE source = 'firewall' AND {W}",
             "drill": {"tiles": {"Blocked": {"action": "block"}, "Passed (logged)": {"action": "pass"}, "Blocked sources": {"action": "block"},
                                 "Ports targeted": {"action": "block"}, "Internal blocked": {"action": "block"}}}},
            {"id": "actions", "title": "Traffic by action", "type": "timeseries", "span": 2, "drill": {"series": "action"},
             "sql": f"SELECT {B} t, action series, count(*) v FROM events WHERE source = 'firewall' AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "proto", "title": "Protocols", "type": "pie", "drill": {"by": "proto"},
             "sql": f"SELECT coalesce(proto, '?') label, count(*) v FROM events WHERE source = 'firewall' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 8"},
            {"id": "iface", "title": "Blocked per interface", "type": "timeseries", "span": 2, "stack": True,
             "drill": {"base": {"action": "block"}, "series": "iface"},
             "sql": f"SELECT {B} t, coalesce(interface, '?') series, count(*) v FROM events WHERE source = 'firewall' AND action = 'block' AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "dir", "title": "Direction", "type": "pie",
             "sql": f"SELECT coalesce(direction, '?') || ' / ' || action label, count(*) v, direction f_direction, action f_action FROM events WHERE source = 'firewall' AND {W} GROUP BY 1, 3, 4 ORDER BY 2 DESC LIMIT 8"},
            {"id": "ports", "title": "Top blocked destination ports", "type": "hbar",
             "drill": {"base": {"action": "block"}},
             "sql": f"SELECT dst_port::text || '/' || coalesce(proto, '') label, count(*) v, dst_port f_port, proto o_proto FROM events WHERE source = 'firewall' AND action = 'block' AND dst_port IS NOT NULL AND {W} GROUP BY 1, 3, 4 ORDER BY 2 DESC LIMIT 15"},
            {"id": "countries", "title": "Blocked by country", "type": "hbar", "drill": {"base": {"action": "block"}, "by": "country"},
             "sql": f"SELECT src_country label, count(*) v FROM events WHERE source = 'firewall' AND action = 'block' AND src_country IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 15"},
            {"id": "hour", "title": "Blocks by hour of day", "type": "bar", "drill": {"base": {"action": "block"}},
             "sql": f"SELECT lpad(extract(hour FROM ts)::int::text, 2, '0') label, count(*) v FROM events WHERE source = 'firewall' AND action = 'block' AND {W} GROUP BY 1 ORDER BY 1"},
            {"id": "srcs", "title": "Top blocked sources", "type": "table", "drill": {"base": {"action": "block"}, "by": {"ip": "ip"}},
             "cols": [["ip", "Source", "ip"], ["country", "", "flag"], ["ports", "Ports", "num"], ["hosts", "Hosts", "num"], ["n", "Hits", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(src_ip) ip, max(src_country) country, count(DISTINCT dst_port) ports, count(DISTINCT dst_ip) hosts, count(*) n, max(ts) last FROM events WHERE source = 'firewall' AND action = 'block' AND {W} AND src_ip IS NOT NULL GROUP BY 1 ORDER BY 5 DESC LIMIT 25"},
            {"id": "rules", "title": "Top rules", "type": "table",
             "cols": [["rule", "Rule"], ["action", "Action"], ["n", "Hits", "num"]],
             "drill": {"by": {"action": "action"}},
             "sql": f"SELECT coalesce(nullif(data->>'label', ''), 'rule ' || coalesce(data->>'rulenr', '?')) rule, action, count(*) n, "
                    f"nullif(data->>'label', '') f_d_label, CASE WHEN nullif(data->>'label', '') IS NULL THEN max(data->>'rulenr') END o_d_rulenr "
                    f"FROM events WHERE source = 'firewall' AND {W} GROUP BY 1, 2, 4 ORDER BY 3 DESC LIMIT 25"},
            {"id": "inbound", "title": "Allowed inbound from the internet", "type": "table",
             "cols": [["dst", "Destination", "ip"], ["port", "Port"], ["proto", "Proto"], ["srcs", "Sources", "num"], ["n", "Hits", "num"]],
             "drill": {"base": {"action": "pass", "direction": "in"}, "by": {"ip": "dst", "port": "port", "proto": "proto"}},
             "sql": f"SELECT host(dst_ip) dst, dst_port port, proto, count(DISTINCT src_ip) srcs, count(*) n FROM events WHERE source = 'firewall' AND action = 'pass' AND direction = 'in' AND {W} AND NOT {PRIV} GROUP BY 1, 2, 3 ORDER BY 5 DESC LIMIT 25"},
            {"id": "internal", "title": "Internal hosts being blocked", "type": "table", "drill": {"base": {"action": "block"}, "by": {"ip": "ip"}},
             "cols": [["ip", "Host", "ip"], ["dsts", "Destinations", "num"], ["ports", "Ports"], ["n", "Blocks", "num"]],
             "sql": f"SELECT host(src_ip) ip, count(DISTINCT dst_ip) dsts, (array_agg(DISTINCT dst_port))[1:8] ports, count(*) n FROM events WHERE source = 'firewall' AND action = 'block' AND {W} AND {PRIV} GROUP BY 1 ORDER BY 4 DESC LIMIT 25"},
            log_panel("source = 'firewall'"),
        ]},
    "dns": {
        "title": "DNS (Unbound)", "source": "unbound", "group": "opnsense", "panels": [
            {"id": "kpi", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) AS \"Queries\", count(*) FILTER (WHERE action IN ('block', 'drop')) AS \"Blocked\", "
                f"count(*) FILTER (WHERE action = 'nxdomain' OR data->>'rcode' = 'NXDOMAIN') AS \"NXDOMAIN\", "
                f"count(DISTINCT src_ip) AS \"Clients\", count(DISTINCT domain) AS \"Unique domains\" "
                f"FROM events WHERE source = 'unbound' AND {W}",
             "drill": {"tiles": {"Blocked": {"action": "block,drop"}, "NXDOMAIN": {"d_rcode": "NXDOMAIN"}}}},
            {"id": "q", "title": "Queries over time", "type": "timeseries", "span": 2,
             "sql": f"SELECT {B} t, CASE WHEN action IN ('block', 'drop') THEN 'blocked' WHEN action IN ('query', 'reply') THEN 'resolved' ELSE action END series, count(*) v FROM events WHERE source = 'unbound' AND action IS NOT NULL AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "qtype", "title": "Query types", "type": "pie",
             "sql": f"SELECT coalesce(data->>'qtype', data->>'type', '?') label, count(*) v, data->>'qtype' o_d_qtype, data->>'type' o_d_type FROM events WHERE source = 'unbound' AND {W} GROUP BY 1, 3, 4 ORDER BY 2 DESC LIMIT 8"},
            {"id": "clients", "title": "Top clients", "type": "hbar", "drill": {"by": "ip"},
             "sql": f"SELECT host(src_ip) label, count(*) v FROM events WHERE source = 'unbound' AND src_ip IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 15"},
            {"id": "rcode", "title": "Response codes", "type": "pie",
             "sql": f"SELECT coalesce(data->>'rcode', 'n/a') label, count(*) v, data->>'rcode' f_d_rcode FROM events WHERE source = 'unbound' AND {W} GROUP BY 1, 3 ORDER BY 2 DESC LIMIT 8"},
            {"id": "lists", "title": "Blocklists hit", "type": "pie",
             "drill": {"base": {"action": "block,drop"}},
             "sql": f"SELECT coalesce(nullif(data->>'blocklist', ''), 'local') label, count(*) v, nullif(data->>'blocklist', '') f_d_blocklist FROM events WHERE source = 'unbound' AND action IN ('block', 'drop') AND {W} GROUP BY 1, 3 ORDER BY 2 DESC LIMIT 8"},
            {"id": "top", "title": "Top domains", "type": "table", "drill": {"by": {"domain": "domain"}}, "cols": [["domain", "Domain"], ["clients", "Clients", "num"], ["n", "Queries", "num"]],
             "sql": f"SELECT domain, count(DISTINCT src_ip) clients, count(*) n FROM events WHERE source = 'unbound' AND domain IS NOT NULL AND {W} GROUP BY 1 ORDER BY 3 DESC LIMIT 25"},
            {"id": "blocked", "title": "Top blocked domains", "type": "table", "drill": {"base": {"action": "block,drop"}, "by": {"domain": "domain"}}, "cols": [["domain", "Domain"], ["list", "List"], ["clients", "Clients", "num"], ["n", "Hits", "num"]],
             "sql": f"SELECT domain, max(data->>'blocklist') list, count(DISTINCT src_ip) clients, count(*) n FROM events WHERE source = 'unbound' AND action IN ('block', 'drop') AND {W} GROUP BY 1 ORDER BY 4 DESC LIMIT 25"},
            {"id": "nx", "title": "Top NXDOMAIN", "type": "table", "drill": {"by": {"domain": "domain", "ip": "client"}}, "cols": [["domain", "Domain"], ["client", "Client", "ip"], ["n", "Count", "num"]],
             "sql": f"SELECT domain, host(src_ip) client, count(*) n FROM events WHERE source = 'unbound' AND (action = 'nxdomain' OR data->>'rcode' = 'NXDOMAIN') AND {W} GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 25"},
            {"id": "long", "title": "Longest / unusual names (tunneling check)", "type": "table", "drill": {"by": {"domain": "domain", "ip": "client"}}, "cols": [["domain", "Domain"], ["client", "Client", "ip"], ["len", "Length", "num"]],
             "sql": f"SELECT domain, host(src_ip) client, max(length(domain)) len FROM events WHERE source = 'unbound' AND length(domain) > 50 AND {W} GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 25"},
            log_panel("source = 'unbound'"),
        ]},
    "web": {
        "title": "Web server (nginx)", "source": "nginx", "group": "opnsense", "panels": [
            {"id": "kpi", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) AS \"Requests\", count(*) FILTER (WHERE action ~ '^http_4') AS \"4xx\", "
                f"count(*) FILTER (WHERE action ~ '^http_5') AS \"5xx\", "
                f"count(*) FILTER (WHERE jsonb_array_length(coalesce(data->'tags', '[]'::jsonb)) > 0) AS \"Suspicious\", "
                f"count(DISTINCT src_ip) AS \"Clients\", count(*) FILTER (WHERE action IN ('waf_block', 'rate_limited')) AS \"WAF / rate limited\" "
                f"FROM events WHERE source = 'nginx' AND {W}",
             "drill": {"tiles": {"4xx": {"action": "http_4*"}, "5xx": {"action": "http_5*"}, "WAF / rate limited": {"action": "waf_block,rate_limited"}}}},
            {"id": "status", "title": "Responses by class", "type": "timeseries", "span": 2,
             "sql": f"SELECT {B} t, CASE WHEN action ~ '^http_2' THEN '2xx' WHEN action ~ '^http_3' THEN '3xx' WHEN action ~ '^http_4' THEN '4xx' WHEN action ~ '^http_5' THEN '5xx' ELSE coalesce(action, 'other') END series, count(*) v FROM events WHERE source = 'nginx' AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "codes", "title": "Status codes", "type": "pie",
             "sql": f"SELECT replace(coalesce(action, '?'), 'http_', '') label, count(*) v, action f_action FROM events WHERE source = 'nginx' AND {W} GROUP BY 1, 3 ORDER BY 2 DESC LIMIT 10"},
            {"id": "attacks", "title": "Attack patterns over time", "type": "timeseries", "span": 2,
             "sql": f"SELECT {B} t, tag series, count(*) v FROM (SELECT ts, jsonb_array_elements_text(data->'tags') tag FROM events WHERE source = 'nginx' AND {W} AND jsonb_typeof(data->'tags') = 'array') x GROUP BY 1, 2 ORDER BY 1"},
            {"id": "vhosts", "title": "Virtual hosts", "type": "pie", "drill": {"by": "domain"},
             "sql": f"SELECT coalesce(domain, '?') label, count(*) v FROM events WHERE source = 'nginx' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 8"},
            {"id": "paths", "title": "Top paths", "type": "table", "cols": [["path", "Path"], ["n", "Requests", "num"], ["err", "Errors", "num"]],
             "sql": f"SELECT left(data->>'path', 120) path, count(*) n, count(*) FILTER (WHERE action ~ '^http_[45]') err, max(data->>'path') o_d_path FROM events WHERE source = 'nginx' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 25"},
            {"id": "404", "title": "Top 4xx paths (probing)", "type": "table", "cols": [["path", "Path"], ["ips", "IPs", "num"], ["n", "Hits", "num"]],
             "drill": {"base": {"action": "http_4*"}},
             "sql": f"SELECT left(data->>'path', 120) path, count(DISTINCT src_ip) ips, count(*) n, max(data->>'path') o_d_path FROM events WHERE source = 'nginx' AND action ~ '^http_4' AND {W} GROUP BY 1 ORDER BY 3 DESC LIMIT 25"},
            {"id": "clients", "title": "Top clients", "type": "table", "drill": {"by": {"ip": "ip"}}, "cols": [["ip", "Client", "ip"], ["country", "", "flag"], ["err", "Errors", "num"], ["sus", "Suspicious", "num"], ["n", "Requests", "num"]],
             "sql": f"SELECT host(src_ip) ip, max(src_country) country, count(*) FILTER (WHERE action ~ '^http_[45]') err, count(*) FILTER (WHERE jsonb_array_length(coalesce(data->'tags', '[]'::jsonb)) > 0) sus, count(*) n FROM events WHERE source = 'nginx' AND {W} GROUP BY 1 ORDER BY 5 DESC LIMIT 25"},
            {"id": "ua", "title": "Top user agents", "type": "table", "cols": [["ua", "User agent"], ["n", "Requests", "num"]],
             "sql": f"SELECT left(coalesce(data->>'user_agent', '-'), 120) ua, count(*) n, max(data->>'user_agent') o_d_user_agent FROM events WHERE source = 'nginx' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 20"},
            {"id": "countries", "title": "Requests by country", "type": "hbar", "drill": {"by": "country"},
             "sql": f"SELECT src_country label, count(*) v FROM events WHERE source = 'nginx' AND src_country IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 15"},
            log_panel("source = 'nginx'"),
        ]},
    "threats": {
        "title": "Threats (IDS · CrowdSec · Q-Feeds)", "source": "suricata,crowdsec,qfeeds", "group": "opnsense", "panels": [
            {"id": "kpi", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) FILTER (WHERE source = 'suricata') AS \"IDS events\", "
                f"count(*) FILTER (WHERE source = 'crowdsec' AND action = 'alert') AS \"CrowdSec alerts\", "
                f"count(*) FILTER (WHERE source = 'crowdsec' AND action IN ('ban', 'captcha')) AS \"CrowdSec decisions\", "
                f"count(*) FILTER (WHERE {CS_FW}) AS \"CrowdSec firewall blocks\", "
                f"({BL.format('crowdsec')}->>'size')::bigint AS \"CrowdSec blocklist IPs\", "
                f"({BL.format('crowdsec')}->>'packets')::bigint AS \"CrowdSec blocked packets (since rules loaded)\", "
                f"count(*) FILTER (WHERE source = 'qfeeds') AS \"Q-Feeds hits\", "
                f"count(*) FILTER (WHERE source = 'qfeeds' AND {PRIV}) AS \"Outbound threat-intel hits\", "
                f"(SELECT count(*) FROM alerts WHERE status = 'open' AND severity IN ('high', 'critical')) AS \"Open high/critical alerts\" "
                f"FROM events WHERE (source IN ('suricata', 'crowdsec', 'qfeeds') OR {CS_FW}) AND {W}",
             "drill": {"tiles": {"IDS events": {"source": "suricata"}, "CrowdSec alerts": {"source": "crowdsec", "action": "alert"},
                                 "CrowdSec decisions": {"source": "crowdsec", "action": "ban,captcha"},
                                 "CrowdSec firewall blocks": {"source": "firewall", "d_blocklist": "CrowdSec"}, "CrowdSec blocklist IPs": None,
                                 "CrowdSec blocked packets (since rules loaded)": None,
                                 "Q-Feeds hits": {"source": "qfeeds"},
                                 "Outbound threat-intel hits": {"source": "qfeeds"}, "Open high/critical alerts": {"url": "/alerts"}}}},
            {"id": "src", "title": "Threat events by source", "type": "timeseries", "span": 2, "drill": {"series": "source"},
             "sql": f"SELECT {B} t, CASE WHEN source = 'firewall' THEN 'crowdsec blocklist' ELSE source END series, count(*) v FROM events "
                    f"WHERE (source IN ('suricata', 'crowdsec', 'qfeeds', 'zenarmor') AND (source <> 'zenarmor' OR action IN ('threat', 'block')) "
                    f"OR {CS_FW}) AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "alerts", "title": "Alerts by rule", "type": "pie", "drill": {"url": "/alerts"},
             "sql": "SELECT rule label, count(*) v FROM alerts WHERE last_seen > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC LIMIT 10"},
            {"id": "sev", "title": "Alerts over time by severity", "type": "timeseries", "span": 2, "drill": {"url": "/alerts"},
             "sql": "SELECT to_timestamp(floor(extract(epoch FROM created_at) / $2) * $2) t, severity series, count(*) v FROM alerts WHERE created_at > now() - make_interval(secs => $1) GROUP BY 1, 2 ORDER BY 1"},
            {"id": "cls", "title": "IDS classifications", "type": "pie",
             "drill": {"base": {"source": "suricata"}},
             "sql": f"SELECT coalesce(data->>'classification', data->>'category', '?') label, count(*) v, data->>'classification' o_d_classification, data->>'category' o_d_category FROM events WHERE source = 'suricata' AND {W} GROUP BY 1, 3, 4 ORDER BY 2 DESC LIMIT 8"},
            {"id": "sigs", "title": "IDS signatures", "type": "table", "drill": {"base": {"source": "suricata"}, "by": {"q": "sig"}}, "cols": [["sig", "Signature"], ["srcs", "Sources", "num"], ["n", "Hits", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT message sig, count(DISTINCT src_ip) srcs, count(*) n, max(ts) last FROM events WHERE source = 'suricata' AND action IS NOT NULL AND {W} GROUP BY 1 ORDER BY 3 DESC LIMIT 25"},
            {"id": "cs", "title": "CrowdSec scenarios", "type": "table", "cols": [["scenario", "Scenario"], ["ips", "IPs", "num"], ["n", "Events", "num"]],
             "drill": {"base": {"source": "crowdsec"}},
             "sql": f"SELECT coalesce(data->>'scenario', data->>'reason', '?') scenario, count(DISTINCT src_ip) ips, count(*) n, data->>'scenario' o_d_scenario, data->>'reason' o_d_reason FROM events WHERE source = 'crowdsec' AND {W} GROUP BY 1, 4, 5 ORDER BY 3 DESC LIMIT 25"},
            {"id": "csfw", "title": "Blocked by the CrowdSec blocklist", "type": "table",
             "drill": {"base": {"source": "firewall", "d_blocklist": "CrowdSec"}, "by": {"ip": "ip"}},
             "cols": [["ip", "IP", "ip"], ["country", "", "flag"], ["dir", "Dir"], ["n", "Blocks", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(CASE WHEN direction = 'out' THEN dst_ip ELSE src_ip END) ip, "
                    f"max(CASE WHEN direction = 'out' THEN dst_country ELSE src_country END) country, "
                    f"coalesce(direction, '?') dir, count(*) n, max(ts) last "
                    f"FROM events WHERE {CS_FW} AND {W} GROUP BY 1, 3 ORDER BY 4 DESC LIMIT 25"},
            {"id": "blocklists", "title": "Blocklists (Settings › OPNsense › Blocklist aliases)", "type": "table", "span": 2,
             "drill": {"base": {"source": "firewall"}, "by": {"d_blocklist": "name"}},
             "cols": [["name", "Blocklist"], ["aliases", "Aliases"], ["size", "Addresses", "num"], ["rules", "Rules", "num"],
                      ["packets", "Blocked packets", "num"], ["logged", "Logged blocks", "num"]],
             "sql": "SELECT b.value->>'name' name, (SELECT string_agg(a, ', ') FROM jsonb_array_elements_text(b.value->'aliases') a) aliases, "
                    "(b.value->>'size')::bigint size, jsonb_array_length(coalesce(b.value->'rules', '[]')) rules, "
                    "(b.value->>'packets')::bigint packets, (SELECT count(*) FROM events e WHERE e.source = 'firewall' "
                    "AND e.data->>'blocklist' = b.value->>'name' AND e.ts > now() - make_interval(secs => $1)) logged "
                    "FROM snapshots s, jsonb_each(CASE WHEN jsonb_typeof(s.data) = 'object' THEN s.data ELSE '{}'::jsonb END) b "
                    "WHERE s.key = 'blocklists' ORDER BY 1"},
            {"id": "attackers", "title": "Top attackers across all sources", "type": "table", "drill": {"base": {"source": ""}, "by": {"ip": "ip"}},
             "cols": [["ip", "IP", "ip"], ["country", "", "flag"], ["sources", "Seen by"], ["n", "Events", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(src_ip) ip, max(src_country) country, array_agg(DISTINCT source) sources, count(*) n, max(ts) last FROM events WHERE {W} AND src_ip IS NOT NULL AND NOT {PRIV} AND (source IN ('suricata', 'crowdsec', 'qfeeds') OR action IN ('block', 'login_failed', 'waf_block')) GROUP BY 1 ORDER BY 4 DESC LIMIT 25"},
            {"id": "qf", "title": "Q-Feeds matches", "type": "table", "drill": {"base": {"source": "qfeeds"}, "by": {"ip": "src"}}, "cols": [["src", "Source", "ip"], ["dst", "Destination", "ip"], ["dir", "Dir"], ["port", "Port"], ["n", "Hits", "num"]],
             "sql": f"SELECT host(src_ip) src, host(dst_ip) dst, direction dir, dst_port port, count(*) n FROM events WHERE source = 'qfeeds' AND {W} GROUP BY 1, 2, 3, 4 ORDER BY 5 DESC LIMIT 25"},
            {"id": "decisions", "title": "Active CrowdSec decisions", "type": "table", "drill": {"base": {"source": ""}, "by": {"ip": "value"}}, "cols": [["value", "Value"], ["type", "Type"], ["reason", "Reason"], ["origin", "Origin"], ["expiration", "Expires"]],
             "sql": "SELECT regexp_replace(coalesce(d->>'scope_value', d->>'value'), '^[A-Za-z_]*[g-zG-Z_][A-Za-z_]*:', '') value, coalesce(d->>'action', d->>'type') type, coalesce(d->>'reason', d->>'scenario') reason, coalesce(d->>'origin', d->>'source') origin, coalesce(d->>'expiration', d->>'duration') expiration "
                    "FROM snapshots, jsonb_array_elements(CASE WHEN jsonb_typeof(data) = 'array' THEN data ELSE '[]'::jsonb END) d WHERE key = 'crowdsec_decisions' AND $1::float8 > 0 LIMIT 200"},
            log_panel("source IN ('suricata', 'crowdsec', 'qfeeds')"),
        ]},
    "zenarmor": {
        # field names: Zenarmor ES/syslog stream (see parsers/security.py). Only conn records carry app_name /
        # app_category; dns/tls/http carry a web "category" (dns: domain_categories) instead.
        "title": "Zenarmor", "source": "zenarmor", "group": "opnsense", "panels": [
            {"id": "kpi", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) AS \"Events\", count(*) FILTER (WHERE action = 'block') AS \"Blocked\", "
                f"count(*) FILTER (WHERE data->>'family' = 'alert' OR coalesce(data->>'security', '') <> '') AS \"Threats\", "
                f"count(DISTINCT src_ip) AS \"Hosts\", count(DISTINCT data->>'app_name') AS \"Applications\", "
                f"count(DISTINCT domain) AS \"Domains\" "
                f"FROM events WHERE source = 'zenarmor' AND {W}",
             "drill": {"tiles": {"Blocked": {"action": "block"}, "Threats": {"d_family": "alert"}, "Applications": {"d_family": "conn"}}}},
            {"id": "act", "title": "Records by type", "type": "timeseries", "span": 2, "drill": {"series": "d_family"},
             "sql": f"SELECT {B} t, coalesce(data->>'family', '?') series, count(*) v FROM events WHERE source = 'zenarmor' AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "blk", "title": "Blocked vs allowed", "type": "pie",
             "sql": f"SELECT CASE WHEN action = 'block' THEN 'blocked' ELSE 'allowed' END label, count(*) v, CASE WHEN action = 'block' THEN 'block' END o_action FROM events WHERE source = 'zenarmor' AND {W} GROUP BY 1, 3"},
            {"id": "apps", "title": "Top applications (connections)", "type": "hbar", "drill": {"by": "d_app_name"},
             "sql": f"SELECT data->>'app_name' label, count(*) v FROM events WHERE source = 'zenarmor' AND data->>'app_name' IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 15"},
            {"id": "cat", "title": "Application categories", "type": "pie", "drill": {"by": "d_app_category"},
             "sql": f"SELECT data->>'app_category' label, count(*) v FROM events WHERE source = 'zenarmor' AND data->>'app_category' IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 10"},
            {"id": "webcat", "title": "Web categories (DNS / TLS / HTTP)", "type": "hbar", "drill": {"by": "d_category"},
             "sql": f"SELECT data->>'category' label, count(*) v FROM events WHERE source = 'zenarmor' AND data->>'family' IN ('dns', 'tls', 'http') AND coalesce(data->>'category', '') <> '' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 15"},
            {"id": "hosts", "title": "Top local hosts", "type": "hbar",
             "sql": f"SELECT coalesce(nullif(data->>'src_hostname', host(src_ip)::text), data->'device'->>'name', host(src_ip)) label, count(*) v, host(src_ip) o_ip FROM events WHERE source = 'zenarmor' AND {W} GROUP BY 1, 3 ORDER BY 2 DESC LIMIT 15"},
            {"id": "blocked", "title": "Blocked destinations", "type": "table", "drill": {"base": {"action": "block"}},
             "cols": [["dest", "Destination"], ["cat", "Category"], ["hosts", "Hosts", "num"], ["n", "Hits", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT coalesce(domain, host(dst_ip)) dest, max(coalesce(data->>'app_category', data->>'category')) cat, count(DISTINCT src_ip) hosts, count(*) n, max(ts) last, domain o_domain, CASE WHEN domain IS NULL THEN max(host(dst_ip)) END o_ip FROM events WHERE source = 'zenarmor' AND action = 'block' AND {W} GROUP BY 1, 6 ORDER BY 4 DESC LIMIT 25"},
            {"id": "threats", "title": "Threats", "type": "table", "drill": {"by": {"ip": "src"}},
             "cols": [["src", "Host", "ip"], ["name", "Device"], ["dest", "Destination"], ["what", "Threat / rule"], ["n", "Hits", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(src_ip) src, max(coalesce(nullif(data->>'src_hostname', host(src_ip)::text), data->'device'->>'name', host(src_ip))) name, coalesce(domain, host(dst_ip)) dest, "
                    f"coalesce(nullif(data->>'security', ''), data->'alertinfo'->>'signature', data->'alertinfo'->>'category') what, count(*) n, max(ts) last "
                    f"FROM events WHERE source = 'zenarmor' AND (data->>'family' = 'alert' OR coalesce(data->>'security', '') <> '') AND {W} GROUP BY 1, 3, 4 ORDER BY 5 DESC LIMIT 25"},
            {"id": "dns", "title": "Top DNS queries", "type": "table", "drill": {"base": {"d_family": "dns"}, "by": {"domain": "domain"}},
             "cols": [["domain", "Domain"], ["cat", "Category"], ["clients", "Clients", "num"], ["n", "Queries", "num"]],
             "sql": f"SELECT domain, max(data->>'category') cat, count(DISTINCT src_ip) clients, count(*) n FROM events WHERE source = 'zenarmor' AND data->>'family' = 'dns' AND domain IS NOT NULL AND {W} GROUP BY 1 ORDER BY 4 DESC LIMIT 25"},
            {"id": "tls", "title": "Top TLS server names (SNI)", "type": "table", "drill": {"base": {"d_family": "tls"}, "by": {"domain": "sni"}},
             "cols": [["sni", "Server name"], ["cat", "Category"], ["clients", "Clients", "num"], ["n", "Sessions", "num"]],
             "sql": f"SELECT domain sni, max(data->>'category') cat, count(DISTINCT src_ip) clients, count(*) n FROM events WHERE source = 'zenarmor' AND data->>'family' = 'tls' AND {W} GROUP BY 1 ORDER BY 4 DESC LIMIT 25"},
            {"id": "http", "title": "Plain HTTP requests", "type": "table", "drill": {"base": {"d_family": "http"}, "by": {"domain": "host"}},
             "cols": [["host", "Host"], ["cat", "Category"], ["ua", "Browser / agent"], ["n", "Requests", "num"]],
             "sql": f"SELECT domain host, max(data->>'category') cat, max(coalesce(data->>'browser', data->>'user_agent')) ua, count(*) n FROM events WHERE source = 'zenarmor' AND data->>'family' = 'http' AND {W} GROUP BY 1 ORDER BY 4 DESC LIMIT 25"},
            {"id": "devices", "title": "Devices seen by Zenarmor", "type": "table", "drill": {"by": {"ip": "ip"}},
             "cols": [["name", "Device"], ["cat", "Type"], ["os", "OS"], ["vendor", "Vendor"], ["ip", "IP", "ip"], ["n", "Records", "num"]],
             "sql": f"SELECT coalesce(nullif(data->>'src_hostname', host(src_ip)::text), data->'device'->>'name', host(src_ip)) name, max(data->'device'->>'category') cat, max(concat_ws(' ', data->'device'->>'os', data->'device'->>'osver')) os, max(data->'device'->>'vendor') vendor, max(host(src_ip)) ip, count(*) n FROM events WHERE source = 'zenarmor' AND {W} GROUP BY 1 ORDER BY 6 DESC LIMIT 30"},
            {"id": "bytes", "title": "Top talkers by volume, MB (connections)", "type": "hbar",
             "sql": f"SELECT coalesce(nullif(data->>'src_hostname', host(src_ip)::text), data->'device'->>'name', host(src_ip)) label, round(sum(greatest(coalesce((data->>'src_nbytes')::numeric, 0), coalesce((data->>'src_pbytes')::numeric, 0)) + greatest(coalesce((data->>'dst_nbytes')::numeric, 0), coalesce((data->>'dst_pbytes')::numeric, 0))) / 1048576, 1) v, host(src_ip) o_ip FROM events WHERE source = 'zenarmor' AND data->>'family' = 'conn' AND {W} GROUP BY 1, 3 ORDER BY 2 DESC LIMIT 15"},
            {"id": "countries", "title": "Destination countries", "type": "hbar", "drill": False,
             "sql": f"SELECT dst_country label, count(*) v FROM events WHERE source = 'zenarmor' AND dst_country IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 15"},
            log_panel("source = 'zenarmor'"),
        ]},
    "auth": {
        "title": "Authentication", "source": "auth,vpn", "group": "opnsense", "panels": [
            {"id": "kpi", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) FILTER (WHERE action = 'login_failed') AS \"Failed logins\", "
                f"count(*) FILTER (WHERE action = 'login_success') AS \"Successful logins\", "
                f"count(DISTINCT src_ip) FILTER (WHERE action = 'login_failed') AS \"IPs with failed logins\", "
                f"count(DISTINCT username) FILTER (WHERE action = 'login_failed') AS \"Usernames tried\", "
                f"count(*) FILTER (WHERE action = 'config_change') AS \"Config changes\" "
                f"FROM events WHERE source IN ('auth', 'vpn', 'system') AND {W}",
             "drill": {"base": {"source": ""}, "tiles": {"Failed logins": {"action": "login_failed"}, "Successful logins": {"action": "login_success"},
                                                         "IPs with failed logins": {"action": "login_failed"}, "Usernames tried": {"action": "login_failed"},
                                                         "Config changes": {"action": "config_change"}}}},
            {"id": "ts", "title": "Logins over time", "type": "timeseries", "span": 2, "drill": {"base": {"source": "", "action": "login_failed,login_success,vpn_connect"}},
             "sql": f"SELECT {B} t, source || ' ' || action series, count(*) v FROM events WHERE action IN ('login_failed', 'login_success', 'vpn_connect') AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "users", "title": "Usernames tried", "type": "pie", "drill": {"base": {"source": "", "action": "login_failed"}, "by": "user"},
             "sql": f"SELECT coalesce(username, '?') label, count(*) v FROM events WHERE action = 'login_failed' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 10"},
            {"id": "fails", "title": "Failed logins per source IP", "type": "table", "drill": {"base": {"source": "", "action": "login_failed"}, "by": {"ip": "ip"}}, "cols": [["ip", "IP", "ip"], ["country", "", "flag"], ["svc", "Service"], ["users", "Users"], ["n", "Failures", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(src_ip) ip, max(src_country) country, max(coalesce(program, source)) svc, (array_agg(DISTINCT username))[1:6] users, count(*) n, max(ts) last FROM events WHERE action = 'login_failed' AND {W} GROUP BY 1 ORDER BY 5 DESC LIMIT 25"},
            {"id": "ok", "title": "Successful logins", "type": "table", "drill": {"base": {"source": "", "action": "login_success,vpn_connect"}, "by": {"ip": "ip", "user": "username"}}, "cols": [["ts", "Time", "time"], ["username", "User"], ["ip", "From", "ip"], ["prog", "Via"]],
             "sql": f"SELECT ts, username, host(src_ip) ip, coalesce(program, source) prog FROM events WHERE action IN ('login_success', 'vpn_connect') AND {W} ORDER BY ts DESC LIMIT 50"},
            {"id": "cfg", "title": "Configuration changes", "type": "table", "drill": {"base": {"source": "", "action": "config_change"}, "by": {"host": "host"}}, "cols": [["ts", "Time", "time"], ["host", "Host"], ["part", "Changed"], ["username", "By"], ["ip", "From", "ip"], ["message", "Message"]],
             "sql": f"SELECT ts, host, coalesce(data->'config'->>'label', '?') part, username, host(src_ip) ip, left(message, 160) message "
                    f"FROM events WHERE action = 'config_change' AND {W} ORDER BY ts DESC LIMIT 50"},
            log_panel("source = 'auth'"),
        ]},
    "vpn": {
        "title": "VPN", "source": "vpn", "group": "opnsense", "panels": [
            {"id": "vpnkpi", "type": "stat", "span": 3, "drill": {"base": {"source": "vpn"}, "tiles": {"VPN connects": {"action": "vpn_connect"}}},
             "sql": "SELECT (SELECT count(*) FROM snapshots s, jsonb_array_elements(coalesce(s.data->'wireguard'->'peers', '[]')) p "
                    "WHERE s.key = 'vpn' AND p->>'peer-status' = 'online') AS \"WireGuard peers online\", "
                    "(SELECT count(*) FROM snapshots s, jsonb_array_elements(coalesce(s.data->'wireguard'->'peers', '[]')) p WHERE s.key = 'vpn') AS \"WireGuard peers\", "
                    "(SELECT count(*) FROM snapshots s, jsonb_array_elements(coalesce(s.data->'openvpn', '[]')) c "
                    "WHERE s.key = 'vpn' AND coalesce(c->>'common_name', '') <> '') AS \"OpenVPN clients\", "
                    "(SELECT count(*) FROM snapshots s, jsonb_array_elements(coalesce(s.data->'ipsec', '[]')) t "
                    "WHERE s.key = 'vpn' AND t->>'connected' = 'true') AS \"IPsec tunnels up\", "
                    "(SELECT count(*) FROM events WHERE source = 'vpn' AND action = 'vpn_connect' AND ts > now() - make_interval(secs => $1)) AS \"VPN connects\""},
            {"id": "wg", "title": "WireGuard peers (live)", "type": "table", "span": 3, "drill": {"base": {"source": "vpn"}, "by": {"user": "name"}},
             "cols": [["name", "Peer"], ["iface", "Instance"], ["status", "Status"], ["endpoint", "Endpoint"], ["allowed", "Allowed IPs"],
                      ["hs", "Last handshake", "ago"], ["rx", "Received", "bytes"], ["tx", "Sent", "bytes"]],
             "sql": "SELECT p->>'name' name, coalesce(p->>'ifname', p->>'if') iface, p->>'peer-status' status, nullif(p->>'endpoint', '(none)') endpoint, "
                    "p->>'allowed-ips' allowed, CASE WHEN coalesce(p->>'latest-handshake', '0') ~ '^[1-9][0-9]*$' THEN to_timestamp((p->>'latest-handshake')::bigint) END hs, "
                    "(p->>'transfer-rx')::numeric rx, (p->>'transfer-tx')::numeric tx "
                    "FROM snapshots s, jsonb_array_elements(coalesce(s.data->'wireguard'->'peers', '[]')) p WHERE s.key = 'vpn' AND $1::float8 > 0 "
                    "ORDER BY (p->>'peer-status' = 'online') DESC, p->>'name'"},
            {"id": "ovpn", "title": "OpenVPN sessions (live)", "type": "table", "span": 2, "drill": {"base": {"source": "vpn"}, "by": {"user": "cn"}},
             "cols": [["cn", "User / CN"], ["server", "Server"], ["real", "From"], ["virtual", "VPN address"], ["since", "Connected since"],
                      ["rx", "Received", "bytes"], ["tx", "Sent", "bytes"]],
             "sql": "SELECT coalesce(nullif(c->>'username', 'UNDEF'), c->>'common_name') cn, c->>'description' server, c->>'real_address' real, "
                    "c->>'virtual_address' virtual, c->>'connected_since' since, (nullif(c->>'bytes_received', ''))::numeric rx, (nullif(c->>'bytes_sent', ''))::numeric tx "
                    "FROM snapshots s, jsonb_array_elements(coalesce(s.data->'openvpn', '[]')) c "
                    "WHERE s.key = 'vpn' AND coalesce(c->>'common_name', c->>'real_address', '') <> '' AND $1::float8 > 0"},
            {"id": "ipsec", "title": "IPsec tunnels (live)", "type": "table", "drill": {"base": {"source": "vpn"}, "by": {"ip": "remote"}},
             "cols": [["name", "Tunnel"], ["remote", "Remote"], ["up", "Up"], ["rx", "In", "bytes"], ["tx", "Out", "bytes"]],
             "sql": "SELECT coalesce(nullif(t->>'phase1desc', ''), t->>'name') name, t->>'remote-addrs' remote, CASE WHEN t->>'connected' = 'true' THEN 'yes' ELSE 'no' END up, "
                    "(nullif(t->>'bytes-in', ''))::numeric rx, (nullif(t->>'bytes-out', ''))::numeric tx "
                    "FROM snapshots s, jsonb_array_elements(coalesce(s.data->'ipsec', '[]')) t WHERE s.key = 'vpn' AND $1::float8 > 0"},
            {"id": "vpnev", "title": "VPN connects / disconnects", "type": "timeseries", "span": 3, "drill": {"base": {"source": "vpn"}, "series": "action"},
             "sql": f"SELECT {B} t, action series, count(*) v FROM events WHERE source = 'vpn' AND action IN ('vpn_connect', 'vpn_disconnect', 'login_success', 'login_failed') AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "vpnlogins", "title": "VPN logins", "type": "table", "span": 3,
             "drill": {"base": {"source": "vpn", "action": "login_success,login_failed,vpn_connect"}, "by": {"ip": "ip", "user": "username"}},
             "cols": [["ts", "Time", "time"], ["action", "Result"], ["username", "User"], ["ip", "From", "ip"], ["country", "", "flag"], ["prog", "Via"]],
             "sql": f"SELECT ts, replace(action, '_', ' ') action, username, host(src_ip) ip, src_country country, coalesce(program, source) prog "
                    f"FROM events WHERE source = 'vpn' AND action IN ('login_success', 'login_failed', 'vpn_connect') AND {W} ORDER BY ts DESC LIMIT 50"},
            log_panel("source = 'vpn'"),
        ]},
    "unifi": {
        "title": "Wi-Fi & clients", "source": "unifi", "group": "unifi", "panels": [
            {"id": "kpi", "type": "stat", "span": 3, "sql":
                "SELECT (SELECT count(*) FROM snapshots s, jsonb_array_elements(coalesce(s.data, '[]')) c "
                "WHERE s.key = 'unifi:clients' AND NOT coalesce((c->>'wired')::boolean, false)) AS \"Wi-Fi clients now\", "
                "(SELECT count(*) FROM snapshots s, jsonb_array_elements(coalesce(s.data, '[]')) c "
                "WHERE s.key = 'unifi:clients' AND coalesce((c->>'wired')::boolean, false)) AS \"Wired clients now\", "
                f"count(*) FILTER (WHERE action = 'client_connect') AS \"Connects\", "
                f"count(*) FILTER (WHERE action = 'client_roam') AS \"Roams\", "
                f"count(*) FILTER (WHERE action = 'device_offline') AS \"Device offline\", "
                f"count(*) FILTER (WHERE action IN ('rogue_ap', 'rogue_dhcp')) AS \"Rogue AP / DHCP\" "
                f"FROM events WHERE source = 'unifi' AND {W}",
             "drill": {"tiles": {"Wi-Fi clients now": {"url": "/unifi#clients"}, "Wired clients now": {"url": "/unifi#clients"},
                                 "Connects": {"action": "client_connect"}, "Roams": {"action": "client_roam"},
                                 "Device offline": {"action": "device_offline"}, "Rogue AP / DHCP": {"action": "rogue_ap,rogue_dhcp"}}}},
            {"id": "sec", "title": "Clients with security events (UniFi location + OPNsense findings)", "type": "table", "span": 3,
             "drill": {"base": {"source": ""}, "by": {"ip": "ip"}},
             "cols": [["name", "Device"], ["ip", "IP", "ip"], ["where", "Connected to"], ["signal", "Signal", "num"],
                      ["fw", "Firewall blocks", "num"], ["dns", "DNS blocked", "num"], ["threats", "Threat events", "num"],
                      ["alerts", "Open alerts", "num"]],
             "sql": "WITH ev AS (SELECT src_ip, count(*) FILTER (WHERE source = 'firewall' AND action = 'block') fw, "
                    "count(*) FILTER (WHERE source = 'unbound' AND action IN ('block', 'drop')) dns, "
                    "count(*) FILTER (WHERE source IN ('suricata', 'crowdsec', 'qfeeds') OR (source = 'zenarmor' AND action = 'block')) threats "
                    f"FROM events WHERE {W} AND src_ip IS NOT NULL AND source IN ('firewall', 'unbound', 'suricata', 'crowdsec', 'qfeeds', 'zenarmor') GROUP BY 1) "
                    "SELECT coalesce(d.hostname, d.mac) name, host(d.ip) ip, d.conn_where \"where\", d.conn_signal signal, ev.fw, ev.dns, ev.threats, "
                    "(SELECT count(*) FROM alerts a WHERE a.src_ip = d.ip AND a.status = 'open') alerts "
                    "FROM devices d JOIN ev ON ev.src_ip = d.ip WHERE d.conn_where IS NOT NULL "
                    "ORDER BY 7 DESC, 8 DESC, 5 + 6 DESC LIMIT 30"},
            {"id": "ts", "title": "UniFi events over time", "type": "timeseries", "span": 2, "drill": {"series": "action"},
             "sql": f"SELECT {B} t, action series, count(*) v FROM events WHERE source = 'unifi' AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "ssid", "title": "Clients per Wi-Fi network (now)", "type": "pie", "drill": {"url": "/unifi#clients"},
             "sql": "SELECT CASE WHEN coalesce((c->>'wired')::boolean, false) THEN 'wired' ELSE coalesce(c->>'ssid', '?') END label, count(*) v "
                    "FROM snapshots s, jsonb_array_elements(coalesce(s.data, '[]')) c WHERE s.key = 'unifi:clients' AND $1::float8 > 0 "
                    "GROUP BY 1 ORDER BY 2 DESC"},
            {"id": "ap", "title": "Clients per access point (now)", "type": "hbar", "drill": {"url": "/unifi#devices"},
             "sql": "SELECT coalesce(c->>'ap', '?') label, count(*) v FROM snapshots s, jsonb_array_elements(coalesce(s.data, '[]')) c "
                    "WHERE s.key = 'unifi:clients' AND NOT coalesce((c->>'wired')::boolean, false) AND $1::float8 > 0 GROUP BY 1 ORDER BY 2 DESC LIMIT 20"},
            {"id": "weak", "title": "Weakest Wi-Fi signal (now)", "type": "table", "drill": {"base": {"source": ""}, "by": {"ip": "ip"}},
             "cols": [["name", "Client"], ["ip", "IP", "ip"], ["ap", "AP"], ["signal", "Signal dBm", "num"], ["sat", "Experience %", "num"]],
             "sql": "SELECT coalesce(c->>'alias', c->>'hostname', c->>'mac') name, c->>'ip' ip, c->>'ap' ap, (c->>'signal')::numeric signal, "
                    "(c->>'satisfaction')::numeric sat FROM snapshots s, jsonb_array_elements(coalesce(s.data, '[]')) c "
                    "WHERE s.key = 'unifi:clients' AND c->>'signal' IS NOT NULL AND $1::float8 > 0 ORDER BY 4 LIMIT 20"},
            {"id": "roam", "title": "Most roaming clients", "type": "table", "drill": {"base": {"source": "unifi", "action": "client_roam"}, "by": {"ip": "ip"}},
             "cols": [["name", "Client"], ["ip", "IP", "ip"], ["n", "Roams", "num"], ["last", "Last", "ago"]],
             "sql": "SELECT coalesce(max(d.hostname), e.data->>'mac') name, host(e.src_ip) ip, count(*) n, max(e.ts) last FROM events e "
                    "LEFT JOIN devices d ON d.mac = e.data->>'mac' WHERE e.source = 'unifi' AND e.action = 'client_roam' "
                    "AND e.ts > now() - make_interval(secs => $1) GROUP BY e.data->>'mac', 2 ORDER BY 3 DESC LIMIT 20"},
            {"id": "traffic", "title": "Top clients by traffic (current sessions)", "type": "table", "drill": {"base": {"source": ""}, "by": {"ip": "ip"}},
             "cols": [["name", "Client"], ["ip", "IP", "ip"], ["where", "Via"], ["down", "Down", "bytes"], ["up", "Up", "bytes"]],
             "sql": "SELECT coalesce(c->>'alias', c->>'hostname', c->>'mac') name, c->>'ip' ip, coalesce(c->>'ap', c->>'switch') \"where\", "
                    "(c->>'rx_bytes')::numeric down, (c->>'tx_bytes')::numeric up FROM snapshots s, jsonb_array_elements(coalesce(s.data, '[]')) c "
                    "WHERE s.key = 'unifi:clients' AND c->>'rx_bytes' IS NOT NULL AND $1::float8 > 0 "
                    "ORDER BY coalesce((c->>'rx_bytes')::numeric, 0) + coalesce((c->>'tx_bytes')::numeric, 0) DESC LIMIT 20"},
            {"id": "dev", "title": "Device events (offline, restarts, PoE, rogue)", "type": "table", "span": 2,
             "drill": {"base": {"source": "unifi"}, "by": {"action": "action"}},
             "cols": [["ts", "Time", "time"], ["action", "Event"], ["message", "Message"]],
             "sql": f"SELECT ts, action, left(message, 200) message FROM events WHERE source = 'unifi' AND action IN ('device_offline', "
                    f"'device_online', 'device_restart', 'device_isolated', 'device_upgraded', 'poe_disconnect', 'poe_overload', 'overheat', "
                    f"'stp_blocking', 'rogue_ap', 'rogue_dhcp', 'ips_alert', 'admin_login', 'login_success', 'login_failed') AND {W} ORDER BY ts DESC LIMIT 50"},
            {"id": "air", "title": "Foreign APs using your Wi-Fi names", "type": "table", "drill": {"url": "/unifi#air"},
             "cols": [["essid", "Wi-Fi name"], ["bssid", "BSSID"], ["signal", "Signal", "num"], ["heard_by", "Heard by"]],
             "sql": "SELECT r->>'essid' essid, r->>'bssid' bssid, (r->>'signal')::numeric signal, r->>'heard_by' heard_by "
                    "FROM snapshots s, jsonb_array_elements(coalesce(s.data, '[]')) r WHERE s.key = 'unifi:rogue' "
                    "AND (r->>'evil_twin')::boolean AND $1::float8 > 0 ORDER BY 3 DESC NULLS LAST"},
            log_panel("source = 'unifi'"),
        ]},
    "syslog": {
        "title": "System logs", "source": "system,dhcp,unraid", "group": "tools", "panels": [
            {"id": "kpi", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) AS \"Messages\", count(*) FILTER (WHERE severity <= 3) AS \"Errors+\", count(*) FILTER (WHERE severity = 4) AS \"Warnings\", "
                f"count(DISTINCT program) AS \"Programs\", count(DISTINCT host) AS \"Hosts\" FROM events WHERE source IN ('system', 'dhcp', 'unraid') AND {W}",
             "drill": {"tiles": {"Errors+": {"min_severity": 3}, "Warnings": {"min_severity": 4}}}},
            {"id": "sev", "title": "Messages by severity", "type": "timeseries", "span": 2,
             "sql": f"SELECT {B} t, (ARRAY['emerg','alert','crit','error','warning','notice','info','debug'])[severity + 1] series, count(*) v FROM events WHERE source IN ('system', 'dhcp', 'unraid') AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "prog", "title": "Top programs", "type": "pie", "drill": {"by": "program"},
             "sql": f"SELECT coalesce(program, '?') label, count(*) v FROM events WHERE source IN ('system', 'dhcp', 'unraid') AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 10"},
            {"id": "errors", "title": "Recent warnings and errors", "type": "table", "span": 3,
             "drill": {"base": {"min_severity": 4}, "by": {"program": "program", "host": "host"}},
             "cols": [["ts", "Time", "time"], ["host", "Host"], ["program", "Program"], ["sev", "Sev"], ["message", "Message"]],
             "sql": f"SELECT ts, host, program, (ARRAY['emerg','alert','crit','error','warning','notice','info','debug'])[severity + 1] sev, left(message, 300) message FROM events WHERE source IN ('system', 'dhcp', 'unraid') AND severity <= 4 AND {W} ORDER BY ts DESC LIMIT 100"},
            {"id": "hosts", "title": "Messages per host", "type": "hbar", "drill": {"by": "host"},
             "sql": f"SELECT coalesce(host, '?') label, count(*) v FROM events WHERE source IN ('system', 'dhcp', 'unraid') AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 15"},
            {"id": "progs", "title": "Programs", "type": "table", "drill": {"by": {"program": "program", "host": "host"}},
             "cols": [["host", "Host"], ["program", "Program"], ["err", "Errors / warnings", "num"], ["n", "Messages", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host, program, count(*) FILTER (WHERE severity <= 4) err, count(*) n, max(ts) last FROM events WHERE source IN ('system', 'dhcp', 'unraid') AND {W} GROUP BY 1, 2 ORDER BY 4 DESC LIMIT 40"},
            log_panel("source IN ('system', 'dhcp', 'unraid')"),
        ]},
}


_ORDER = re.compile(r"ORDER BY\s+(\d+|[a-z_]+)(\s+DESC)?", re.I)


def sql_order(sql: str, columns: list[str]) -> dict[str, Any] | None:
    """Column a table query sorts by (its last ORDER BY), so the page can mark it: {"k": "n", "dir": -1}."""
    m = _ORDER.findall(sql)
    if not m:
        return None
    col, desc = m[-1]
    if col.isdigit():
        col = columns[int(col) - 1] if 0 < int(col) <= len(columns) else ""
    return {"k": col, "dir": -1 if desc else 1} if col in columns else None


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
            if panel["type"] == "table" and out["rows"]:
                out["order"] = sql_order(sql, list(out["rows"][0]))
        except Exception as exc:  # noqa: BLE001 - one broken panel must not break the page
            out["rows"], out["error"] = [], str(exc)
        return out

    panels = await asyncio.gather(*(run(p) for p in spec["panels"]))
    return {"name": name, "title": spec["title"], "source": spec.get("source"), "step": step, "panels": panels}
