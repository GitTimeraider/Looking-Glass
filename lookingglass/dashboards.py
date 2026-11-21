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

from . import db, rollup
from .event_filter import LOCAL_NETS
from .parsers.filterlog import QFEEDS as QF

W = "ts > now() - make_interval(secs => $1)"
B = "to_timestamp(floor(extract(epoch FROM ts) / $2) * $2)"
PRIV = ("(src_ip << '10.0.0.0/8' OR src_ip << '172.16.0.0/12' OR src_ip << '192.168.0.0/16' "
        "OR src_ip << 'fc00::/7' OR src_ip << '100.64.0.0/10')")


# firewall log lines of the rules that use the CrowdSec aliases (Settings › OPNsense › Blocklist aliases, marked
# data.blocklist by the poller) - the plugin's own rules log only with Services › CrowdSec › Settings › "Enable log for
# rules". The rule names catch lines stored before the marking existed.
CS_FW = "(source = 'firewall' AND (lower(data->>'blocklist') = 'crowdsec' OR data->>'label' LIKE 'CrowdSec (%'))"
# CrowdSec events carry CrowdSec's own time (when it detected it), which can be long before Looking Glass pulled
# them (first pull, a restart): they count in the period they happened OR reached Looking Glass in. Few rows - the
# (source, ts) index narrows it to CrowdSec.
CS_SEEN = ("(source = 'crowdsec' AND (ts > now() - make_interval(secs => $1) "
           "OR received_at > now() - make_interval(secs => $1)))")
# one blocklist of that setting from the poller's snapshot (lower-case name)
BL = "(SELECT data->'{0}' FROM snapshots WHERE key = 'blocklists')"


# SWAG (swag.py): its nginx lines are source nginx with program swag; fail2ban has its own source; CrowdSec in Docker
# (crowdsec_lapi.py) is source crowdsec with program crowdsec-lapi; honeypot hits carry data.honeypot
SW = "(source = 'nginx' AND program = 'swag')"
SW_DRILL = {"source": "nginx", "program": "swag"}
SW_BLOCK = "action IN ('bouncer_block', 'waf_block', 'rate_limited')"
CSL = "(source = 'crowdsec' AND program = 'crowdsec-lapi')"
CSL_DRILL = {"source": "crowdsec", "program": "crowdsec-lapi"}
CSL_SEEN = f"({CS_SEEN} AND program = 'crowdsec-lapi')"
HP = "(source IN ('nginx', 'fail2ban') AND data->>'honeypot' = 'true')"
HP_DRILL = {"source": "nginx,fail2ban", "d_honeypot": "true"}
F2B_DRILL = {"source": "fail2ban"}
# a local source address - private, CGNAT, loopback (127.0.0.1: the SWAG host / container itself), link-local: the same
# as Event search's "Source: local" (and the honeypot alert's INTERNAL, which also counts Settings › Internal networks)
LOCAL_SRC = "(" + " OR ".join(f"src_ip << '{n}'" for n in LOCAL_NETS) + ")"


def cs_ban_now(ip: str) -> str:
    """SQL: the address ``ip`` (an inet expression) is banned by CrowdSec right now - a decision of CrowdSec in Docker
    or of the OPNsense plugin (their last poll) on that address or a range holding it."""
    return ("EXISTS (SELECT 1 FROM snapshots cs, jsonb_array_elements(CASE WHEN jsonb_typeof(cs.data) = 'array' THEN cs.data "
            "ELSE '[]'::jsonb END) d WHERE cs.key IN ('crowdsec_lapi_decisions', 'crowdsec_decisions') "
            "AND CASE WHEN lower(coalesce(d->>'scope', d->>'lg_scope', '')) IN ('ip', 'range') "
            f"THEN {ip} <<= coalesce(d->>'lg_value', d->>'value')::inet ELSE false END)")


def cs_ban_until(ip: str) -> str:
    """SQL: when the longest CrowdSec ban of ``ip`` in force ends (NULL: none)."""
    return ("(SELECT max(coalesce(d->>'until', d->>'lg_until'))::timestamptz FROM snapshots cs, jsonb_array_elements("
            "CASE WHEN jsonb_typeof(cs.data) = 'array' THEN cs.data ELSE '[]'::jsonb END) d "
            "WHERE cs.key IN ('crowdsec_lapi_decisions', 'crowdsec_decisions') "
            "AND CASE WHEN lower(coalesce(d->>'scope', d->>'lg_scope', '')) IN ('ip', 'range') "
            f"THEN {ip} <<= coalesce(d->>'lg_value', d->>'value')::inet ELSE false END)")


def cs_banned_in_period(ip: str) -> str:
    """SQL: CrowdSec decided a ban / captcha on ``ip`` in the period ($1 seconds) - for whatever scenario."""
    return ("EXISTS (SELECT 1 FROM events c WHERE c.source = 'crowdsec' AND c.action IN ('ban', 'captcha') "
            f"AND c.src_ip = {ip} AND c.ts > now() - make_interval(secs => $1))")
# fail2ban: per jail and address the latest ban / unban of the last 30 days - "banned now" when it is not an unban
F2B_STATE = ("(SELECT DISTINCT ON (data->>'jail', src_ip) data->>'jail' jail, src_ip, action, ts, src_country FROM events "
             "WHERE source = 'fail2ban' AND action IN ('ban', 'unban', 'restore_ban') AND src_ip IS NOT NULL "
             "AND ts > now() - interval '30 days' ORDER BY data->>'jail', src_ip, ts DESC)")


# Suricata alerts: eve "tls", "flow", "dns", ... records (eve syslog output) are not alerts
IDS = "(source = 'suricata' AND action IN ('alert', 'drop', 'blocked', 'reject'))"
IDS_DROP = "action IN ('drop', 'blocked')"
IDS_PRIO = "coalesce('priority ' || (data->>'priority'), '?')"
# Event search for Q-Feeds blocks (firewall log lines of its rules + the plugin's events, both tagged)
QF_DRILL = {"source": "firewall,qfeeds", "d_blocklist": "Q-Feeds"}
# Q-Feeds direction from the addresses: a LAN rule logs an outgoing connection as "in" (on the LAN interface)
QF_DIR = f"CASE WHEN {PRIV} THEN 'out' ELSE 'in' END"


def log_sql(where: str, limit: int = 150, extra: str = "") -> str:
    """A live log's query; ``extra``: one more condition (the live log's From filter)."""
    return (f"SELECT ts, source, action, host(src_ip) src_ip, src_port, host(dst_ip) dst_ip, dst_port, domain, "
            f"username, src_country, message FROM events WHERE {W} AND {where}{f' AND {extra}' if extra else ''} "
            f"ORDER BY ts DESC LIMIT {limit}")


def log_panel(where: str, title: str = "Live log", limit: int = 150) -> dict[str, Any]:
    return {"id": "log", "title": title, "type": "log", "span": 3, "where": where, "limit": limit,
            "sql": log_sql(where, limit)}


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
            log_panel("source = 'unbound'"),
            {"id": "long", "title": "Longest / unusual names (tunneling check)", "type": "table", "drill": {"by": {"domain": "domain", "ip": "client"}}, "cols": [["domain", "Domain"], ["client", "Client", "ip"], ["len", "Length", "num"]],
             "sql": f"SELECT domain, host(src_ip) client, max(length(domain)) len FROM events WHERE source = 'unbound' AND length(domain) > 50 AND {W} GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 25"},
        ]},
    "swag": {
        # SWAG on the Docker host (swag.py) and CrowdSec's Local API (crowdsec_lapi.py)
        "title": "SWAG & CrowdSec", "source": "nginx", "group": "swag",
        "tabs": [{"id": "web", "title": "Web (nginx)", "source": "nginx"},
                 {"id": "crowdsec", "title": "CrowdSec", "source": "crowdsec"},
                 {"id": "fail2ban", "title": "fail2ban", "source": "fail2ban", "needs": "fail2ban"},  # hidden without it
                 {"id": "honeypot", "title": "Honeypot", "source": "nginx,fail2ban"}],
        "panels": [
            # ------------------------------------------------------------------------------------------ Web ---
            {"id": "sw_kpi", "tab": "web", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) FILTER (WHERE action ~ '^http_') AS \"Requests\", "
                f"count(*) FILTER (WHERE action ~ '^http_4') AS \"4xx\", count(*) FILTER (WHERE action ~ '^http_5') AS \"5xx\", "
                f"count(DISTINCT src_ip) AS \"Clients\", "
                f"count(*) FILTER (WHERE jsonb_array_length(coalesce(data->'tags', '[]'::jsonb)) > 0) AS \"Attack / scanner requests\", "
                f"count(*) FILTER (WHERE action = 'bouncer_block') AS \"CrowdSec bouncer blocks\", "
                f"count(*) FILTER (WHERE action = 'waf_block') AS \"WAF (AppSec) blocks\", "
                f"count(*) FILTER (WHERE action = 'rate_limited') AS \"Rate limited\" "
                f"FROM events WHERE {SW} AND {W}",
             "drill": {"base": SW_DRILL, "tiles": {"4xx": {"status": "4xx"}, "5xx": {"status": "5xx"},
                                                   "Attack / scanner requests": {"tag": "any"},
                                                   "CrowdSec bouncer blocks": {"action": "bouncer_block"},
                                                   "WAF (AppSec) blocks": {"action": "waf_block"},
                                                   "Rate limited": {"action": "rate_limited"}}}},
            {"id": "sw_status", "tab": "web", "title": "Responses by class", "type": "timeseries", "span": 2,
             "drill": {"base": SW_DRILL},
             "sql": f"SELECT {B} t, CASE WHEN action ~ '^http_2' THEN '2xx' WHEN action ~ '^http_3' THEN '3xx' WHEN action ~ '^http_4' THEN '4xx' "
                    f"WHEN action ~ '^http_5' THEN '5xx' WHEN {SW_BLOCK} THEN 'blocked' ELSE 'other' END series, count(*) v "
                    f"FROM events WHERE {SW} AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "sw_codes", "tab": "web", "title": "Status codes", "type": "pie", "drill": {"base": SW_DRILL},
             "sql": f"SELECT replace(coalesce(action, '?'), 'http_', '') label, count(*) v, action f_action FROM events WHERE {SW} AND {W} GROUP BY 1, 3 ORDER BY 2 DESC LIMIT 10"},
            {"id": "sw_attacks", "tab": "web", "title": "Attack patterns over time", "type": "timeseries", "span": 2, "drill": {"base": SW_DRILL},
             "sql": f"SELECT {B} t, tag series, count(*) v FROM (SELECT ts, jsonb_array_elements_text(data->'tags') tag FROM events WHERE {SW} AND {W} AND jsonb_typeof(data->'tags') = 'array') x GROUP BY 1, 2 ORDER BY 1"},
            {"id": "sw_vhosts", "tab": "web", "title": "Sites (host names)", "type": "pie", "drill": {"base": SW_DRILL, "by": "domain"},
             "sql": f"SELECT coalesce(domain, '(not logged)') label, count(*) v FROM events WHERE {SW} AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 8"},
            {"id": "sw_paths", "tab": "web", "title": "Top paths", "type": "table", "drill": {"base": SW_DRILL},
             "cols": [["path", "Path"], ["n", "Requests", "num"], ["err", "Errors", "num"]],
             "sql": f"SELECT left(data->>'path', 120) path, count(*) n, count(*) FILTER (WHERE action ~ '^http_[45]') err, max(data->>'path') o_d_path FROM events WHERE {SW} AND data->>'path' IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 25"},
            {"id": "sw_404", "tab": "web", "title": "Top 4xx paths (probing)", "type": "table", "drill": {"base": SW_DRILL},
             "cols": [["path", "Path"], ["ips", "IPs", "num"], ["n", "Hits", "num"]],
             "sql": f"SELECT left(data->>'path', 120) path, count(DISTINCT src_ip) ips, count(*) n, max(data->>'path') o_d_path FROM events WHERE {SW} AND action ~ '^http_4' AND {W} GROUP BY 1 ORDER BY 3 DESC LIMIT 25"},
            {"id": "sw_clients", "tab": "web", "title": "Top clients", "type": "table", "drill": {"base": SW_DRILL, "by": {"ip": "ip"}},
             "cols": [["ip", "Client", "ip"], ["country", "", "flag"], ["err", "Errors", "num"], ["sus", "Suspicious", "num"],
                      ["blk", "Blocked", "num"], ["n", "Requests", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(src_ip) ip, max(src_country) country, count(*) FILTER (WHERE action ~ '^http_[45]') err, "
                    f"count(*) FILTER (WHERE jsonb_array_length(coalesce(data->'tags', '[]'::jsonb)) > 0) sus, "
                    f"count(*) FILTER (WHERE {SW_BLOCK}) blk, count(*) n, max(ts) last FROM events "
                    f"WHERE {SW} AND src_ip IS NOT NULL AND {W} GROUP BY 1 ORDER BY 6 DESC LIMIT 25"},
            {"id": "sw_blocked", "tab": "web", "title": "Blocked by CrowdSec / WAF / rate limit", "type": "table", "drill": {"base": {**SW_DRILL, "action": "bouncer_block,waf_block,rate_limited"}, "by": {"ip": "ip"}},
             "cols": [["ip", "Client", "ip"], ["country", "", "flag"], ["how", "How"], ["site", "Site"], ["n", "Blocks", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(src_ip) ip, max(src_country) country, string_agg(DISTINCT coalesce(data->>'by', action), ', ') how, "
                    f"max(domain) site, count(*) n, max(ts) last FROM events WHERE {SW} AND {SW_BLOCK} AND {W} GROUP BY 1 ORDER BY 5 DESC LIMIT 25"},
            {"id": "sw_ua", "tab": "web", "title": "Top user agents", "type": "table", "drill": {"base": SW_DRILL},
             "cols": [["ua", "User agent"], ["n", "Requests", "num"]],
             "sql": f"SELECT left(coalesce(data->>'user_agent', '-'), 120) ua, count(*) n, max(data->>'user_agent') o_d_user_agent FROM events WHERE {SW} AND action ~ '^http_' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 20"},
            {"id": "sw_countries", "tab": "web", "title": "Requests by country", "type": "hbar", "drill": {"base": SW_DRILL, "by": "country"},
             "sql": f"SELECT src_country label, count(*) v FROM events WHERE {SW} AND src_country IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 15"},
            {**log_panel(SW), "id": "sw_log", "tab": "web"},
            {"id": "sw_errors", "tab": "web", "title": "nginx errors and warnings", "type": "table", "span": 3, "drill": {"base": {**SW_DRILL, "action": "http_error"}},
             "cols": [["ts", "Last", "time"], ["level", "Level"], ["message", "Message"], ["n", "Count", "num"]],
             "sql": f"SELECT max(ts) ts, data->>'level' level, left(regexp_replace(message, '^\\d+#\\d+: (\\*\\d+ )?', ''), 200) message, count(*) n "
                    f"FROM events WHERE {SW} AND action = 'http_error' AND severity <= 4 AND {W} GROUP BY 2, 3 ORDER BY 1 DESC LIMIT 25"},
            # ------------------------------------------------------------------------------------- CrowdSec ---
            {"id": "csl_kpi", "tab": "crowdsec", "type": "stat", "span": 3, "sql":
                f"SELECT (SELECT count(*) FROM events WHERE {CSL_SEEN} AND action = 'alert') AS \"Alerts\", "
                f"(SELECT count(*) FROM events WHERE {CSL_SEEN} AND action = 'alert' AND data->>'appsec' = 'true') AS \"AppSec (WAF) alerts\", "
                "(SELECT jsonb_array_length(data) FROM snapshots WHERE key = 'crowdsec_lapi_decisions' AND jsonb_typeof(data) = 'array') AS \"Active decisions\", "
                f"(SELECT count(DISTINCT src_ip) FROM events WHERE {CSL_SEEN} AND action = 'alert') AS \"Attacking IPs\", "
                f"(SELECT count(DISTINCT data->>'scenario') FROM events WHERE {CSL_SEEN} AND action = 'alert') AS \"Scenarios\", "
                f"count(*) FILTER (WHERE action IN ('bouncer_block', 'waf_block')) AS \"Blocked in SWAG\", "
                "(SELECT (data->'appsec'->>'blocked')::numeric::bigint FROM snapshots WHERE key = 'crowdsec_lapi_metrics') AS \"AppSec blocked (since start)\" "
                f"FROM events WHERE {SW} AND {W}",
             "drill": {"tiles": {"Alerts": {**CSL_DRILL, "action": "alert", "hours": 24 * 90},
                                 "AppSec (WAF) alerts": {**CSL_DRILL, "action": "alert", "d_appsec": "true", "hours": 24 * 90},
                                 "Active decisions": {**CSL_DRILL, "action": "ban,captcha", "hours": 24 * 90},
                                 "Attacking IPs": {**CSL_DRILL, "action": "alert"}, "Scenarios": {**CSL_DRILL, "action": "alert"},
                                 "Blocked in SWAG": {**SW_DRILL, "action": "bouncer_block,waf_block"},
                                 "AppSec blocked (since start)": None}}},
            {"id": "csl_time", "tab": "crowdsec", "title": "CrowdSec over time", "type": "timeseries", "span": 2,
             "drill": {"series_drill": {"alerts": {**CSL_DRILL, "action": "alert"}, "decisions": {**CSL_DRILL, "action": "ban,captcha"},
                                        "blocked in SWAG": {**SW_DRILL, "action": "bouncer_block,waf_block"}}},
             "sql": f"SELECT {B} t, CASE WHEN source = 'nginx' THEN 'blocked in SWAG' WHEN action = 'alert' THEN 'alerts' ELSE 'decisions' END series, "
                    f"count(*) v FROM events WHERE ({CSL} OR ({SW} AND action IN ('bouncer_block', 'waf_block'))) AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "csl_scen", "tab": "crowdsec", "title": "Scenarios", "type": "pie", "drill": {"base": {**CSL_DRILL, "action": "alert"}, "by": "d_scenario"},
             "sql": f"SELECT coalesce(data->>'scenario', '?') label, count(*) v FROM events WHERE {CSL_SEEN} AND action = 'alert' GROUP BY 1 ORDER BY 2 DESC LIMIT 10"},
            {"id": "csl_ips", "tab": "crowdsec", "title": "Attackers", "type": "table", "span": 3, "drill": {"base": CSL_DRILL, "by": {"ip": "ip"}},
             "cols": [["ip", "IP", "ip"], ["country", "", "flag"], ["as", "Network (AS)"], ["scenarios", "Scenarios"], ["sites", "Sites"],
                      ["alerts", "Alerts", "num"], ["events", "Events", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(src_ip) ip, max(src_country) country, max(data->>'as') \"as\", string_agg(DISTINCT data->>'scenario', ', ') scenarios, "
                    f"string_agg(DISTINCT domain, ', ') sites, count(*) alerts, sum((data->>'events_count')::int) events, max(ts) last "
                    f"FROM events WHERE {CSL_SEEN} AND action = 'alert' AND src_ip IS NOT NULL GROUP BY 1 ORDER BY 6 DESC LIMIT 25"},
            # the bans in force (snapshot of the last poll): time left counts down in the browser; Unban deletes the
            # decision through the Local API (needs the machine login - "id" is empty without it, so no button)
            {"id": "csl_active", "tab": "crowdsec", "title": "Active bans (now)", "type": "table", "span": 3,
             "search": {"cols": ["value", "country", "scenario", "origin"], "placeholder": "Search IP, country, scenario…", "show": 200},
             "drill": {"base": {**CSL_DRILL, "hours": 24 * 90}},
             "cols": [["value", "Target"], ["country", "", "flag"], ["type", "Type"], ["scenario", "Scenario"], ["origin", "Origin"],
                      ["until", "Time left", "left"], ["id", "", "unban"]],
             "sql": "SELECT d->>'value' value, CASE WHEN lower(d->>'scope') IN ('ip', 'range') THEN split_part(d->>'value', '/', 1) END o_ip, "
                    "d->>'country' country, d->>'type' type, d->>'scenario' scenario, d->>'origin' origin, "
                    "(d->>'until')::timestamptz until, CASE WHEN (d->>'can_unban')::boolean THEN d->>'id' END id, 'lapi' unban_src "
                    "FROM snapshots s, jsonb_array_elements(CASE WHEN jsonb_typeof(s.data) = 'array' THEN s.data ELSE '[]'::jsonb END) d "
                    "WHERE s.key = 'crowdsec_lapi_decisions' AND $1 > 0 ORDER BY until DESC NULLS LAST LIMIT 5000"},
            {"id": "csl_countries", "tab": "crowdsec", "title": "Alerts by country", "type": "hbar", "drill": {"base": {**CSL_DRILL, "action": "alert"}, "by": "country"},
             "sql": f"SELECT src_country label, count(*) v FROM events WHERE {CSL_SEEN} AND action = 'alert' AND src_country IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 12"},
            {"id": "csl_appsec", "tab": "crowdsec", "title": "AppSec (WAF) and HTTP targets", "type": "table", "span": 3,
             "drill": {"base": {**CSL_DRILL, "action": "alert"}, "by": {"d_scenario": "scenario"}},
             "cols": [["scenario", "Scenario / rule"], ["uri", "Targets"], ["sites", "Sites"], ["ips", "IPs", "num"], ["n", "Alerts", "num"]],
             "sql": f"SELECT data->>'scenario' scenario, left(string_agg(DISTINCT u, ' · '), 300) uri, string_agg(DISTINCT domain, ', ') sites, "
                    f"count(DISTINCT src_ip) ips, count(DISTINCT id) n FROM events LEFT JOIN LATERAL "
                    f"jsonb_array_elements_text(CASE WHEN jsonb_typeof(data->'meta'->'target_uri') = 'array' THEN data->'meta'->'target_uri' ELSE '[]'::jsonb END) u ON true "
                    f"WHERE {CSL_SEEN} AND action = 'alert' AND (data ? 'meta') GROUP BY 1 ORDER BY 5 DESC LIMIT 25"},
            {"id": "csl_acq", "tab": "crowdsec", "title": "What CrowdSec reads (metrics, since its start)", "type": "table", "span": 3,
             "cols": [["source", "Log / source"], ["type", "Type"], ["read", "Lines read", "num"], ["parsed", "Parsed", "num"], ["unparsed", "Not parsed", "num"]],
             "sql": "SELECT a->>'source' source, a->>'type' type, (a->>'read')::numeric::bigint read, (a->>'parsed')::numeric::bigint parsed, "
                    "(a->>'unparsed')::numeric::bigint unparsed FROM snapshots s, jsonb_array_elements(CASE WHEN jsonb_typeof(s.data->'acquisition') = 'array' "
                    "THEN s.data->'acquisition' ELSE '[]'::jsonb END) a WHERE s.key = 'crowdsec_lapi_metrics' AND $1 > 0 ORDER BY 3 DESC LIMIT 30"},
            {**log_panel(f"({CSL} OR ({SW} AND action IN ('bouncer_block', 'waf_block')))"), "id": "csl_log", "tab": "crowdsec"},
            # ------------------------------------------------------------------------------------- fail2ban ---
            {"id": "f2b_kpi", "tab": "fail2ban", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) FILTER (WHERE action = 'ban') AS \"Bans\", count(*) FILTER (WHERE action = 'unban') AS \"Unbans\", "
                f"count(*) FILTER (WHERE action = 'found') AS \"Matches (Found)\", "
                f"count(DISTINCT src_ip) FILTER (WHERE action = 'ban') AS \"Banned IPs\", "
                f"(SELECT count(*) FROM {F2B_STATE} st WHERE action <> 'unban') AS \"Banned now\", "
                f"count(DISTINCT data->>'jail') FILTER (WHERE data ? 'jail') AS \"Active jails\" "
                f"FROM events WHERE source = 'fail2ban' AND {W}",
             "drill": {"base": F2B_DRILL, "tiles": {"Bans": {"action": "ban"}, "Unbans": {"action": "unban"},
                                                    "Matches (Found)": {"action": "found"}, "Banned IPs": {"action": "ban"},
                                                    "Banned now": {"action": "ban,restore_ban", "hours": 24 * 30}}}},
            {"id": "f2b_time", "tab": "fail2ban", "title": "Bans per jail", "type": "timeseries", "span": 2,
             "drill": {"base": {**F2B_DRILL, "action": "ban"}, "series": "d_jail"},
             "sql": f"SELECT {B} t, coalesce(data->>'jail', '?') series, count(*) v FROM events WHERE source = 'fail2ban' AND action = 'ban' AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "f2b_act", "tab": "fail2ban", "title": "What fail2ban did", "type": "pie", "drill": {"base": F2B_DRILL, "by": "action"},
             "sql": f"SELECT coalesce(action, 'other') label, count(*) v FROM events WHERE source = 'fail2ban' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 8"},
            {"id": "f2b_jails", "tab": "fail2ban", "title": "Jails", "type": "table", "span": 3, "drill": {"base": F2B_DRILL, "by": {"d_jail": "jail"}},
             "cols": [["jail", "Jail"], ["found", "Matches", "num"], ["bans", "Bans", "num"], ["ips", "Banned IPs", "num"], ["now", "Banned now", "num"], ["last", "Last ban", "ago"]],
             "sql": f"SELECT j.jail, count(*) FILTER (WHERE e.action = 'found') found, count(*) FILTER (WHERE e.action = 'ban') bans, "
                    f"count(DISTINCT e.src_ip) FILTER (WHERE e.action = 'ban') ips, "
                    f"(SELECT count(*) FROM {F2B_STATE} st WHERE st.jail = j.jail AND st.action <> 'unban') now, "
                    f"max(e.ts) FILTER (WHERE e.action = 'ban') last "
                    f"FROM (SELECT DISTINCT data->>'jail' jail FROM events WHERE source = 'fail2ban' AND data ? 'jail' AND ts > now() - interval '30 days') j "
                    f"LEFT JOIN events e ON e.source = 'fail2ban' AND e.data->>'jail' = j.jail AND e.ts > now() - make_interval(secs => $1) "
                    f"GROUP BY 1 ORDER BY 3 DESC, 2 DESC LIMIT 40"},
            {"id": "f2b_now", "tab": "fail2ban", "title": "Banned now", "type": "table", "span": 2, "drill": {"base": F2B_DRILL, "by": {"ip": "ip"}},
             "cols": [["ip", "IP", "ip"], ["country", "", "flag"], ["jail", "Jail"], ["since", "Since", "time"]],
             "sql": f"SELECT host(src_ip) ip, src_country country, jail, ts since FROM {F2B_STATE} st WHERE action <> 'unban' AND $1 > 0 ORDER BY ts DESC LIMIT 50"},
            {"id": "f2b_countries", "tab": "fail2ban", "title": "Banned by country", "type": "hbar", "drill": {"base": {**F2B_DRILL, "action": "ban"}, "by": "country"},
             "sql": f"SELECT src_country label, count(*) v FROM events WHERE source = 'fail2ban' AND action = 'ban' AND src_country IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 12"},
            {"id": "f2b_ips", "tab": "fail2ban", "title": "Top offenders", "type": "table", "span": 3, "drill": {"base": F2B_DRILL, "by": {"ip": "ip"}},
             "cols": [["ip", "IP", "ip"], ["country", "", "flag"], ["jails", "Jails"], ["found", "Matches", "num"], ["bans", "Bans", "num"],
                      ["web", "Web requests", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(e.src_ip) ip, max(e.src_country) country, string_agg(DISTINCT e.data->>'jail', ', ') jails, "
                    f"count(*) FILTER (WHERE e.action = 'found') found, count(*) FILTER (WHERE e.action = 'ban') bans, "
                    f"(SELECT count(*) FROM events w WHERE w.src_ip = e.src_ip AND {SW.replace('source', 'w.source').replace('program', 'w.program')} "
                    f"AND w.ts > now() - make_interval(secs => $1)) web, max(e.ts) last "
                    f"FROM events e WHERE e.source = 'fail2ban' AND e.src_ip IS NOT NULL AND e.action IN ('found', 'ban') "
                    f"AND e.ts > now() - make_interval(secs => $1) GROUP BY e.src_ip ORDER BY 5 DESC, 4 DESC LIMIT 25"},
            {**log_panel("source = 'fail2ban' AND action IS NOT NULL"), "id": "f2b_log", "tab": "fail2ban"},
            # ------------------------------------------------------------------------------------- Honeypot ---
            {"id": "hp_kpi", "tab": "honeypot", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) AS \"Hits\", count(DISTINCT src_ip) AS \"IPs\", count(DISTINCT src_country) AS \"Countries\", "
                f"count(DISTINCT src_ip) FILTER (WHERE {LOCAL_SRC}) AS \"From inside\", "
                # who touched it and got banned: by CrowdSec (any scenario, in the period / in force now), by fail2ban jails
                f"(SELECT count(*) FROM (SELECT DISTINCT src_ip FROM events WHERE {HP} AND {W} AND src_ip IS NOT NULL) h "
                f"WHERE {cs_banned_in_period('h.src_ip')} OR {cs_ban_now('h.src_ip')}) AS \"Banned by CrowdSec\", "
                f"(SELECT count(*) FROM (SELECT DISTINCT src_ip FROM events WHERE {HP} AND {W} AND src_ip IS NOT NULL) h "
                f"WHERE {cs_ban_now('h.src_ip')}) AS \"Banned now\", "
                f"count(*) FILTER (WHERE source = 'fail2ban' AND action = 'ban') AS \"Bans by honeypot jails\", "
                "(SELECT count(*) FROM alerts WHERE status = 'open' AND rule = 'honeypot') AS \"Open honeypot alerts\" "
                f"FROM events WHERE {HP} AND {W}",
             "needs_cols": {"Bans by honeypot jails": "fail2ban", "Banned by CrowdSec": "crowdsec", "Banned now": "crowdsec"},
             "drill": {"base": HP_DRILL, "tiles": {"From inside": {"src_scope": "local"}, "Bans by honeypot jails": {"source": "fail2ban", "d_honeypot": "true", "action": "ban"},
                                                   "Banned by CrowdSec": None, "Banned now": {"url": "/dash/swag#crowdsec"},
                                                   "Open honeypot alerts": {"url": "/alerts"}}}},
            {"id": "hp_time", "tab": "honeypot", "title": "Honeypot hits over time", "type": "timeseries", "span": 3, "drill": {"base": HP_DRILL},
             "sql": f"SELECT {B} t, CASE WHEN source = 'fail2ban' THEN 'fail2ban ' || coalesce(action, '') ELSE 'web requests' END series, count(*) v "
                    f"FROM events WHERE {HP} AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "hp_ips", "tab": "honeypot", "title": "Who touched the honeypot", "type": "table", "span": 3, "drill": {"base": HP_DRILL, "by": {"ip": "ip"}},
             "cols": [["ip", "IP", "ip"], ["country", "", "flag"], ["hits", "Hits", "num"], ["paths", "Paths"], ["ua", "User agent"],
                      ["other", "Other requests", "num"], ["cs", "CrowdSec"], ["cs_until", "Ban ends", "left"],
                      ["first", "First", "time"], ["last", "Last", "ago"]],
             "sql": "SELECT ip, country, hits, paths, ua, other, CASE WHEN cs_until IS NOT NULL OR banned_now THEN 'banned now' "
                    "WHEN banned THEN 'banned' END cs, cs_until, first, last FROM ("
                    "SELECT host(h.src_ip) ip, max(h.src_country) country, count(*) hits, left(string_agg(DISTINCT h.data->>'path', ' · '), 200) paths, "
                    "left(max(h.data->>'user_agent'), 100) ua, (SELECT count(*) FROM events o WHERE o.src_ip = h.src_ip AND o.source = 'nginx' "
                    "AND coalesce(o.data->>'honeypot', '') <> 'true' AND o.ts > now() - make_interval(secs => $1)) other, "
                    f"{cs_ban_until('h.src_ip')} cs_until, {cs_ban_now('h.src_ip')} banned_now, {cs_banned_in_period('h.src_ip')} banned, "
                    "min(h.ts) first, max(h.ts) last "
                    "FROM events h WHERE h.source IN ('nginx', 'fail2ban') AND h.data->>'honeypot' = 'true' AND h.src_ip IS NOT NULL "
                    "AND h.ts > now() - make_interval(secs => $1) GROUP BY h.src_ip ORDER BY 3 DESC LIMIT 50) x ORDER BY hits DESC"},
            {"id": "hp_paths", "tab": "honeypot", "title": "Trap paths hit", "type": "hbar", "drill": {"base": HP_DRILL},
             "sql": f"SELECT left(coalesce(data->>'path', data->>'jail', '?'), 80) label, count(*) v FROM events WHERE {HP} AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 15"},
            {"id": "hp_countries", "tab": "honeypot", "title": "By country", "type": "hbar", "drill": {"base": HP_DRILL, "by": "country"},
             "sql": f"SELECT src_country label, count(*) v FROM events WHERE {HP} AND src_country IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 12"},
            {"id": "hp_ua", "tab": "honeypot", "title": "User agents", "type": "table", "drill": {"base": HP_DRILL},
             "cols": [["ua", "User agent"], ["n", "Hits", "num"]],
             "sql": f"SELECT left(coalesce(data->>'user_agent', '-'), 120) ua, count(*) n FROM events WHERE {HP} AND source = 'nginx' AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 20"},
            {**log_panel(HP), "id": "hp_log", "tab": "honeypot"},
        ]},
    "threats": {
        # one page, four tabs: Main = all three sources together, then one tab per source (see run_dashboard)
        "title": "Threats", "source": "suricata,crowdsec,qfeeds", "group": "opnsense",
        "tabs": [{"id": "main", "title": "Main", "source": "suricata,crowdsec,qfeeds"},
                 {"id": "crowdsec", "title": "CrowdSec", "source": "crowdsec", "needs": "crowdsec"},
                 {"id": "qfeeds", "title": "Q-Feeds", "source": "qfeeds", "needs": "qfeeds"},
                 {"id": "suricata", "title": "Suricata", "source": "suricata", "needs": "suricata"}],
        "panels": [
            # ------------------------------------------------------------------------------------------ Main ---
            {"id": "kpi", "tab": "main", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) FILTER (WHERE {IDS}) AS \"Suricata alerts\", "
                f"count(*) FILTER (WHERE {IDS} AND {IDS_DROP}) AS \"Suricata dropped\", "
                f"(SELECT count(*) FROM events WHERE {CS_SEEN} AND action = 'alert') AS \"CrowdSec alerts\", "
                # active now (the API lists the current ones): a ban older than the period still counts
                "(SELECT sum(jsonb_array_length(data))::bigint FROM snapshots WHERE key IN ('crowdsec_decisions', 'crowdsec_lapi_decisions') "
                "AND jsonb_typeof(data) = 'array') AS \"CrowdSec active decisions\", "
                f"count(*) FILTER (WHERE {CS_FW}) AS \"CrowdSec firewall blocks\", "
                f"count(*) FILTER (WHERE {QF}) AS \"Q-Feeds hits\", "
                f"count(*) FILTER (WHERE {QF} AND {PRIV}) AS \"Outbound threat-intel hits\", "
                f"(SELECT count(*) FROM alerts WHERE status = 'open' AND severity IN ('high', 'critical')) AS \"Open high/critical alerts\" "
                f"FROM events WHERE (source IN ('suricata', 'crowdsec') OR {CS_FW} OR {QF}) AND {W}",
             "drill": {"tiles": {"Suricata alerts": {"source": "suricata", "action": "alert,drop,blocked,reject"},
                                 "Suricata dropped": {"source": "suricata", "action": "drop,blocked"},
                                 "CrowdSec alerts": {"source": "crowdsec", "action": "alert", "hours": 24 * 90},
                                 "CrowdSec active decisions": {"source": "crowdsec", "action": "ban,captcha", "hours": 24 * 90},
                                 "CrowdSec firewall blocks": {"source": "firewall", "d_blocklist": "CrowdSec"},
                                 "Q-Feeds hits": QF_DRILL, "Outbound threat-intel hits": QF_DRILL,
                                 "Open high/critical alerts": {"url": "/alerts"}}},
             # tiles of a source that is switched off (and has no data in the period) are left out, see run_dashboard
             "needs_cols": {"Suricata alerts": "suricata", "Suricata dropped": "suricata", "CrowdSec alerts": "crowdsec",
                            "CrowdSec active decisions": "crowdsec", "CrowdSec firewall blocks": "crowdsec",
                            "Q-Feeds hits": "qfeeds", "Outbound threat-intel hits": "qfeeds"}},
            # CrowdSec = its own detections + the blocks of the rules using its aliases (firewall log lines)
            {"id": "src", "tab": "main", "title": "Threat events by source", "type": "timeseries", "span": 2,
             "drill": {"series": "source", "series_drill": {"crowdsec": {"source": "firewall", "d_blocklist": "CrowdSec"}, "qfeeds": QF_DRILL}},
             "sql": f"SELECT {B} t, CASE WHEN {QF} THEN 'qfeeds' WHEN source = 'firewall' THEN 'crowdsec' ELSE source END series, "
                    f"count(*) v FROM events WHERE ({IDS} OR source = 'crowdsec' OR {CS_FW} OR {QF}) AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "blk", "tab": "main", "title": "Blocks per source", "type": "bar", "drill": {"base": {"source": ""}},
             "sql": f"SELECT 'Suricata (dropped)' label, count(*) FILTER (WHERE {IDS} AND {IDS_DROP}) v, "
                    f"'suricata' o_source, 'drop,blocked' o_action, NULL o_d_blocklist FROM events WHERE source = 'suricata' AND {W} "
                    f"UNION ALL SELECT 'CrowdSec (firewall)', count(*), 'firewall', NULL, 'CrowdSec' FROM events WHERE {CS_FW} AND {W} "
                    f"UNION ALL SELECT 'Q-Feeds', count(*), 'firewall,qfeeds', NULL, 'Q-Feeds' FROM events WHERE {QF} AND {W}"},
            {"id": "alerts", "tab": "main", "title": "Alerts by rule", "type": "pie", "drill": {"url": "/alerts"},
             "sql": "SELECT rule label, count(*) v FROM alerts WHERE last_seen > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC LIMIT 10"},
            {"id": "sev", "tab": "main", "title": "Alerts over time by severity", "type": "timeseries", "span": 2, "drill": {"url": "/alerts"},
             "sql": "SELECT to_timestamp(floor(extract(epoch FROM created_at) / $2) * $2) t, severity series, count(*) v FROM alerts WHERE created_at > now() - make_interval(secs => $1) GROUP BY 1, 2 ORDER BY 1"},
            {**log_panel(f"({IDS} OR source = 'crowdsec' OR {QF})"), "tab": "main"},
            {"id": "attackers", "tab": "main", "title": "Top attackers across all sources", "type": "table", "span": 3, "drill": {"base": {"source": ""}, "by": {"ip": "ip"}},
             "cols": [["ip", "IP", "ip"], ["country", "", "flag"], ["sources", "Seen by"], ["n", "Events", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(src_ip) ip, max(src_country) country, array_agg(DISTINCT source) sources, count(*) n, max(ts) last FROM events WHERE {W} AND src_ip IS NOT NULL AND NOT {PRIV} AND ({IDS} OR source IN ('crowdsec', 'qfeeds') OR action IN ('block', 'login_failed', 'waf_block')) GROUP BY 1 ORDER BY 4 DESC LIMIT 25"},
            {"id": "blocklists", "tab": "main", "title": "Blocklists (Settings › OPNsense › Blocklist aliases)", "type": "table", "span": 3,
             "drill": {"base": {"source": "firewall"}, "by": {"d_blocklist": "name"}},
             "cols": [["name", "Blocklist"], ["aliases", "Aliases"], ["size", "Addresses", "num"], ["rules", "Rules", "num"],
                      ["packets", "Blocked packets", "num"], ["logged", "Logged blocks", "num"]],
             "sql": "SELECT b.value->>'name' name, (SELECT string_agg(a, ', ') FROM jsonb_array_elements_text(b.value->'aliases') a) aliases, "
                    "(b.value->>'size')::bigint size, coalesce(nullif(jsonb_array_length(coalesce(b.value->'rids', '[]')), 0), "
                    "jsonb_array_length(coalesce(b.value->'rules', '[]'))) rules, "
                    "(b.value->>'packets')::bigint packets, (SELECT count(*) FROM events e WHERE e.source = 'firewall' "
                    "AND lower(e.data->>'blocklist') = lower(b.value->>'name') AND e.ts > now() - make_interval(secs => $1)) logged "
                    "FROM snapshots s, jsonb_each(CASE WHEN jsonb_typeof(s.data) = 'object' THEN s.data ELSE '{}'::jsonb END) b "
                    "WHERE s.key = 'blocklists' ORDER BY 1"},
            # -------------------------------------------------------------------------------------- CrowdSec ---
            {"id": "cs_kpi", "tab": "crowdsec", "type": "stat", "span": 3, "sql":
                f"SELECT (SELECT count(*) FROM events WHERE {CS_SEEN} AND action = 'alert') AS \"Alerts\", "
                "(SELECT sum(jsonb_array_length(data))::bigint FROM snapshots WHERE key IN ('crowdsec_decisions', 'crowdsec_lapi_decisions') "
                "AND jsonb_typeof(data) = 'array') AS \"Active decisions\", "
                f"count(*) AS \"Firewall blocks\", count(DISTINCT CASE WHEN direction = 'out' THEN dst_ip ELSE src_ip END) AS \"Blocked IPs\", "
                f"({BL.format('crowdsec')}->>'size')::bigint AS \"Blocklist IPs\", "
                f"({BL.format('crowdsec')}->>'packets')::bigint AS \"Blocked packets (since rules loaded)\" "
                f"FROM events WHERE {CS_FW} AND {W}",
             "drill": {"tiles": {"Alerts": {"source": "crowdsec", "action": "alert", "hours": 24 * 90},
                                 "Active decisions": {"source": "crowdsec", "action": "ban,captcha", "hours": 24 * 90},
                                 "Firewall blocks": {"source": "firewall", "d_blocklist": "CrowdSec"},
                                 "Blocked IPs": {"source": "firewall", "d_blocklist": "CrowdSec"},
                                 "Blocklist IPs": None, "Blocked packets (since rules loaded)": None}}},
            # the decisions CrowdSec holds now (snapshot of the last pull, rows normalised by crowdsec_ban_row); "ends"
            # counts down in the browser, the unban column deletes the decision on OPNsense (POST /api/crowdsec/unban)
            {"id": "cs_bans", "tab": "crowdsec", "title": "Active bans", "type": "table", "span": 3, "needs": "crowdsec",
             "search": {"cols": ["ip", "country", "reason", "origin"], "placeholder": "Search IP, country, reason…", "show": 200},
             "drill": {"base": {"source": "crowdsec", "hours": 24 * 90}},
             "cols": [["ip", "IP / value", "ip"], ["country", "", "flag"], ["type", "Type"], ["reason", "Reason"],
                      ["origin", "Origin"], ["ends", "Time left", "left"], ["id", "", "unban"]],
             "sql": "SELECT d->>'id' id, d->>'lg_ip' o_ip, coalesce(d->>'lg_ip', d->>'lg_value', d->>'scope_value') ip, d->>'country' country, "
                    "coalesce(d->>'action', d->>'type', 'ban') \"type\", coalesce(d->>'reason', d->>'scenario') reason, "
                    "coalesce(d->>'source', d->>'origin') origin, d->>'lg_until' ends, 'opnsense' unban_src "
                    "FROM snapshots s, jsonb_array_elements(CASE WHEN jsonb_typeof(s.data) = 'array' THEN s.data ELSE '[]'::jsonb END) d "
                    "WHERE s.key = 'crowdsec_decisions' AND $1::float8 IS NOT NULL ORDER BY ends DESC NULLS LAST LIMIT 5000"},
            {"id": "cs_time", "tab": "crowdsec", "title": "CrowdSec over time", "type": "timeseries", "span": 3,
             "drill": {"series_drill": {"firewall blocks": {"source": "firewall", "d_blocklist": "CrowdSec"},
                                        "alerts": {"source": "crowdsec", "action": "alert"}, "decisions": {"source": "crowdsec", "action": "ban,captcha"}}},
             "sql": f"SELECT {B} t, CASE WHEN source = 'firewall' THEN 'firewall blocks' WHEN action = 'alert' THEN 'alerts' "
                    f"ELSE 'decisions' END series, count(*) v FROM events WHERE (source = 'crowdsec' OR {CS_FW}) AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "cs_dir", "tab": "crowdsec", "title": "Blocked direction", "type": "pie",
             "drill": {"base": {"source": "firewall", "d_blocklist": "CrowdSec"}, "by": "direction"},
             "sql": f"SELECT coalesce(direction, '?') label, count(*) v FROM events WHERE {CS_FW} AND {W} GROUP BY 1 ORDER BY 2 DESC"},
            {"id": "csfw", "tab": "crowdsec", "title": "Blocked by the CrowdSec blocklist", "type": "table", "span": 3, "needs": "crowdsec",
             "drill": {"base": {"source": "firewall", "d_blocklist": "CrowdSec"}, "by": {"ip": "ip"}},
             "cols": [["ip", "IP", "ip"], ["country", "", "flag"], ["dir", "Dir"], ["n", "Blocks", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(CASE WHEN direction = 'out' THEN dst_ip ELSE src_ip END) ip, "
                    f"max(CASE WHEN direction = 'out' THEN dst_country ELSE src_country END) country, "
                    f"coalesce(direction, '?') dir, count(*) n, max(ts) last "
                    f"FROM events WHERE {CS_FW} AND {W} GROUP BY 1, 3 ORDER BY 4 DESC LIMIT 25"},
            {"id": "cs_countries", "tab": "crowdsec", "title": "Blocked by country", "type": "hbar",
             "drill": {"base": {"source": "firewall", "d_blocklist": "CrowdSec"}, "by": "country"},
             "sql": f"SELECT src_country label, count(*) v FROM events WHERE {CS_FW} AND src_country IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 12"},
            {"id": "cs_ports", "tab": "crowdsec", "title": "Ports they tried", "type": "hbar", "fill_md": True,
             "drill": {"base": {"source": "firewall", "d_blocklist": "CrowdSec"}, "by": "port"},
             "sql": f"SELECT dst_port::text label, count(*) v FROM events WHERE {CS_FW} AND dst_port IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 12"},
            {**log_panel(f"(source = 'crowdsec' OR {CS_FW})"), "id": "cs_log", "tab": "crowdsec"},
            # --------------------------------------------------------------------------------------- Q-Feeds ---
            {"id": "qf_kpi", "tab": "qfeeds", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) AS \"Hits\", count(*) FILTER (WHERE NOT {PRIV}) AS \"Inbound\", "
                f"count(*) FILTER (WHERE {PRIV}) AS \"Outbound\", "
                f"count(DISTINCT CASE WHEN {PRIV} THEN dst_ip ELSE src_ip END) AS \"Threat IPs\", "
                f"count(DISTINCT src_ip) FILTER (WHERE {PRIV}) AS \"Internal hosts\", "
                f"({BL.format('q-feeds')}->>'size')::bigint AS \"Blocklist IPs\" "
                f"FROM events WHERE {QF} AND {W}",
             "drill": {"base": QF_DRILL, "tiles": {"Blocklist IPs": None}}},
            {"id": "qf_time", "tab": "qfeeds", "title": "Q-Feeds hits over time", "type": "timeseries", "span": 3,
             "drill": {"base": QF_DRILL},
             "sql": f"SELECT {B} t, CASE WHEN {PRIV} THEN 'outbound' ELSE 'inbound' END series, count(*) v FROM events "
                    f"WHERE {QF} AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "qf_iface", "tab": "qfeeds", "title": "Interfaces", "type": "pie", "drill": {"base": QF_DRILL, "by": "iface"},
             "sql": f"SELECT coalesce(interface, '?') label, count(*) v FROM events WHERE {QF} AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 8"},
            {"id": "qf", "tab": "qfeeds", "title": "Q-Feeds matches", "type": "table", "span": 3, "needs": "qfeeds",
             "drill": {"base": QF_DRILL, "by": {"src": "src", "dst": "dst"}},
             "cols": [["src", "Source", "ip"], ["dst", "Destination", "ip"], ["dir", "Dir"], ["port", "Port"], ["n", "Hits", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(src_ip) src, host(dst_ip) dst, {QF_DIR} dir, dst_port port, count(*) n, max(ts) last "
                    f"FROM events WHERE {QF} AND {W} GROUP BY 1, 2, 3, 4 ORDER BY 5 DESC LIMIT 25"},
            {"id": "qf_internal", "tab": "qfeeds", "title": "Internal hosts contacting listed addresses", "type": "table",
             "drill": {"base": QF_DRILL, "by": {"src": "ip"}},
             "cols": [["ip", "Host", "ip"], ["dsts", "Listed IPs", "num"], ["n", "Hits", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(src_ip) ip, count(DISTINCT dst_ip) dsts, count(*) n, max(ts) last FROM events "
                    f"WHERE {QF} AND {PRIV} AND {W} GROUP BY 1 ORDER BY 3 DESC LIMIT 25"},
            {"id": "qf_ports", "tab": "qfeeds", "title": "Destination ports", "type": "hbar", "fill_md": True, "drill": {"base": QF_DRILL, "by": "port"},
             "sql": f"SELECT dst_port::text label, count(*) v FROM events WHERE {QF} AND dst_port IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 12"},
            {**log_panel(QF), "id": "qf_log", "tab": "qfeeds"},
            # -------------------------------------------------------------------------------------- Suricata ---
            {"id": "ids_kpi", "tab": "suricata", "type": "stat", "span": 3, "sql":
                f"SELECT count(*) FILTER (WHERE {IDS}) AS \"Alerts\", "
                f"count(*) FILTER (WHERE {IDS} AND {IDS_DROP}) AS \"Dropped (IPS)\", "
                f"count(*) FILTER (WHERE {IDS} AND data->>'priority' = '1') AS \"Priority 1\", "
                f"count(DISTINCT message) FILTER (WHERE {IDS}) AS \"Signatures\", "
                f"count(DISTINCT src_ip) FILTER (WHERE {IDS}) AS \"Source IPs\", "
                f"count(DISTINCT src_ip) FILTER (WHERE {IDS} AND {PRIV}) AS \"Internal hosts alerting\", "
                f"count(*) FILTER (WHERE action = 'tls') AS \"TLS records\", "
                "(SELECT count(*) FROM alerts WHERE status = 'open' AND rule = 'ids') AS \"Open Suricata alerts\" "
                f"FROM events WHERE source = 'suricata' AND {W}",
             "drill": {"tiles": {"Alerts": {"action": "alert,drop,blocked,reject"}, "Dropped (IPS)": {"action": "drop,blocked"},
                                 "Priority 1": {"d_priority": "1"}, "Signatures": {"action": "alert,drop,blocked,reject"},
                                 "Source IPs": {"action": "alert,drop,blocked,reject"},
                                 "TLS records": {"action": "tls"}, "Open Suricata alerts": {"url": "/alerts"}}}},
            {"id": "ids_time", "tab": "suricata", "title": "Alerts over time by priority", "type": "timeseries", "span": 2,
             "drill": {"base": {"action": "alert,drop,blocked,reject"}},
             "sql": f"SELECT {B} t, {IDS_PRIO} series, count(*) v FROM events WHERE {IDS} AND {W} GROUP BY 1, 2 ORDER BY 1"},
            {"id": "ids_act", "tab": "suricata", "title": "Alerted vs dropped", "type": "pie", "drill": {"by": "action"},
             "sql": f"SELECT action label, count(*) v FROM events WHERE {IDS} AND {W} GROUP BY 1 ORDER BY 2 DESC"},
            {"id": "ids_cls", "tab": "suricata", "title": "Classifications", "type": "pie",
             "sql": f"SELECT coalesce(data->>'classification', data->>'category', '?') label, count(*) v, data->>'classification' o_d_classification, data->>'category' o_d_category FROM events WHERE {IDS} AND {W} GROUP BY 1, 3, 4 ORDER BY 2 DESC LIMIT 10"},
            {"id": "ids_app", "tab": "suricata", "title": "Application protocols", "type": "hbar", "drill": {"by": "d_app_proto"},
             "sql": f"SELECT coalesce(data->>'app_proto', proto, '?') label, count(*) v FROM events WHERE {IDS} AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 12"},
            {"id": "ids_countries", "tab": "suricata", "title": "Source countries", "type": "hbar", "drill": {"by": "country"},
             "sql": f"SELECT src_country label, count(*) v FROM events WHERE {IDS} AND src_country IS NOT NULL AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 12"},
            {"id": "ids_sigs", "tab": "suricata", "title": "Signatures", "type": "table", "span": 2,
             "drill": {"by": {"q": "sig"}},
             "cols": [["sig", "Signature"], ["sid", "SID"], ["prio", "Prio"], ["cls", "Classification"], ["srcs", "Srcs", "num"],
                      ["dropped", "Dropped", "num"], ["n", "Hits", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT message sig, max(data->>'sid') sid, min(data->>'priority') prio, "
                    f"max(coalesce(data->>'classification', data->>'category')) cls, count(DISTINCT src_ip) srcs, "
                    f"count(*) FILTER (WHERE {IDS_DROP}) dropped, count(*) n, max(ts) last "
                    f"FROM events WHERE {IDS} AND {W} GROUP BY 1 ORDER BY 7 DESC LIMIT 50"},
            {"id": "ids_iface", "tab": "suricata", "title": "Interfaces", "type": "pie", "drill": {"by": "iface"},
             "sql": f"SELECT coalesce(interface, '?') label, count(*) v FROM events WHERE {IDS} AND {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 8"},
            # the live log high up, right below the overview - before the top lists and the TLS tables
            {**log_panel(IDS), "id": "ids_log", "tab": "suricata"},
            {"id": "ids_src", "tab": "suricata", "title": "Top sources", "type": "table", "drill": {"by": {"src": "ip"}},
             "cols": [["ip", "Source", "ip"], ["country", "", "flag"], ["sigs", "Sigs", "num"], ["n", "Hits", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(src_ip) ip, max(src_country) country, count(DISTINCT message) sigs, count(*) n, max(ts) last "
                    f"FROM events WHERE {IDS} AND src_ip IS NOT NULL AND {W} GROUP BY 1 ORDER BY 4 DESC LIMIT 25"},
            {"id": "ids_dst", "tab": "suricata", "title": "Targeted hosts & ports", "type": "table", "drill": {"by": {"dst": "ip", "port": "port"}},
             "cols": [["ip", "Destination", "ip"], ["port", "Port"], ["proto", "Proto"], ["srcs", "Sources", "num"], ["n", "Hits", "num"]],
             "sql": f"SELECT host(dst_ip) ip, dst_port port, proto, count(DISTINCT src_ip) srcs, count(*) n "
                    f"FROM events WHERE {IDS} AND dst_ip IS NOT NULL AND {W} GROUP BY 1, 2, 3 ORDER BY 5 DESC LIMIT 25"},
            {"id": "ids_internal", "tab": "suricata", "title": "Internal hosts triggering alerts", "type": "table", "drill": {"by": {"src": "ip"}},
             "cols": [["ip", "Host", "ip"], ["sigs", "Sigs", "num"], ["dsts", "Peers", "num"], ["n", "Hits", "num"], ["last", "Last", "ago"]],
             "sql": f"SELECT host(src_ip) ip, count(DISTINCT message) sigs, count(DISTINCT dst_ip) dsts, count(*) n, max(ts) last "
                    f"FROM events WHERE {IDS} AND {PRIV} AND {W} GROUP BY 1 ORDER BY 4 DESC LIMIT 25"},
            {"id": "ids_ja", "tab": "suricata", "title": "TLS client fingerprints (JA3 / JA4)", "type": "table",
             "drill": {"base": {"action": "tls"}, "by": {"d_ja3": "ja3"}},
             "cols": [["ja4", "JA4"], ["ja3", "JA3"], ["clients", "Clients", "num"], ["n", "Records", "num"]],
             "sql": f"SELECT data->>'ja4' ja4, data->>'ja3' ja3, count(DISTINCT src_ip) clients, count(*) n FROM events "
                    f"WHERE source = 'suricata' AND action = 'tls' AND {W} GROUP BY 1, 2 ORDER BY 4 DESC LIMIT 25"},
            {"id": "ids_sni", "tab": "suricata", "title": "TLS server names (SNI)", "type": "table",
             "drill": {"base": {"action": "tls"}, "by": {"domain": "sni"}},
             "cols": [["sni", "Server name"], ["clients", "Clients", "num"], ["n", "Records", "num"]],
             "sql": f"SELECT domain sni, count(DISTINCT src_ip) clients, count(*) n FROM events "
                    f"WHERE source = 'suricata' AND action = 'tls' AND domain IS NOT NULL AND {W} GROUP BY 1 ORDER BY 3 DESC LIMIT 25"},
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


async def run_log(name: str, panel_id: str, hours: float, scope: str) -> list[dict[str, Any]]:
    """One live log of a dashboard with only local / only non-local (``public``) source addresses: the newest events
    of that kind, not the unfiltered log with some rows hidden. KeyError: no such live log."""
    from .event_filter import src_scope_sql

    panel = next((p for p in DASHBOARDS[name]["panels"] if p["id"] == panel_id and p["type"] == "log"), None)
    if panel is None:
        raise KeyError(panel_id)
    args: list[Any] = [hours * 3600]

    def arg(v: Any) -> str:
        args.append(v)
        return f"${len(args)}"

    sql = log_sql(panel["where"], panel["limit"], src_scope_sql(scope, arg))
    async with db.heavy(hours), db.pool().acquire() as conn:
        return db.records(await conn.fetch(sql, *args))


def step_for(hours: float) -> int:
    """Chart bucket size: about 60 bars. From 2 days on whole hours (7 days: 3 h, 30 days: 12 h), so charts can be
    drawn from the hourly counts."""
    step = max(60, int(hours * 3600 / 60))
    return -(-step // 3600) * 3600 if hours >= rollup.MIN_HOURS else step


# panels that only count events per source / action / protocol / interface / direction / port / country / severity:
# over 2+ days they read the hourly counts (rollup.py) - same numbers, a fraction of the work
ROLLUP_PANELS = {("firewall", "actions"), ("firewall", "proto"), ("firewall", "iface"), ("firewall", "dir"),
                 ("firewall", "ports"), ("firewall", "countries"), ("firewall", "hour"), ("dns", "q"),
                 ("auth", "ts"), ("vpn", "vpnev"),
                 ("syslog", "sev"), ("threats", "ids_act"), ("threats", "ids_countries"),
                 ("threats", "ids_iface")}


async def run_dashboard(name: str, hours: float, off: set[str] | frozenset[str] = frozenset(),
                        tab: str | None = None) -> dict[str, Any]:
    """``off``: optional sources (suricata, crowdsec, qfeeds) that are switched off and have no data in the period -
    their panels ("needs"), stat tiles ("needs_cols") and tabs ("needs") are left out.
    ``tab``: on a dashboard with "tabs" only that tab's panels are run (default: the first tab)."""
    spec = DASHBOARDS[name]
    tabs = [t for t in spec.get("tabs") or [] if t.get("needs") not in off]
    source = spec.get("source")
    if tabs:
        cur = next((t for t in tabs if t["id"] == tab), tabs[0])
        tab, source = cur["id"], cur.get("source", source)
    secs, step = hours * 3600, step_for(hours)

    async def run(panel: dict[str, Any]) -> dict[str, Any]:
        sql = panel["sql"]
        fast = hours >= rollup.MIN_HOURS and (name, panel["id"]) in ROLLUP_PANELS
        args = [secs, step] if "$2" in sql else [secs]
        out = {k: v for k, v in panel.items() if k not in ("sql", "where", "limit")}
        try:
            async with db.heavy(hours), db.pool().acquire() as conn:
                out["rows"] = db.records(await (rollup.fetch(conn, sql, *args) if fast else conn.fetch(sql, *args)))
            if hide := {c for c, src in (panel.get("needs_cols") or {}).items() if src in off}:
                out["rows"] = [{k: v for k, v in r.items() if k not in hide} for r in out["rows"]]
            if panel["type"] == "table" and out["rows"]:
                out["order"] = sql_order(sql, list(out["rows"][0]))
        except Exception as exc:  # noqa: BLE001 - one broken panel must not break the page
            out["rows"], out["error"] = [], str(exc)
        return out

    panels = await asyncio.gather(*(run(p) for p in spec["panels"]
                                    if p.get("needs") not in off and (not tabs or p.get("tab", tabs[0]["id"]) == tab)))
    out = {"name": name, "title": spec["title"], "source": source, "step": step, "panels": panels}
    if tabs:
        out.update(tabs=[{"id": t["id"], "title": t["title"]} for t in tabs], tab=tab)
    return out
