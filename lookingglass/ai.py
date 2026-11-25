"""AI security analyst: an agent loop over any OpenAI compatible ``/chat/completions`` endpoint.

Works with Anthropic's OpenAI SDK compatibility layer (base URL ``https://api.anthropic.com/v1/``),
OpenAI itself, OpenRouter, LiteLLM, Ollama, LM Studio, vLLM ... anything that speaks the
chat-completions + tools protocol.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from . import db, privacy
from .app_config import FIELDS, GROUPS
from .config import Settings, local_time, time_style
from .reports import CATEGORIES, build_report, category_label, is_all, parse_categories

log = logging.getLogger(__name__)
# every AI request with what started it - off unless LOG_AI_REQUESTS=true (main.py sets the level)
request_log = logging.getLogger("lookingglass.ai_requests")

SCHEMA_DOC = """
PostgreSQL tables you can query with sql_query (read only):

events(id bigint, ts timestamptz, received_at timestamptz, source text, host text, program text,
       severity smallint /*syslog 0=emerg..7=debug*/, action text, src_ip inet, src_port int, dst_ip inet, dst_port int,
       proto text, interface text, direction text, username text, domain text, src_country text, dst_country text,
       message text, data jsonb, uid text)
  source values: firewall (pf filterlog), nginx (web server/reverse proxy: program 'swag' = the SWAG reverse proxy in Docker;
                 older rows with another program came from the OPNsense nginx plugin, no longer read), unbound (DNS), crowdsec (program 'crowdsec-lapi' = CrowdSec in Docker,
                 else the OPNsense plugin), fail2ban (SWAG's fail2ban: data.jail), suricata (IDS/IPS),
                 qfeeds (threat intel blocks), auth (ssh / web GUI logins), vpn, dhcp, system,
                 unraid (Unraid syslog + notifications, host = server name), docker (Unraid container logs, program = container),
                 unifi (UniFi controller events: Wi-Fi / wired clients and APs / switches; src_ip = client IP when known)
  action examples: firewall: pass/block; nginx: http_200, http_404, waf_block (WAF / CrowdSec AppSec), bouncer_block
                   (CrowdSec bouncer in nginx), rate_limited, http_error; unbound: query, reply,
                   block, nxdomain; crowdsec: alert, ban, captcha; fail2ban: found, ban, unban, restore_ban; suricata: alert, drop, blocked; auth: login_failed, login_success,
                   config_change; dhcp: lease; unifi: client_connect, client_disconnect, client_roam, client_blocked,
                   device_offline, device_online, device_restart, rogue_ap, rogue_dhcp, poe_disconnect, login_success / login_failed (controller admin logins), ips_alert
  data keys: firewall {label (rule description), rid, reason, tcpflags}; nginx {method, path, status, user_agent, tags[]};
             unbound {qtype, rcode, blocklist, category}; suricata {sid, signature, classification, priority};
             crowdsec {scenario, decisions, as, country, events_count, appsec, meta {target_uri[], target_fqdn[], rule_name[] ...};
                       decision events (ban/captcha): id, value, scenario, origin, duration, until, alert_id};
             nginx bouncer_block / waf_block {remediation, by (appsec = WAF), blocked_by};
             fail2ban {jail, honeypot}; honeypot hits (traps): data.honeypot = true (nginx tags[] also has 'honeypot');
             unifi {key (EVT_...), mac (client), ap, ap_from, ap_to, ssid, sw, port, subsystem}
alerts(id, created_at, last_seen, rule, severity /*info|low|medium|high|critical*/, title, description, src_ip inet,
       dst_ip inet, count int, status /*open|acknowledged|closed*/, close_reason /*false_positive|resolved|muted|known_false_positive = a repeat of an alert closed as false positive, see data.repeat_of*/, fingerprint, data jsonb)
alert_comments(id, alert_id /*alerts.id*/, created_at, updated_at, author, body)  -- the user's own notes on alerts
metrics(ts, name, labels, value)  names: memory_used_pct, load1, pf_states, pf_states_pct, disk_used_pct, temperature,
       gateway_delay_ms, gateway_loss_pct, if_rx_bps, if_tx_bps (labels = interface), if_received_errors, ...
devices(mac, ip, hostname, name_source, vendor, interface, sources text[], lease_type, lease_expires, online, trusted, notes,
        conn_type /*wifi|wired, from UniFi*/, conn_where /*'AP Living room · Home (5 GHz)' / 'Switch Office port 5'*/,
        conn_signal /*dBm*/, conn_seen, first_seen, last_seen,
        limits jsonb /*per-device overrides (volume_factor, ml_sensitivity, risk_threshold, new_country..., alert modes alert|silent|off); missing = device type default, else global*/, device_type text /*computer|phone|server|iot|network|other*/)   -- network inventory: ARP, DHCP leases, UniFi clients
device_profile(key /*MAC or IP*/, kind /*country|port|domain|tls|hour*/, value, first_seen, last_seen, hits)
       -- what is NORMAL for each device (learned); device_hourly(key, hour, ip, features jsonb: connections, destinations,
       ports, countries, dns, failed_lookups, blocked) -- per device and hour
risk_scores(entity /*IP*/, score, parts jsonb [{rule, severity, points}], updated)  -- alerts add points that fade
intel_indicators(kind /*domain|ip|ja3*/, value, feed /*urlhaus|threatfox|feodo|sslbl_ja3|tor_relay|tor_exit*/, info)
seen_domains(domain, first_seen, first_client, registered /*RDAP*/)  -- first lookup of each domain on the network
snapshots(key, ts, data jsonb)  keys: system, activity (top processes), gateways, interfaces, services, firmware, arp,
       leases_kea / leases_dnsmasq / leases_isc, unbound_totals, qfeeds_stats, poller_status,
       crowdsec_decisions (OPNsense plugin) / crowdsec_lapi_decisions (CrowdSec in Docker): the decisions in force now -
       prefer the crowdsec_status tool for bans, CrowdSec metrics and whether both CrowdSecs share one Local API,
       unifi:devices (APs / switches: state, model, firmware, upgradable, cpu, mem, clients, ports[], radios[]),
       unifi:clients (connected now: mac, ip, alias, hostname, wired, ssid, ap, switch, port, signal, satisfaction, tx/rx_bytes),
       unifi:health, unifi:rogue (neighbouring APs; evil_twin = foreign AP using one of your SSIDs), unifi:status,
       unraid:<server id>:<info|metrics|temps|storage (array + per-pool groups, spin state)|array|docker|docker_stats|notifications|vms|ups|shares|disks (SMART)>, unraid_status
metrics also: cpu_used_pct, swap_used_pct, unraid_cpu_pct / unraid_mem_pct / unraid_temp / unraid_disk_temp /
       unraid_array_used_pct / unraid_pool_used_pct / unraid_group_spinning (labels '<server id>[:<item>]'), container_cpu_pct / container_mem_bytes ('<server id>:<container>'),
       unifi_clients (labels wifi|wired), unifi_ssid_clients / unifi_ap_clients (labels = SSID / AP name), unifi_wifi_satisfaction,
       unifi_device_cpu / unifi_device_mem / unifi_device_tx_bps / unifi_device_rx_bps (labels = device name)

blocks(id, ip inet, created_at, expires_at /*NULL = until removed*/, created_by /*user, or 'auto'*/, reason, alert_id,
       auto bool, status /*active|removed|expired*/, removed_at, removed_by, in_alias bool, last_error)
       -- addresses blocked in OPNsense from Looking Glass (one alias it fills)
snoozes(id, name, starts_at, ends_at, networks /*IPs / CIDRs, NULL = all*/, rules text[] /*empty = all*/, hits, created_by)
       -- maintenance windows: matching alerts were stored closed (close_reason muted, data.snoozed) and not mailed
wan_daily(gateway, day date, samples, delay_avg, delay_p50, delay_p95, delay_max /*ms*/, stddev_avg /*jitter ms*/,
       loss_avg, loss_max /*%*/, down_samples, up_samples)  -- per gateway and day, 2 years; metrics also gateway_stddev_ms, gateway_up (1/0)
audit_log(id, ts, username, ip, action /*login|login_failed|logout|change|backup|reset|reset_requested*/,
       target /*e.g. 'PUT /api/settings'*/, status /*HTTP*/, detail jsonb)  -- who did what in Looking Glass
backup_runs(source /*backrest|bichon*/, ext_id, kind /*backup|forget|prune|check|stats|restore|dry-run*/,
       job /*Backrest plan; Bichon: mail account (address) or 'Bichon data backup'*/,
       repo, status /*success|warning|error|running|pending|cancelled*/, started, ended, duration_s, bytes_processed
       /*data scanned*/, bytes_added /*new data in the repository*/, files_new, files_changed, files_total, snapshot_id,
       message /*error text*/, data jsonb /*errors[], progress, stats {total_size, total_uncompressed_size,
       compression_ratio, snapshot_count}*/)  -- every run of the backup tools; speed = bytes_processed / duration_s
       -- Bichon (mail archive): kind 'backup' = a mail sync (files_new = mails archived, data.error_count /
       data.errors = failed folders), kind 'stats' = hourly archive size (data.stats {total_size, index_size, emails,
       attachments}, data.accounts {address: mails})
snapshots also: backrest:config (plans with schedule / retention, repositories), backrest:summary, backrest:status,
       bichon:state (accounts with sync state, archive totals), bichon:status,
       backup_jobs:<source> (jobs with schedule and overdue threshold_s)

Tips: use host(src_ip) to print addresses, `src_ip << '10.0.0.0/8'::inet` for subnet tests, ts > now() - interval '24 hours'
for time windows. Always aggregate (GROUP BY / count) rather than pulling raw rows when looking at large volumes.
"""

SYSTEM_PROMPT = """You are Looking Glass's security analyst, a senior SOC / network security engineer investigating an
OPNsense firewall, the network behind it (UniFi access points / switches when configured) and the user's Unraid
server(s). You have tools that query the log database (firewall, nginx, Unbound DNS, CrowdSec, Suricata,
Q-Feeds threat intel, authentication, VPN, DHCP, UniFi and system logs) plus OPNsense and UniFi state and
the backups (Backrest / restic, and the Bichon mail archive: failed, overdue or slow backups and mail syncs are a
resilience risk - e.g. against ransomware).

How to work:
- Investigate with the tools before answering; base every claim on data you actually retrieved and cite the concrete
  evidence (IPs, counts, timestamps, rule names, signatures). If data is missing (a source sends no logs) say so and
  explain how to enable it in OPNsense.
- Look for: intrusion attempts, successful compromises, brute force, port scans, web attacks, malware / C2 beaconing,
  DNS tunneling / DGA, data exfiltration (unusual volumes or destinations), new or rogue devices, policy weaknesses
  (overly permissive rules, exposed services), vulnerable or outdated components and misconfigurations.
- Distinguish background internet noise (mass scanners hitting WAN that were blocked) from things that matter
  (anything ALLOWED, anything originating INSIDE the network, successful logins, repeated targeting).
- Rate findings by severity (critical/high/medium/low/info), and give concrete remediation steps that reference the
  OPNsense UI (menu paths) where helpful.
- Combine sources: OPNsense / DNS tell WHAT a device does, UniFi tells WHERE it is (AP or switch port, SSID /
  VLAN, signal) and since when. Use that to name the device, judge whether it belongs on that network (e.g. an IoT plug on
  the main SSID, an unknown wired device on a free switch port) and to give exact containment steps (UniFi Network ›
  Client Devices › Block, move it to an isolated SSID / VLAN, disable the switch port, or an OPNsense rule).
- The user's comments on alerts (alert_comments; included by list_alerts and alert_detail) are first-hand knowledge:
  why an alert was closed or marked false positive, what a device is, what was already done. Take them into account,
  also for similar alerts (same rule and / or address) - e.g. don't report something the user explained as expected,
  unless the data shows it changed.
- Looking Glass's own settings: before you tell the user to change anything in Looking Glass (a Settings path, a
  switch, an exclusion), call looking_glass_settings and name only settings, pages and buttons it returns, with their
  exact path and current value. Never invent a Looking Glass setting or menu path. If what is needed is not a
  setting (e.g. which paths count as a web attack, which is built into the detection code), say so plainly and offer
  what does exist: an alert filter (Settings › Alert filters, or Mute similar… on the Alerts page), a snooze, or
  closing the alert as a false positive.
- Be concise; use markdown headings, bullet lists and tables.

Current time: {now} UTC = {local}. Timestamps in the data are UTC; when you write times for the user, convert them
to {style} (convert in SQL with AT TIME ZONE '{zone}' or yourself).
Data volume in the last 24h by source: {volumes}
{setup}""" + SCHEMA_DOC

TOOLS: list[dict[str, Any]] = [
    {"type": "function", "function": {
        "name": "sql_query",
        "description": "Run one read-only SQL SELECT/WITH query against the Looking Glass PostgreSQL database. Returns up to 200 rows as JSON.",
        "parameters": {"type": "object", "properties": {"query": {"type": "string", "description": "A single SELECT statement"}},
                       "required": ["query"]}}},
    {"type": "function", "function": {
        "name": "search_events",
        "description": "Search raw log events with simple filters. Prefer sql_query for aggregations.",
        "parameters": {"type": "object", "properties": {
            "source": {"type": "string", "description": "firewall, nginx, unbound, crowdsec, suricata, qfeeds, auth, vpn, dhcp, system, unifi, unraid, docker"},
            "ip": {"type": "string", "description": "match src_ip or dst_ip"},
            "action": {"type": "string"},
            "text": {"type": "string", "description": "case-insensitive substring of message/domain"},
            "hours": {"type": "number", "description": "look back window, default 24"},
            "limit": {"type": "integer", "description": "max rows (default 50, max 200)"}}}}},
    {"type": "function", "function": {
        "name": "ip_profile",
        "description": "Everything known about one IP address: activity per source/action, ports, domains, alerts, first/last seen, country.",
        "parameters": {"type": "object", "properties": {"ip": {"type": "string"}, "hours": {"type": "number", "description": "default 168"}},
                       "required": ["ip"]}}},
    {"type": "function", "function": {
        "name": "alert_detail",
        "description": "One alert in full: description, data, the user's comments on it, and earlier alerts of the same rule "
                       "and address (with their status, close reason and comments).",
        "parameters": {"type": "object", "properties": {"alert_id": {"type": "integer"}}, "required": ["alert_id"]}}},
    {"type": "function", "function": {
        "name": "event_detail",
        "description": "One log event in full (all fields and its raw data) with context: the devices behind its addresses, "
                       "what the same source address did 15 minutes before and after, how often this kind of event "
                       "happened in the last 7 days, and alerts about its addresses (with the user's comments).",
        "parameters": {"type": "object", "properties": {"event_id": {"type": "integer"}}, "required": ["event_id"]}}},
    {"type": "function", "function": {
        "name": "list_alerts",
        "description": "List alerts raised by the detection engine, with the user's comments on them.",
        "parameters": {"type": "object", "properties": {
            "status": {"type": "string", "description": "open, acknowledged, closed or all (default open)"},
            "hours": {"type": "number", "description": "only alerts seen in this window (default 168)"},
            "limit": {"type": "integer"}}}}},
    {"type": "function", "function": {
        "name": "system_status",
        "description": "Current OPNsense system state (resources, versions, gateways, services, firmware/updates), Unraid servers (hardware, array/disks, containers, notifications, UPS, VMs), log ingestion stats and which API endpoints work.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "unifi_status",
        "description": "UniFi network now: access points / switches (state, firmware, load, ports), connected Wi-Fi and wired clients "
                       "with AP / switch port, SSID, signal and traffic, health and neighbouring / evil-twin APs. Optional filter "
                       "on a client name, IP or MAC.",
        "parameters": {"type": "object", "properties": {"client": {"type": "string", "description": "optional name / IP / MAC filter"}}}}},
    {"type": "function", "function": {
        "name": "backup_status",
        "description": "Backups (Backrest / restic, Bichon mail archive syncs): every backup job with its state (ok, warning, failed, overdue, running, "
                       "never), last and last successful run, schedule, runs and failures in the period, plus recent "
                       "failed or warning runs with their error text.",
        "parameters": {"type": "object", "properties": {"days": {"type": "integer", "description": "period, default 7"}}}}},
    {"type": "function", "function": {
        "name": "crowdsec_status",
        "description": "CrowdSec now (OPNsense plugin and CrowdSec in Docker next to SWAG): the bans in force grouped per "
                       "address (scenarios, type, origin, time left), counts per scenario / origin / country, alerts and "
                       "SWAG bouncer / WAF blocks of the last 24 hours, which logs CrowdSec reads, AppSec and bouncer "
                       "metrics, and whether both share one Local API. Optional filter on one address.",
        "parameters": {"type": "object", "properties": {"ip": {"type": "string", "description": "optional: only this address"}}}}},
    {"type": "function", "function": {
        "name": "looking_glass_settings",
        "description": "Looking Glass's own Settings as they really exist: every tab and setting with its exact menu path, "
                       "choices and current value, plus the alert filters, snoozes and notification rules that are set up "
                       "and what can and cannot be configured. Call it before advising any change in Looking Glass. "
                       "Without search: an overview without descriptions; with search: the matching settings in full.",
        "parameters": {"type": "object", "properties": {"search": {
            "type": "string", "description": "optional words to find in a setting's tab, name, key or description, "
                                             "e.g. 'web', 'scanner', 'block'"}}}}},
    {"type": "function", "function": {
        "name": "traffic_overview",
        "description": "Aggregated statistics (top blocked sources, ports, countries, DNS, web, auth failures, IDS signatures ...) for a period.",
        "parameters": {"type": "object", "properties": {"hours": {"type": "number", "description": "default 24"}}}}},
]

_FORBIDDEN = re.compile(r"\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|copy|vacuum|call|do|lock|set|reset|"
                        r"pg_sleep|pg_read|pg_ls|lo_import|lo_export|dblink|pg_terminate|pg_cancel)\b", re.I)


# secrets the model must never read (credentials, MFA material, session key)
_SECRET = re.compile(r"\b(users|webauthn_credentials|kv|app_settings|unraid_servers|api_key|password_hash|totp_secret|secret_key|"
                     r"pg_shadow|pg_authid|pg_user|current_setting|pg_settings|pg_stat_activity)\b", re.I)


def _dump(value: Any, limit: int = 40000) -> str:
    # ensure_ascii=False: names stay as written ("Jörg", not "J\u00f6rg") - privacy mode recognises them that way
    text = json.dumps(db.jsonable(value), default=str, ensure_ascii=False)
    if len(text) > limit:
        # cut after a complete value (", " separates them), never inside an address or a name
        cut = text.rfind(", ", limit - 2000, limit)
        text = text[:cut if cut > 0 else limit] + f'... [truncated, {len(text)} chars total - narrow the query]'
    return text


async def _comments(alert_ids: list[int]) -> dict[int, list[dict[str, Any]]]:
    out: dict[int, list[dict[str, Any]]] = {}
    if alert_ids:
        for r in await db.pool().fetch("SELECT alert_id, created_at, author, body FROM alert_comments "
                                       "WHERE alert_id = ANY($1::bigint[]) ORDER BY created_at", alert_ids):
            out.setdefault(r["alert_id"], []).append({"at": r["created_at"], "by": r["author"], "comment": r["body"]})
    return out


async def tool_sql_query(query: str) -> Any:
    q = query.strip().rstrip(";")
    if ";" in q:
        return {"error": "only a single statement is allowed"}
    if not re.match(r"^\s*(select|with|explain)\b", q, re.I) or _FORBIDDEN.search(re.sub(r"'[^']*'", "''", q)):
        return {"error": "only read-only SELECT queries are allowed"}
    if _SECRET.search(q):
        return {"error": "that table/column holds credentials and is not accessible"}
    async with db.pool().acquire() as conn:
        async with conn.transaction(readonly=True):
            await conn.execute("SET LOCAL statement_timeout = '30s'")
            rows = await conn.fetch(f"SELECT * FROM ({q}) AS _q LIMIT 200" if not q.lower().startswith("explain") else q)
    return {"rows": db.records(rows), "row_count": len(rows)}


async def tool_search_events(source: str | None = None, ip: str | None = None, action: str | None = None,
                             text: str | None = None, hours: float = 24, limit: int = 50) -> Any:
    where, args = ["ts > now() - make_interval(secs => $1)"], [float(hours) * 3600]
    if source:
        args.append(source)
        where.append(f"source = ${len(args)}")
    if ip:
        args.append(ip)
        where.append(f"(src_ip = ${len(args)}::inet OR dst_ip = ${len(args)}::inet)")
    if action:
        args.append(action)
        where.append(f"action = ${len(args)}")
    if text:
        args.append(f"%{text}%")
        where.append(f"(message ILIKE ${len(args)} OR domain ILIKE ${len(args)})")
    args.append(max(1, min(int(limit or 50), 200)))
    rows = await db.pool().fetch(
        f"SELECT ts, source, action, host(src_ip) src, src_port, host(dst_ip) dst, dst_port, proto, interface, username, domain, "
        f"src_country, message FROM events WHERE {' AND '.join(where)} ORDER BY ts DESC LIMIT ${len(args)}", *args)
    return db.records(rows)


async def tool_ip_profile(ip: str, hours: float = 168) -> Any:
    pool = db.pool()
    secs = float(hours) * 3600
    base = "ts > now() - make_interval(secs => $2) AND (src_ip = $1::inet OR dst_ip = $1::inet)"
    by_source = await pool.fetch(f"SELECT source, action, count(*) n, min(ts) first, max(ts) last FROM events WHERE {base} "
                                 "GROUP BY 1, 2 ORDER BY n DESC LIMIT 50", ip, secs)
    ports = await pool.fetch(f"SELECT dst_port, proto, action, count(*) n FROM events WHERE {base} AND src_ip = $1::inet "
                             "AND dst_port IS NOT NULL GROUP BY 1, 2, 3 ORDER BY n DESC LIMIT 25", ip, secs)
    peers = await pool.fetch(f"SELECT host(CASE WHEN src_ip = $1::inet THEN dst_ip ELSE src_ip END) peer, count(*) n FROM events "
                             f"WHERE {base} GROUP BY 1 ORDER BY n DESC LIMIT 20", ip, secs)
    domains = await pool.fetch("SELECT domain, action, count(*) n FROM events WHERE ts > now() - make_interval(secs => $2) "
                               "AND src_ip = $1::inet AND domain IS NOT NULL GROUP BY 1, 2 ORDER BY n DESC LIMIT 30", ip, secs)
    alerts = await pool.fetch("SELECT id, rule, severity, title, status, last_seen FROM alerts WHERE src_ip = $1::inet OR dst_ip = $1::inet "
                              "ORDER BY last_seen DESC LIMIT 20", ip)
    country = await pool.fetchval("SELECT coalesce(src_country, dst_country) FROM events WHERE (src_ip = $1::inet AND src_country IS NOT NULL) "
                                  "OR (dst_ip = $1::inet AND dst_country IS NOT NULL) LIMIT 1", ip)
    device = await pool.fetchrow("SELECT * FROM devices WHERE ip = $1::inet OR $1::inet = ANY(ips) "
                                 "ORDER BY last_seen DESC LIMIT 1", ip)
    return {"ip": ip, "country": country, "device": dict(device) if device else None, "activity": db.records(by_source),
            "top_ports_as_source": db.records(ports), "top_peers": db.records(peers), "dns_queries": db.records(domains),
            "alerts": db.records(alerts)}


async def tool_list_alerts(status: str = "open", hours: float = 168, limit: int = 50) -> Any:
    args: list[Any] = [float(hours) * 3600, max(1, min(int(limit or 50), 200))]
    cond = ""
    if status and status != "all":
        args.append(status)
        cond = "AND status = $3"
    rows = await db.pool().fetch(
        f"SELECT id, created_at, last_seen, rule, severity, title, description, host(src_ip) src, host(dst_ip) dst, count, status, "
        f"close_reason FROM alerts WHERE last_seen > now() - make_interval(secs => $1) {cond} "
        f"ORDER BY array_position(ARRAY['critical','high','medium','low','info'], severity), last_seen DESC LIMIT $2", *args)
    out = db.records(rows)
    comments = await _comments([a["id"] for a in out])
    for a in out:
        if a["id"] in comments:
            a["comments"] = comments[a["id"]]
    return out


async def tool_alert_detail(alert_id: int) -> Any:
    row = await db.pool().fetchrow(
        "SELECT id, created_at, last_seen, rule, severity, title, description, host(src_ip) src, host(dst_ip) dst, count, "
        "status, close_reason, data FROM alerts WHERE id = $1", int(alert_id))
    if not row:
        return {"error": f"alert #{alert_id} does not exist (deleted, or closed alerts older than the retention)"}
    alert = db.jsonable(dict(row))
    similar = db.records(await db.pool().fetch(
        "SELECT id, created_at, last_seen, severity, title, count, status, close_reason FROM alerts WHERE rule = $1 "
        "AND id <> $2 AND (src_ip IS NOT DISTINCT FROM $3::inet) ORDER BY last_seen DESC LIMIT 20",
        row["rule"], row["id"], alert["src"]))
    comments = await _comments([alert["id"]] + [a["id"] for a in similar])
    alert["comments"] = comments.get(alert["id"], [])
    for a in similar:
        if a["id"] in comments:
            a["comments"] = comments[a["id"]]
    return {"alert": alert, "earlier_alerts_same_rule_and_source": similar}


async def tool_event_detail(event_id: int) -> Any:
    pool = db.pool()
    row = await pool.fetchrow(
        "SELECT id, ts, received_at, source, host, program, severity, action, host(src_ip) src_ip, src_port, "
        "host(dst_ip) dst_ip, dst_port, proto, interface, direction, username, domain, src_country, dst_country, "
        "message, data FROM events WHERE id = $1", int(event_id))
    if not row:
        return {"error": f"event #{event_id} does not exist (older than the retention, or deleted)"}
    ev = db.jsonable(dict(row))
    ips = [ip for ip in (ev["src_ip"], ev["dst_ip"]) if ip]
    devices = {}
    for ip in ips:
        dev = await pool.fetchrow("SELECT mac, hostname, vendor, interface, device_type, trusted, notes, first_seen, last_seen "
                                  "FROM devices WHERE ip = $1::inet OR $1::inet = ANY(ips) ORDER BY last_seen DESC LIMIT 1", ip)
        if dev:
            devices[ip] = db.jsonable(dict(dev))
    around = []
    if ev["src_ip"]:
        around = db.records(await pool.fetch(
            "SELECT id, ts, source, action, host(dst_ip) dst, dst_port, proto, domain, left(message, 200) message FROM events "
            "WHERE src_ip = $1::inet AND ts BETWEEN $2::timestamptz - interval '15 minutes' AND $2::timestamptz + interval '15 minutes' "
            "AND id <> $3 ORDER BY abs(extract(epoch FROM ts - $2::timestamptz)) LIMIT 40", ev["src_ip"], row["ts"], row["id"]))
    similar = db.records(await pool.fetch(
        "SELECT count(*) n, count(DISTINCT src_ip) sources, min(ts) first, max(ts) last FROM events "
        "WHERE ts > now() - interval '7 days' AND source = $1 AND action IS NOT DISTINCT FROM $2 "
        "AND dst_port IS NOT DISTINCT FROM $3 AND (src_ip IS NOT DISTINCT FROM $4::inet OR domain IS NOT DISTINCT FROM $5)",
        row["source"], row["action"], row["dst_port"], ev["src_ip"], row["domain"]))
    alerts = []
    if ips:
        alerts = db.records(await pool.fetch(
            "SELECT id, created_at, last_seen, rule, severity, title, status, close_reason FROM alerts "
            "WHERE (src_ip = ANY($1::inet[]) OR dst_ip = ANY($1::inet[])) AND last_seen > now() - interval '7 days' "
            "ORDER BY last_seen DESC LIMIT 20", ips))
        comments = await _comments([a["id"] for a in alerts])
        for a in alerts:
            if a["id"] in comments:
                a["comments"] = comments[a["id"]]
    return {"event": ev, "devices": devices, "same_source_15_minutes_around": around,
            "similar_events_last_7_days": similar[0] if similar else None, "alerts_about_these_addresses": alerts}


async def tool_system_status() -> Any:
    from .ingest import STATS

    keys = ["system", "gateways", "firmware", "poller_status", "qfeeds_stats"]
    out = {k: await db.get_snapshot(k) for k in keys}
    services = await db.get_snapshot("services") or []
    out["services"] = [{"name": s.get("name"), "description": s.get("description"), "running": s.get("running")}
                       for s in services if isinstance(s, dict)]
    out["ingest"] = STATS.as_dict()
    servers = await db.pool().fetch("SELECT id, name FROM unraid_servers WHERE enabled")
    out["unraid"] = {}
    for srv in servers:
        snap = {}
        for key in ("info", "metrics", "storage", "docker", "notifications", "ups", "vms"):
            snap[key] = await db.get_snapshot(f"unraid:{srv['id']}:{key}")
        out["unraid"][srv["name"]] = snap
    return out


async def tool_unifi_status(client: str | None = None) -> Any:
    out = {k: await db.get_snapshot(f"unifi:{k}") for k in ("status", "health", "devices", "rogue")}
    if not out["status"]:
        return {"configured": False, "hint": "UniFi is not connected: Settings › UniFi in Looking Glass"}
    clients = await db.get_snapshot("unifi:clients") or []
    if client:
        q = client.lower()
        clients = [c for c in clients if q in " ".join(str(c.get(k) or "") for k in ("alias", "hostname", "ip", "mac")).lower()]
    out["clients"] = clients[:300]
    out["client_count"] = len(clients)
    return out


async def tool_backup_status(days: int = 7) -> Any:
    from . import backups

    out = await backups.overview(max(1, min(int(days), 400)), "UTC")
    if not out["jobs"] and not any(s["status"] for s in out["sources"]):
        return {"configured": False, "hint": "No backup tool is connected: Settings › Backrest / Bichon in Looking Glass"}
    out["problems"] = [r for r in out.pop("recent") if r["status"] in ("error", "warning")][:30]
    return out


def _ban_rows(rows: Any, which: str) -> list[dict[str, Any]]:
    """Both snapshot formats (crowdsec_lapi.py / parsers.security.crowdsec_ban_row) as one shape."""
    out = []
    for d in rows if isinstance(rows, list) else []:
        if not isinstance(d, dict):
            continue
        if which == "docker":
            out.append({"value": d.get("value"), "type": d.get("type"), "scenario": d.get("scenario"),
                        "origin": d.get("origin"), "until": d.get("until"), "country": d.get("country")})
        else:
            out.append({"value": d.get("lg_value") or d.get("scope_value") or d.get("value"),
                        "type": d.get("action") or d.get("type") or "ban", "scenario": d.get("reason") or d.get("scenario"),
                        "origin": d.get("source") or d.get("origin"), "until": d.get("lg_until"), "country": d.get("country")})
    return out


def _top(rows: list[dict[str, Any]], key: str, n: int = 15) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in rows:
        k = str(r.get(key) or "?")
        counts[k] = counts.get(k, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1])[:n])


async def tool_crowdsec_status(ip: str | None = None) -> Any:
    from . import crowdsec_shared
    from .config import get_settings

    s = get_settings()
    if not (s.crowdsec_lapi_enabled or (s.opnsense_enabled and s.crowdsec_pull)):
        return {"configured": False, "hint": "No CrowdSec is connected: Settings › SWAG & CrowdSec (Local API) or "
                                             "Settings › OPNsense (CrowdSec plugin) in Looking Glass"}
    primary = await crowdsec_shared.shared_primary(s)
    lists = {"docker": _ban_rows(await db.get_snapshot("crowdsec_lapi_decisions"), "docker"),
             "opnsense": _ban_rows(await db.get_snapshot("crowdsec_decisions"), "opnsense")}
    out: dict[str, Any] = {
        "shared_local_api": ({"shared": True, "local_api": primary, "note": "both lists hold the same decisions; Unban "
                              "is offered only in the Active bans list of the CrowdSec that is the Local API"}
                             if primary else {"shared": False}),
    }
    for which, rows in lists.items():
        if which == "opnsense" and primary and lists["docker"]:
            continue  # the same decisions twice
        if ip:
            rows = [r for r in rows if str(r.get("value") or "").split("/")[0] == ip]
        per: dict[str, dict[str, Any]] = {}
        for r in rows:  # CrowdSec keeps one decision per scenario: one entry per address, as the Active bans lists show
            p = per.setdefault(str(r["value"]), {"value": r["value"], "country": r["country"], "scenarios": set(),
                                                 "types": set(), "origins": set(), "decisions": 0, "until": None})
            p["scenarios"].add(r["scenario"] or "?"); p["types"].add(r["type"] or "ban"); p["origins"].add(r["origin"] or "?")
            p["decisions"] += 1
            p["until"] = max(filter(None, (p["until"], r["until"])), default=None)
        bans = sorted(per.values(), key=lambda p: p["until"] or "", reverse=True)
        for p in bans:
            for k in ("scenarios", "types", "origins"):
                p[k] = sorted(p[k])
        label = "CrowdSec in Docker (SWAG & CrowdSec page)" if which == "docker" else "OPNsense CrowdSec plugin (Threats › CrowdSec)"
        if rows or not ip:
            out[f"active_bans_{which}"] = {"where": label, "decisions": len(rows), "addresses": len(bans),
                                           "by_scenario": _top(rows, "scenario"), "by_origin": _top(rows, "origin", 8),
                                           "by_country": _top(rows, "country", 10), "bans": bans[:100]}
    where_ip = " AND src_ip = $1::inet" if ip else ""
    args = [ip] if ip else []
    pool = db.pool()
    out["alerts_24h_by_scenario"] = db.records(await pool.fetch(
        "SELECT coalesce(data->>'scenario', data->>'reason') scenario, CASE WHEN program = 'crowdsec-lapi' THEN 'docker' "
        "ELSE 'opnsense' END crowdsec, count(*) alerts, count(DISTINCT src_ip) ips FROM events WHERE source = 'crowdsec' "
        f"AND action = 'alert' AND ts > now() - interval '24 hours'{where_ip} GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 25", *args))
    out["swag_blocks_24h"] = db.records(await pool.fetch(
        "SELECT host(src_ip) ip, string_agg(DISTINCT coalesce(data->>'by', action), ', ') how, count(*) n, max(domain) site "
        "FROM events WHERE source = 'nginx' AND program = 'swag' AND action IN ('bouncer_block', 'waf_block') "
        f"AND ts > now() - interval '24 hours'{where_ip} GROUP BY 1 ORDER BY 3 DESC LIMIT 20", *args))
    if not ip:
        metrics = await db.get_snapshot("crowdsec_lapi_metrics")
        if isinstance(metrics, dict):
            out["metrics"] = {k: metrics.get(k) for k in ("version", "acquisition", "overflows", "appsec", "bouncers")}
        status = await db.get_snapshot("crowdsec_lapi:status")
        if isinstance(status, dict):
            out["local_api_status"] = {k: status.get(k) for k in ("ok", "error", "parts", "active_decisions")}
    return out


# Settings tabs as the web UI names them (settings.html); test_ai_settings checks they stay the same
SETTINGS_TABS = {**{g: label for g, label in GROUPS.items()}, "ingest": "Ingestion & network",
                 "email": "Email & notifications", "packages": "Unraid servers › Container packages",
                 "mute": "Alert filters › Recurring mute windows"}
# settings pages that are not plain fields (managed in their own lists / pages)
SETTINGS_PAGES = [
    {"path": "Settings › Alert filters", "what": "Stop alerts you don't want or change their severity. Conditions: "
     "severity (this and below), rules / sources, text in the alert's title or description, IP address / network, "
     "source / destination ports; combined with all (AND) or any (OR). Actions: Don't create, Create as closed, or "
     "Change severity. Only alerts are affected, not logs. The Alerts page's 'Mute similar…' fills one in."},
    {"path": "Alerts page › Snooze & maintenance (/snooze)", "what": "For a time window, store alerts matching rules "
     "and / or addresses silently (not shown or mailed)."},
    {"path": "Alerts page › an alert › Close (with a reason, e.g. false positive), Comment, Mute similar…, Block…",
     "what": "Per alert. Comments are first-hand knowledge you get with the alerts."},
    {"path": "Settings › Email & notifications › Notification rules", "what": "Which alerts are mailed to whom."},
    {"path": "Settings › Unraid servers", "what": "Add Unraid servers, choose arrays / pools and SMART checks."},
    {"path": "Settings › Threat intel & traps › Threat feeds", "what": "Downloaded known-bad lists; update now."},
    {"path": "Settings › Data & detection › Backup / Delete collected data", "what": "Backup of Looking Glass, "
     "deleting collected data."},
    {"path": "Blocked addresses page (/blocks)", "what": "Addresses blocked in OPNsense through the alias."},
]
NOT_CONFIGURABLE = [
    "Which request paths / patterns count as a web attack or scanner probe (path_traversal, sqli, xss, rce, "
    "sensitive_file, scanner_probe, scanner_ua) is built into the code; there is no per-path exclusion setting. Use "
    "the 'Web attacks / scanners from the internet' settings for how much alerts, and an alert filter for specific alerts.",
    "Detection rules' logic and fixed thresholds are code unless a setting below names them.",
]
# values the model gets only as set / not set: credentials, mail addresses, the words privacy mode hides
_HIDDEN_VALUES = re.compile(r"username|password|smtp_from|mail_to|privacy_terms|privacy_keep|privacy_avoid|ca_pem|"
                            r"tool_env|registry_user")


def _setting_value(f: Any, value: Any) -> Any:
    if f.kind in ("secret", "image") or _HIDDEN_VALUES.search(f.key):
        return "(set)" if value else "(empty)"
    return value


async def tool_looking_glass_settings(settings: Settings, search: str | None = None) -> Any:
    words = [w for w in re.split(r"\s+", (search or "").lower()) if w]
    tabs: dict[str, list[dict[str, Any]]] = {}
    for f in FIELDS:
        tab = SETTINGS_TABS.get(f.group, f.group)
        if words and not all(w in f"{tab} {f.label} {f.key} {f.help}".lower() for w in words):
            continue
        item: dict[str, Any] = {"setting": f.label, "key": f.key,
                                "value": _setting_value(f, getattr(settings, f.key, None))}
        if f.choices:
            item["choices"] = list(f.choices)
        if words:
            item["description"] = f.help
            if f.min is not None or f.max is not None:
                item["range"] = [f.min, f.max]
        tabs.setdefault(f"Settings › {tab}", []).append(item)
    out: dict[str, Any] = {"settings": tabs or "no setting matches - it does not exist in Looking Glass",
                           "other_pages": SETTINGS_PAGES, "not_configurable": NOT_CONFIGURABLE}
    if not words:
        out["tabs"] = [f"Settings › {t}" for t in (*SETTINGS_TABS.values(), "Alert filters")]
    pool = db.pool()
    out["alert_filters"] = db.records(await pool.fetch(
        "SELECT id, name, enabled, action, set_severity, max_severity, rules, contains, text_mode, networks, src_ports, "
        "dst_ports, match_mode, hits, last_hit FROM alert_filters ORDER BY id"))
    out["active_snoozes"] = db.records(await pool.fetch(
        "SELECT id, name, starts_at, ends_at, networks, rules FROM snoozes WHERE ends_at > now() ORDER BY starts_at"))
    out["notification_rules"] = db.records(await pool.fetch(  # recipients left out: mail addresses
        "SELECT id, name, enabled, min_severity, rules, contains, networks FROM notification_rules ORDER BY id"))
    return out


async def run_tool(name: str, args: dict[str, Any], settings: Settings | None = None) -> str:
    if name == "looking_glass_settings":
        from .config import get_settings
        args = {**args, "settings": settings or get_settings()}
    fn = {"sql_query": tool_sql_query, "search_events": tool_search_events, "ip_profile": tool_ip_profile,
          "list_alerts": tool_list_alerts, "alert_detail": tool_alert_detail, "event_detail": tool_event_detail, "system_status": tool_system_status, "unifi_status": tool_unifi_status,
          "backup_status": tool_backup_status, "looking_glass_settings": tool_looking_glass_settings,
          "crowdsec_status": tool_crowdsec_status,
          "traffic_overview": lambda hours=24: build_report(float(hours))}.get(name)
    if fn is None:
        return json.dumps({"error": f"unknown tool {name}"})
    try:
        return _dump(await fn(**args))
    except TypeError as exc:
        return json.dumps({"error": f"bad arguments: {exc}"})
    except Exception as exc:  # noqa: BLE001 - errors are returned to the model so it can correct itself
        log.info("tool %s failed: %s", name, exc)
        return json.dumps({"error": f"{type(exc).__name__}: {exc}"})


RETRY_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 520, 522, 524, 529}
STATUS_TEXT = {400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 408: "Request Timeout",
               413: "Payload Too Large", 429: "Too Many Requests", 500: "Internal Server Error", 502: "Bad Gateway",
               503: "Service Unavailable", 504: "Gateway Timeout", 524: "A Timeout Occurred (Cloudflare)", 529: "Overloaded"}


TOOL_NAMES = {t["function"]["name"] for t in TOOLS}


# what the AI looks at in a report of a category (Reports: what the report covers)
REVIEW_FOCUS = {
    "opnsense": "OPNsense: open alerts, blocked and allowed traffic, inbound exposure, outbound anomalies from internal "
                "hosts, DNS, web server, IDS, CrowdSec, Q-Feeds, logins and OPNsense system health",
    "unifi": "UniFi: access points / switches that went offline or restarted, clients that keep disconnecting or roaming, "
             "rogue access points / DHCP servers, UniFi admin logins and which UniFi clients had security events",
    "unraid": "Unraid: array and pool state and free space, disk health (status, I/O errors, SMART, temperatures), parity, "
              "Docker containers (stopped, restarting, unhealthy, errors in their logs), Unraid notifications, CPU / memory "
              "load and the UPS",
    "backups": "Backups: failed, warning or overdue backup jobs, jobs without a recent good run, repository check / "
               "prune problems and unusual growth of the backed up data",
}


def review_prompt(hours: float, categories: Any = None) -> str:
    """The task of a report's AI analysis: all categories = the full review, else only the selected ones."""
    cats = parse_categories(categories)
    if is_all(cats):
        intro = f"Perform a full security and health review of the last {hours:g} hours. Check:\n"
    else:
        others = ", ".join(CATEGORIES[c] for c in CATEGORIES if c not in cats)
        intro = (f"Perform a review of the last {hours:g} hours of {category_label(cats)} only (this report leaves out "
                 f"{others}: don't review those). Check:\n")
    return (intro + "".join(f"- {REVIEW_FOCUS[c]}\n" for c in cats)
            + "Report: 1) executive summary, 2) findings ranked by severity with evidence, 3) recommended actions, "
              "4) blind spots (missing data sources). Take the user's comments on alerts into account (list_alerts / "
              "alert_detail).")


def _valid_json(arguments: Any) -> str:
    """Tool call arguments as a JSON object string: servers refuse the next request when they are cut off / invalid."""
    if isinstance(arguments, dict):
        return json.dumps(arguments)
    try:
        value = json.loads(arguments or "{}")
    except ValueError:
        return "{}"
    return json.dumps(value) if isinstance(value, dict) else "{}"


def _clean_message(m: dict[str, Any]) -> dict[str, Any]:
    """No empty text next to tool calls: gateways that translate to Anthropic (OmniRoute, LiteLLM ...) send it on as an
    empty text block, which the API refuses with HTTP 400 ("text content blocks must be non-empty")."""
    if m.get("role") == "assistant" and m.get("tool_calls") and not m.get("content"):
        return {**m, "content": None}
    if m.get("role") == "tool" and not m.get("content"):
        return {**m, "content": "(no output)"}
    return m


def compact_tool_results(messages: list[dict[str, Any]], limit: int = 4000) -> list[dict[str, Any]]:
    """Older tool results cut short, the latest round kept whole: a smaller request for endpoints that drop the
    connection once the history grows (a local model running out of memory / context, a proxy's body size limit)."""
    last = max((i for i, m in enumerate(messages) if m.get("role") == "assistant"), default=len(messages))
    return [{**m, "content": m["content"][:limit] + f"... [shortened from {len(m['content'])} chars]"}
            if i < last and m.get("role") == "tool" and len(m.get("content") or "") > limit else m
            for i, m in enumerate(messages)]


def plain_tool_history(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The conversation with tool calls and results written out as ordinary assistant / user messages."""
    out: list[dict[str, Any]] = []
    for m in messages:
        if m.get("role") == "assistant" and m.get("tool_calls"):
            calls = "; ".join(f'{c["function"]["name"]}({c["function"].get("arguments") or "{}"})' for c in m["tool_calls"])
            out.append({"role": "assistant", "content": ((m.get("content") or "") + f"\n[called tools: {calls}]").strip()})
        elif m.get("role") == "tool":
            text = f'[tool result]\n{m.get("content") or ""}'
            if out and out[-1]["role"] == "user" and str(out[-1]["content"]).startswith("[tool result]"):
                out[-1] = {"role": "user", "content": out[-1]["content"] + "\n\n" + text}
            else:
                out.append({"role": "user", "content": text})
        else:
            out.append(m)
    return out


class AIError(Exception):
    def __init__(self, status: int, body: str, retry_after: str | None = None) -> None:
        self.status, self.body = status, body or ""
        try:
            self.retry_after = min(60.0, float(retry_after)) if retry_after else None
        except ValueError:
            self.retry_after = None
        super().__init__(f"HTTP {status}")


def explain_ai_error(exc: Exception | None, seconds: float, step: int, s: Settings, attempts: int = 3) -> str:
    """A readable reason (and what to do) instead of a bare status code."""
    where = f"step {step} of the analysis, after {seconds:.0f} s and {attempts} attempt{'s' if attempts != 1 else ''}"
    if isinstance(exc, AIError):
        text = re.sub(r"<[^>]+>", " ", exc.body)  # gateways answer with HTML error pages
        text = re.sub(r"\s+", " ", text).strip()[:300]
        head = f"The AI endpoint answered HTTP {exc.status} {STATUS_TEXT.get(exc.status, '')}".rstrip() + f" ({where})."
        hint = {
            504: " A gateway / proxy in front of the model gave up waiting for the answer. Keep 'Stream answers' on "
                 "(Settings › AI analyst), raise the proxy's timeout if you run one (e.g. LiteLLM / nginx), or use a faster "
                 "model; fewer 'Max tool rounds' also shortens the analysis.",
            524: " Cloudflare in front of the endpoint cut the request off after 100 s - keep 'Stream answers' on.",
            502: " The gateway could not reach the model (provider down or overloaded) - try again later.",
            503: " The provider is overloaded or in maintenance - try again later.",
            529: " The provider is overloaded - try again later.",
            429: " Rate limit or quota reached at the provider - wait, or check your plan / credits.",
            400: " The endpoint (or the model's chat template) rejected the request. From step 2 on it carries the "
                 "tool results: a local model with a small context window (Ollama / llama.cpp / vLLM) runs out of room - "
                 "raise its context size (e.g. Ollama num_ctx, llama.cpp --ctx-size) or use a model with tool support; "
                 "the server's own log names the exact reason.",
            401: " The API key was refused (Settings › AI analyst).",
            403: " The API key may not use this model, or the account has no credits.",
            404: " Wrong base URL or model name (Settings › AI analyst).",
            413: " The request was too large for the endpoint - lower 'Max tool rounds'.",
        }.get(exc.status, "")
        return head + hint + (f" Details: {text}" if text else "")
    if isinstance(exc, httpx.TimeoutException):
        return (f"No answer from the AI endpoint within {s.ai_timeout} s ({where}). Raise 'Request timeout' "
                "(Settings › AI analyst) or keep 'Stream answers' on.")
    if isinstance(exc, (httpx.RemoteProtocolError, httpx.ReadError)):
        return (f"The AI endpoint closed the connection in the middle of the answer ({where}): {type(exc).__name__}: {exc}. "
                "The model server (or a proxy in front of it) dropped the request - most often a local model that runs out "
                "of memory or context once the tool results pile up (raise its context size, e.g. Ollama num_ctx, or use a "
                "smaller model), or a proxy's request size / time limit. Lowering 'Max tool rounds' (Settings › AI analyst) "
                "keeps the requests smaller; the server's own log names the exact reason.")
    return f"The AI endpoint could not be reached ({where}): {type(exc).__name__}: {exc}"


def _names(value: str) -> str:
    return ", ".join(x.strip() for x in str(value or "").replace("\n", ",").split(",") if x.strip())


# optional sources that can be set up in Looking Glass but switched off on the user's side (fail2ban in SWAG, Suricata
# or Q-Feeds in OPNsense): set up yet without a single event in 30 days = not in use, not a gap to report
OPTIONAL_SOURCES = ("fail2ban", "suricata", "qfeeds")


def setup_summary(s: Settings, unused: set[str] | frozenset[str] = frozenset()) -> str:
    """What the user has set up in Looking Glass, in a few lines of the system prompt: a source that is not set up
    sends nothing by design (not a gap to report), and SWAG's log files are named for what they are. ``unused``: set
    up, but no events in 30 days (OPTIONAL_SOURCES)."""
    on, off = [], []
    if s.opnsense_enabled:
        pulls = [n for n, v in (("Suricata", s.ids_pull), ("CrowdSec plugin", s.crowdsec_pull), ("Q-Feeds", s.qfeeds_pull)) if v]
        on.append("OPNsense API" + (f" ({', '.join(pulls)})" if pulls else ""))
    else:
        off.append("OPNsense API")
    (on if s.unifi_enabled else off).append("UniFi")
    (on if s.unraid_url and s.unraid_api_key else off).append("Unraid")
    (on if s.backrest_enabled else off).append("Backrest")
    (on if s.bichon_enabled else off).append("Bichon")
    if s.swag_enabled:
        on.append(f"SWAG logs (access: {_names(s.swag_access_logs) or '-'}; error: {_names(s.swag_error_logs) or '-'})")
    else:
        off.append("SWAG logs")
    (on if s.fail2ban_enabled else off).append("SWAG fail2ban")
    if s.crowdsec_lapi_enabled:
        mode = str(getattr(s, "crowdsec_shared_lapi", "auto"))
        on.append("CrowdSec Local API (Docker)" + ("" if mode == "auto" else f", shared with OPNsense: {mode}"))
    else:
        off.append("CrowdSec Local API (Docker)")
    out = f"Set up in Looking Glass: {', '.join(on) or 'nothing yet'}."
    if unused:
        out += (f" Set up but no events at all in 30 days: {', '.join(sorted(unused))} - most likely not running on the "
                "user's side on purpose: don't report it as silent or broken unless the user asks.")
    if off:
        out += (f" NOT set up: {', '.join(off)} - these send no data by design: never report their missing data as a "
                "problem, gap or silent source; mention one only when the user asks what else could be collected.")
    if s.swag_enabled:
        out += (" SWAG's access logs above are SWAG's request logs for ALL its sites, whatever the file is called (e.g. "
                "lookingglass.log = SWAG's access log in a format with the host name, written for Looking Glass to read - "
                "NOT Looking Glass's own traffic, and no sign that Looking Glass is published). The site of a request is "
                "events.domain; data.log is only the file it was read from.")
    notes = str(getattr(s, "ai_notes", "") or "").strip()
    if notes:
        out += f"\nThe user's notes about their setup (first-hand, take them as fact):\n{notes[:NOTES_MAX]}"
    return out + "\n"


NOTES_MAX = 2000


class Analyst:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._no_stream = False  # the endpoint rejected streaming once: use normal requests

    async def _system_prompt(self) -> str:
        rows = await db.pool().fetch("SELECT source, count(*) n FROM events WHERE ts > now() - interval '24 hours' GROUP BY 1 ORDER BY 2 DESC")
        volumes = ", ".join(f"{r['source']}={r['n']}" for r in rows) or "no events yet"
        unused = {r["s"] for r in await db.pool().fetch(  # one index lookup per source
            "SELECT s FROM unnest($1::text[]) s WHERE NOT EXISTS (SELECT 1 FROM events WHERE source = s "
            "AND ts > now() - interval '30 days')", list(OPTIONAL_SOURCES))}
        s = self.settings
        configured = {"fail2ban": s.fail2ban_enabled, "suricata": s.opnsense_enabled and s.ids_pull,
                      "qfeeds": s.opnsense_enabled and s.qfeeds_pull}
        unused = {src for src in unused if configured.get(src)}
        # str.replace, not str.format: the schema documentation contains braces
        return (SYSTEM_PROMPT.replace("{now}", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"))
                .replace("{local}", local_time(self.settings, date=True) + f" {self.settings.timezone or 'UTC'}")
                .replace("{style}", time_style(self.settings)).replace("{zone}", self.settings.timezone or "UTC")
                .replace("{volumes}", volumes).replace("{setup}", setup_summary(self.settings, unused)))

    async def system_message(self, private: bool) -> str:
        """The system prompt exactly as it is sent (with the privacy note in privacy mode)."""
        return await self._system_prompt() + (privacy.PROMPT_NOTE if private else "")

    async def _complete(self, client: httpx.AsyncClient, messages: list[dict[str, Any]], tools: bool = True,
                        step: int = 1, priv: privacy.Session | None = None) -> dict[str, Any]:
        """One model call (streamed when possible), retried on overload / gateway errors and timeouts.

        With ``priv`` (privacy mode) the request is pseudonymized as a whole right here, and the answer - text and tool
        calls - translated back before it is returned: everything else only ever handles the real values."""
        if priv is not None:
            # the system prompt holds no network data (and its examples must stay as written)
            messages = [m if m.get("role") == "system" else await priv.hide_message(m) for m in messages]
        msg = await self._request(client, messages, tools, step)
        return priv.reveal_message(msg) if priv is not None else msg

    async def _request(self, client: httpx.AsyncClient, messages: list[dict[str, Any]], tools: bool,
                       step: int) -> dict[str, Any]:
        body: dict[str, Any] = {"model": self.settings.ai_model, "messages": [_clean_message(m) for m in messages],
                                "max_tokens": 16000}
        if tools:
            body.update(tools=TOOLS, tool_choice="auto")
        started = time.monotonic()
        last: Exception | None = None
        attempts, again, stream = 0, False, True
        request_log.info("AI request: step %d, %d messages, model %s at %s", step, len(messages), self.settings.ai_model,
                 str(client.base_url))
        for attempt in range(3):
            if attempt and not again:
                await asyncio.sleep(last.retry_after if isinstance(last, AIError) and last.retry_after else 5 * 4 ** (attempt - 1))
            again = False
            attempts += 1
            if attempt == 2 and step > 1:
                body["messages"] = compact_tool_results(body["messages"])  # last try: a smaller request
            try:
                if self.settings.ai_stream and not self._no_stream and stream:
                    try:
                        return await self._stream(client, body)
                    except AIError as exc:
                        if exc.status in (400, 404, 415, 422) and "stream" in exc.body.lower():
                            log.info("AI endpoint does not stream (%s) - using normal requests", exc.status)
                            self._no_stream = True
                        else:
                            raise
                r = await client.post("chat/completions", json=body)
                if r.status_code >= 400:
                    raise AIError(r.status_code, r.text, r.headers.get("retry-after"))
                return r.json()["choices"][0]["message"]
            except AIError as exc:
                last = exc
                if exc.status in (400, 422) and any(m.get("role") == "tool" for m in body["messages"]):
                    # some servers / chat templates reject tool call messages in the history: send them as plain text
                    log.warning("AI endpoint refused tool messages (HTTP %d: %s) - retrying with tool results as text",
                                exc.status, exc.body[:500] or "empty answer")
                    body["messages"] = plain_tool_history(body["messages"])
                    again = True
                    continue
                if exc.status not in RETRY_STATUS:
                    log.warning("AI request (step %d) refused: HTTP %d %s", step, exc.status, exc.body[:500] or "(empty answer)")
                    break
            except (httpx.RemoteProtocolError, httpx.ReadError) as exc:
                # connection dropped in the middle of the answer: some gateways break on long streams, try a normal request
                last, stream = exc, False
            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                last = exc
            log.warning("AI request (step %d, attempt %d) failed: %s", step, attempt + 1, last)
        raise RuntimeError(explain_ai_error(last, time.monotonic() - started, step, self.settings, attempts)) from last

    async def _stream(self, client: httpx.AsyncClient, body: dict[str, Any]) -> dict[str, Any]:
        """OpenAI-compatible server-sent events: content and tool call fragments are put back together."""
        content: list[str] = []
        calls: dict[int, dict[str, Any]] = {}
        async with client.stream("POST", "chat/completions", json={**body, "stream": True}) as r:
            if r.status_code >= 400:
                raise AIError(r.status_code, (await r.aread()).decode(errors="replace"), r.headers.get("retry-after"))
            if "text/event-stream" not in r.headers.get("content-type", "") and "stream" not in r.headers.get("content-type", ""):
                data = json.loads(await r.aread())  # the endpoint ignored "stream": a normal answer
                return data["choices"][0]["message"]
            async for line in r.aiter_lines():
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    break
                try:
                    chunk = json.loads(payload)
                except ValueError:
                    continue
                if chunk.get("error"):
                    err = chunk["error"]
                    raise AIError(int(err.get("code") or 500) if str(err.get("code", "")).isdigit() else 500,
                                  json.dumps(err)[:500])
                for choice in chunk.get("choices") or []:
                    delta = choice.get("delta") or {}
                    if delta.get("content"):
                        content.append(delta["content"])
                    for tc in delta.get("tool_calls") or []:
                        cur = calls.setdefault(int(tc.get("index", len(calls))), {"id": None, "name": "", "arguments": ""})
                        cur["id"] = tc.get("id") or cur["id"]
                        fn = tc.get("function") or {}
                        if fn.get("name") and cur["name"] not in TOOL_NAMES:  # some servers repeat the name per chunk
                            cur["name"] += fn["name"]
                        cur["arguments"] += fn.get("arguments") or ""
        msg: dict[str, Any] = {"role": "assistant", "content": "".join(content)}
        if calls:
            msg["tool_calls"] = [{"id": c["id"] or f"call_{i}", "type": "function",
                                  "function": {"name": c["name"], "arguments": c["arguments"] or "{}"}}
                                 for i, c in sorted(calls.items())]
        return msg

    async def chat(self, history: list[dict[str, Any]], user_message: str) -> list[dict[str, Any]]:
        """Run the agent loop. ``history`` holds earlier user/assistant/tool messages (no system prompt).

        Returns the new messages produced in this turn (user message included)."""
        if not self.settings.ai_enabled:
            raise RuntimeError("AI is not configured: set AI_BASE_URL, AI_API_KEY and AI_MODEL")
        request_log.info("AI analysis started: %s", user_message[:120].replace("\n", " "))
        new: list[dict[str, Any]] = [{"role": "user", "content": user_message}]
        priv = await privacy.session(self.settings) if self.settings.ai_privacy else None
        system = {"role": "system", "content": await self.system_message(priv is not None)}
        base = self.settings.ai_base_url.rstrip("/") + "/"
        headers = {"Authorization": f"Bearer {self.settings.ai_api_key}"}
        async with httpx.AsyncClient(base_url=base, headers=headers, timeout=self.settings.ai_timeout) as client:
            for step in range(1, self.settings.ai_max_tool_rounds + 1):
                msg = await self._complete(client, [system, *history, *new], step=step, priv=priv)
                assistant: dict[str, Any] = {"role": "assistant", "content": msg.get("content") or ""}
                calls = msg.get("tool_calls") or []
                if calls:
                    assistant["tool_calls"] = [{"id": c.get("id") or f"call_{step}_{i}", "type": "function",
                                                "function": {"name": c["function"]["name"],
                                                             "arguments": _valid_json(c["function"].get("arguments"))}}
                                               for i, c in enumerate(calls)]
                    calls = assistant["tool_calls"]
                new.append(assistant)
                if not calls:
                    return new
                for c in calls:
                    try:
                        args = json.loads(c["function"].get("arguments") or "{}")
                    except ValueError:
                        args = {}
                    result = await run_tool(c["function"]["name"], args if isinstance(args, dict) else {}, self.settings)
                    new.append({"role": "tool", "tool_call_id": c["id"], "content": result})
            # out of tool rounds: ask for a final answer without tools
            final = await self._complete(client, [system, *history, *new, {"role": "user", "content":
                                         "Tool budget exhausted. Give your final answer now based on what you found."}],
                                         tools=False, step=self.settings.ai_max_tool_rounds + 1, priv=priv)
            new.append({"role": "assistant", "content": final.get("content") or ""})
            return new

    async def analyse(self, hours: int = 24, data: dict[str, Any] | None = None) -> str:
        prompt = review_prompt(hours, (data or {}).get("categories"))
        if data:
            # the report's numbers up front: the model only needs tools to dig into what stands out (fewer, shorter
            # requests - long agent runs are what gateways time out on)
            prompt += ("\n\nThe report data for this period is already collected (JSON below). Base the review on it and "
                       "use the tools only to investigate specific findings in more depth.\n\n" + _dump(data, 30000))
        msgs = await self.chat([], prompt)
        return msgs[-1].get("content") or ""
