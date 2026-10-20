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

from . import db
from .config import Settings, local_time, time_style
from .reports import build_report

log = logging.getLogger(__name__)

SCHEMA_DOC = """
PostgreSQL tables you can query with sql_query (read only):

events(id bigint, ts timestamptz, received_at timestamptz, source text, host text, program text,
       severity smallint /*syslog 0=emerg..7=debug*/, action text, src_ip inet, src_port int, dst_ip inet, dst_port int,
       proto text, interface text, direction text, username text, domain text, src_country text, dst_country text,
       message text, data jsonb, uid text)
  source values: firewall (pf filterlog), nginx (web server/reverse proxy), unbound (DNS), crowdsec, suricata (IDS/IPS),
                 zenarmor (L7 firewall/NGFW), qfeeds (threat intel blocks), auth (ssh / web GUI logins), vpn, dhcp, system,
                 unraid (Unraid syslog + notifications, host = server name), docker (Unraid container logs, program = container),
                 unifi (UniFi controller events: Wi-Fi / wired clients and APs / switches; src_ip = client IP when known)
  action examples: firewall: pass/block; nginx: http_200, http_404, waf_block, rate_limited; unbound: query, reply,
                   block, nxdomain; crowdsec: alert, ban; suricata: alert, drop, blocked; auth: login_failed, login_success,
                   config_change; dhcp: lease; unifi: client_connect, client_disconnect, client_roam, client_blocked,
                   device_offline, device_online, device_restart, rogue_ap, rogue_dhcp, poe_disconnect, login_success / login_failed (controller admin logins), ips_alert
  data keys: firewall {label (rule description), rid, reason, tcpflags}; nginx {method, path, status, user_agent, tags[]};
             unbound {qtype, rcode, blocklist, category}; suricata {sid, signature, classification, priority};
             crowdsec {scenario, decisions}; zenarmor {app_name, app_category, security_tags, ...};
             unifi {key (EVT_...), mac (client), ap, ap_from, ap_to, ssid, sw, port, subsystem}
alerts(id, created_at, last_seen, rule, severity /*info|low|medium|high|critical*/, title, description, src_ip inet,
       dst_ip inet, count int, status /*open|acknowledged|closed*/, fingerprint, data jsonb)
metrics(ts, name, labels, value)  names: memory_used_pct, load1, pf_states, pf_states_pct, disk_used_pct, temperature,
       gateway_delay_ms, gateway_loss_pct, if_rx_bps, if_tx_bps (labels = interface), if_received_errors, ...
devices(mac, ip, hostname, name_source, vendor, interface, sources text[], lease_type, lease_expires, online, trusted, notes,
        conn_type /*wifi|wired, from UniFi*/, conn_where /*'AP Living room · Home (5 GHz)' / 'Switch Office port 5'*/,
        conn_signal /*dBm*/, conn_seen, first_seen, last_seen)   -- network inventory: ARP, DHCP leases, UniFi clients, Zenarmor
device_profile(key /*MAC or IP*/, kind /*country|port|domain|tls|hour*/, value, first_seen, last_seen, hits)
       -- what is NORMAL for each device (learned); device_hourly(key, hour, ip, features jsonb: connections, destinations,
       ports, countries, dns, failed_lookups, blocked, upload_mb) -- per device and hour
risk_scores(entity /*IP*/, score, parts jsonb [{rule, severity, points}], updated)  -- alerts add points that fade
intel_indicators(kind /*domain|ip|ja3*/, value, feed /*urlhaus|threatfox|feodo|sslbl_ja3|tor_relay|tor_exit*/, info)
seen_domains(domain, first_seen, first_client, registered /*RDAP*/)  -- first lookup of each domain on the network
snapshots(key, ts, data jsonb)  keys: system, activity (top processes), gateways, interfaces, services, firmware, arp,
       leases_kea / leases_dnsmasq / leases_isc, unbound_totals, crowdsec_decisions, qfeeds_stats, poller_status,
       unifi:devices (APs / switches: state, model, firmware, upgradable, cpu, mem, clients, ports[], radios[]),
       unifi:clients (connected now: mac, ip, alias, hostname, wired, ssid, ap, switch, port, signal, satisfaction, tx/rx_bytes),
       unifi:health, unifi:rogue (neighbouring APs; evil_twin = foreign AP using one of your SSIDs), unifi:status,
       unraid:<server id>:<info|metrics|temps|storage (array + per-pool groups, spin state)|array|docker|docker_stats|notifications|vms|ups|shares|disks (SMART)>, unraid_status
metrics also: cpu_used_pct, swap_used_pct, unraid_cpu_pct / unraid_mem_pct / unraid_temp / unraid_disk_temp /
       unraid_array_used_pct / unraid_pool_used_pct / unraid_group_spinning (labels '<server id>[:<item>]'), container_cpu_pct / container_mem_bytes ('<server id>:<container>'),
       unifi_clients (labels wifi|wired), unifi_ssid_clients / unifi_ap_clients (labels = SSID / AP name), unifi_wifi_satisfaction,
       unifi_device_cpu / unifi_device_mem / unifi_device_tx_bps / unifi_device_rx_bps (labels = device name)

Tips: use host(src_ip) to print addresses, `src_ip << '10.0.0.0/8'::inet` for subnet tests, ts > now() - interval '24 hours'
for time windows. Always aggregate (GROUP BY / count) rather than pulling raw rows when looking at large volumes.
"""

SYSTEM_PROMPT = """You are Looking Glass's security analyst, a senior SOC / network security engineer investigating an
OPNsense firewall, the network behind it (UniFi access points / switches when configured) and the user's Unraid
server(s). You have tools that query the log database (firewall, nginx, Unbound DNS, CrowdSec, Suricata IDS, Zenarmor,
Q-Feeds threat intel, authentication, VPN, DHCP, UniFi and system logs) plus OPNsense and UniFi state.

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
- Combine sources: OPNsense / Zenarmor / DNS tell WHAT a device does, UniFi tells WHERE it is (AP or switch port, SSID /
  VLAN, signal) and since when. Use that to name the device, judge whether it belongs on that network (e.g. an IoT plug on
  the main SSID, an unknown wired device on a free switch port) and to give exact containment steps (UniFi Network ›
  Client Devices › Block, move it to an isolated SSID / VLAN, disable the switch port, or an OPNsense rule).
- Be concise; use markdown headings, bullet lists and tables.

Current time: {now} UTC = {local}. Timestamps in the data are UTC; when you write times for the user, convert them
to {style} (convert in SQL with AT TIME ZONE '{zone}' or yourself).
Data volume in the last 24h by source: {volumes}
""" + SCHEMA_DOC

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
            "source": {"type": "string", "description": "firewall, nginx, unbound, crowdsec, suricata, zenarmor, qfeeds, auth, vpn, dhcp, system, unifi, unraid, docker"},
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
        "name": "list_alerts",
        "description": "List alerts raised by the detection engine.",
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
    text = json.dumps(db.jsonable(value), default=str)
    if len(text) > limit:
        text = text[:limit] + f'... [truncated, {len(text)} chars total - narrow the query]'
    return text


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
    device = await pool.fetchrow("SELECT * FROM devices WHERE ip = $1::inet", ip)
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
        f"SELECT id, created_at, last_seen, rule, severity, title, description, host(src_ip) src, host(dst_ip) dst, count, status "
        f"FROM alerts WHERE last_seen > now() - make_interval(secs => $1) {cond} "
        f"ORDER BY array_position(ARRAY['critical','high','medium','low','info'], severity), last_seen DESC LIMIT $2", *args)
    return db.records(rows)


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


async def run_tool(name: str, args: dict[str, Any]) -> str:
    fn = {"sql_query": tool_sql_query, "search_events": tool_search_events, "ip_profile": tool_ip_profile,
          "list_alerts": tool_list_alerts, "system_status": tool_system_status, "unifi_status": tool_unifi_status,
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


class AIError(Exception):
    def __init__(self, status: int, body: str, retry_after: str | None = None) -> None:
        self.status, self.body = status, body or ""
        try:
            self.retry_after = min(60.0, float(retry_after)) if retry_after else None
        except ValueError:
            self.retry_after = None
        super().__init__(f"HTTP {status}")


def explain_ai_error(exc: Exception | None, seconds: float, step: int, s: Settings) -> str:
    """A readable reason (and what to do) instead of a bare status code."""
    where = f"step {step} of the analysis, after {seconds:.0f} s and 3 attempts"
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
            401: " The API key was refused (Settings › AI analyst).",
            403: " The API key may not use this model, or the account has no credits.",
            404: " Wrong base URL or model name (Settings › AI analyst).",
            413: " The request was too large for the endpoint - lower 'Max tool rounds'.",
        }.get(exc.status, "")
        return head + hint + (f" Details: {text}" if text else "")
    if isinstance(exc, httpx.TimeoutException):
        return (f"No answer from the AI endpoint within {s.ai_timeout} s ({where}). Raise 'Request timeout' "
                "(Settings › AI analyst) or keep 'Stream answers' on.")
    return f"The AI endpoint could not be reached ({where}): {type(exc).__name__}: {exc}"


class Analyst:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._no_stream = False  # the endpoint rejected streaming once: use normal requests

    async def _system_prompt(self) -> str:
        rows = await db.pool().fetch("SELECT source, count(*) n FROM events WHERE ts > now() - interval '24 hours' GROUP BY 1 ORDER BY 2 DESC")
        volumes = ", ".join(f"{r['source']}={r['n']}" for r in rows) or "no events yet"
        # str.replace, not str.format: the schema documentation contains braces
        return (SYSTEM_PROMPT.replace("{now}", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"))
                .replace("{local}", local_time(self.settings, date=True) + f" {self.settings.timezone or 'UTC'}")
                .replace("{style}", time_style(self.settings)).replace("{zone}", self.settings.timezone or "UTC")
                .replace("{volumes}", volumes))

    async def _complete(self, client: httpx.AsyncClient, messages: list[dict[str, Any]], tools: bool = True,
                        step: int = 1) -> dict[str, Any]:
        """One model call (streamed when possible), retried on overload / gateway errors and timeouts."""
        body: dict[str, Any] = {"model": self.settings.ai_model, "messages": messages, "max_tokens": 16000}
        if tools:
            body.update(tools=TOOLS, tool_choice="auto")
        started = time.monotonic()
        last: Exception | None = None
        for attempt in range(3):
            if attempt:
                await asyncio.sleep(last.retry_after if isinstance(last, AIError) and last.retry_after else 5 * 4 ** (attempt - 1))
            try:
                if self.settings.ai_stream and not self._no_stream:
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
                if exc.status not in RETRY_STATUS:
                    break
            except (httpx.TimeoutException, httpx.RemoteProtocolError, httpx.ConnectError) as exc:
                last = exc
            log.warning("AI request (step %d, attempt %d) failed: %s", step, attempt + 1, last)
        raise RuntimeError(explain_ai_error(last, time.monotonic() - started, step, self.settings)) from last

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
                        cur["name"] += fn.get("name") or ""
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
        new: list[dict[str, Any]] = [{"role": "user", "content": user_message}]
        system = {"role": "system", "content": await self._system_prompt()}
        base = self.settings.ai_base_url.rstrip("/") + "/"
        headers = {"Authorization": f"Bearer {self.settings.ai_api_key}"}
        async with httpx.AsyncClient(base_url=base, headers=headers, timeout=self.settings.ai_timeout) as client:
            for step in range(1, self.settings.ai_max_tool_rounds + 1):
                msg = await self._complete(client, [system, *history, *new], step=step)
                assistant: dict[str, Any] = {"role": "assistant", "content": msg.get("content") or ""}
                calls = msg.get("tool_calls") or []
                if calls:
                    assistant["tool_calls"] = [{"id": c["id"], "type": "function",
                                                "function": {"name": c["function"]["name"], "arguments": c["function"].get("arguments") or "{}"}}
                                               for c in calls]
                new.append(assistant)
                if not calls:
                    return new
                for c in calls:
                    try:
                        args = json.loads(c["function"].get("arguments") or "{}")
                    except ValueError:
                        args = {}
                    result = await run_tool(c["function"]["name"], args if isinstance(args, dict) else {})
                    new.append({"role": "tool", "tool_call_id": c["id"], "content": result})
            # out of tool rounds: ask for a final answer without tools
            final = await self._complete(client, [system, *history, *new, {"role": "user", "content":
                                         "Tool budget exhausted. Give your final answer now based on what you found."}],
                                         tools=False, step=self.settings.ai_max_tool_rounds + 1)
            new.append({"role": "assistant", "content": final.get("content") or ""})
            return new

    async def analyse(self, hours: int = 24, data: dict[str, Any] | None = None) -> str:
        prompt = (f"Perform a full security review of the last {hours} hours. Check open alerts, blocked and allowed traffic, "
                  "inbound exposure, outbound anomalies from internal hosts, DNS, web server, IDS, CrowdSec, Zenarmor, Q-Feeds, "
                  "authentication and system health. Report: 1) executive summary, 2) findings ranked by severity with evidence, "
                  "3) recommended actions, 4) blind spots (missing log sources).")
        if data:
            # the report's numbers up front: the model only needs tools to dig into what stands out (fewer, shorter
            # requests - long agent runs are what gateways time out on)
            prompt += ("\n\nThe report data for this period is already collected (JSON below). Base the review on it and "
                       "use the tools only to investigate specific findings in more depth.\n\n" + _dump(data, 30000))
        msgs = await self.chat([], prompt)
        return msgs[-1].get("content") or ""
