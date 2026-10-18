"""AI security analyst: an agent loop over any OpenAI compatible ``/chat/completions`` endpoint.

Works with Anthropic's OpenAI SDK compatibility layer (base URL ``https://api.anthropic.com/v1/``),
OpenAI itself, OpenRouter, LiteLLM, Ollama, LM Studio, vLLM ... anything that speaks the
chat-completions + tools protocol.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from . import db
from .config import Settings
from .reports import build_report

log = logging.getLogger(__name__)

SCHEMA_DOC = """
PostgreSQL tables you can query with sql_query (read only):

events(id bigint, ts timestamptz, received_at timestamptz, source text, host text, program text,
       severity smallint /*syslog 0=emerg..7=debug*/, action text, src_ip inet, src_port int, dst_ip inet, dst_port int,
       proto text, interface text, direction text, username text, domain text, src_country text, dst_country text,
       message text, data jsonb, uid text)
  source values: firewall (pf filterlog), nginx (web server/reverse proxy), unbound (DNS), crowdsec, suricata (IDS/IPS),
                 zenarmor (L7 firewall/NGFW), qfeeds (threat intel blocks), auth (ssh / web GUI logins), vpn, dhcp, system
  action examples: firewall: pass/block; nginx: http_200, http_404, waf_block, rate_limited; unbound: query, reply,
                   block, nxdomain; crowdsec: alert, ban; suricata: alert, drop, blocked; auth: login_failed, login_success,
                   config_change; dhcp: lease
  data keys: firewall {label (rule description), rid, reason, tcpflags}; nginx {method, path, status, user_agent, tags[]};
             unbound {qtype, rcode, blocklist, category}; suricata {sid, signature, classification, priority};
             crowdsec {scenario, decisions}; zenarmor {app_name, app_category, security_tags, ...}
alerts(id, created_at, last_seen, rule, severity /*info|low|medium|high|critical*/, title, description, src_ip inet,
       dst_ip inet, count int, status /*open|acknowledged|closed*/, fingerprint, data jsonb)
metrics(ts, name, labels, value)  names: memory_used_pct, load1, pf_states, pf_states_pct, disk_used_pct, temperature,
       gateway_delay_ms, gateway_loss_pct, if_rx_bps, if_tx_bps (labels = interface), if_received_errors, ...
devices(mac, ip, hostname, first_seen, last_seen)
snapshots(key, ts, data jsonb)  keys: system, gateways, interfaces, services, firmware, arp, unbound_totals,
       crowdsec_decisions, qfeeds_stats, poller_status

Tips: use host(src_ip) to print addresses, `src_ip << '10.0.0.0/8'::inet` for subnet tests, ts > now() - interval '24 hours'
for time windows. Always aggregate (GROUP BY / count) rather than pulling raw rows when looking at large volumes.
"""

SYSTEM_PROMPT = """You are MonRaider's security analyst, a senior SOC / network security engineer investigating an
OPNsense firewall and the network behind it. You have tools that query the log database (firewall, nginx, Unbound DNS,
CrowdSec, Suricata IDS, Zenarmor, Q-Feeds threat intel, authentication, VPN, DHCP and system logs) plus
OPNsense system state.

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
- Be concise; use markdown headings, bullet lists and tables.

Current time (UTC): {now}
Data volume in the last 24h by source: {volumes}
""" + SCHEMA_DOC

TOOLS: list[dict[str, Any]] = [
    {"type": "function", "function": {
        "name": "sql_query",
        "description": "Run one read-only SQL SELECT/WITH query against the MonRaider PostgreSQL database. Returns up to 200 rows as JSON.",
        "parameters": {"type": "object", "properties": {"query": {"type": "string", "description": "A single SELECT statement"}},
                       "required": ["query"]}}},
    {"type": "function", "function": {
        "name": "search_events",
        "description": "Search raw log events with simple filters. Prefer sql_query for aggregations.",
        "parameters": {"type": "object", "properties": {
            "source": {"type": "string", "description": "firewall, nginx, unbound, crowdsec, suricata, zenarmor, qfeeds, auth, vpn, dhcp, system"},
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
        "description": "Current OPNsense system state: resources, versions, gateways, services, firmware/updates, log ingestion stats and which API endpoints work.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "traffic_overview",
        "description": "Aggregated statistics (top blocked sources, ports, countries, DNS, web, auth failures, IDS signatures ...) for a period.",
        "parameters": {"type": "object", "properties": {"hours": {"type": "number", "description": "default 24"}}}}},
]

_FORBIDDEN = re.compile(r"\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|copy|vacuum|call|do|lock|set|reset|"
                        r"pg_sleep|pg_read|pg_ls|lo_import|lo_export|dblink|pg_terminate|pg_cancel)\b", re.I)


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
    return out


async def run_tool(name: str, args: dict[str, Any]) -> str:
    fn = {"sql_query": tool_sql_query, "search_events": tool_search_events, "ip_profile": tool_ip_profile,
          "list_alerts": tool_list_alerts, "system_status": tool_system_status,
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


class Analyst:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def _system_prompt(self) -> str:
        rows = await db.pool().fetch("SELECT source, count(*) n FROM events WHERE ts > now() - interval '24 hours' GROUP BY 1 ORDER BY 2 DESC")
        volumes = ", ".join(f"{r['source']}={r['n']}" for r in rows) or "no events yet"
        # str.replace, not str.format: the schema documentation contains braces
        return (SYSTEM_PROMPT.replace("{now}", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"))
                .replace("{volumes}", volumes))

    async def _complete(self, client: httpx.AsyncClient, messages: list[dict[str, Any]]) -> dict[str, Any]:
        body = {"model": self.settings.ai_model, "messages": messages, "tools": TOOLS, "tool_choice": "auto", "max_tokens": 16000}
        r = await client.post("chat/completions", json=body)
        if r.status_code >= 400:
            raise RuntimeError(f"AI endpoint returned HTTP {r.status_code}: {r.text[:500]}")
        data = r.json()
        return data["choices"][0]["message"]

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
            for _ in range(self.settings.ai_max_tool_rounds):
                msg = await self._complete(client, [system, *history, *new])
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
            body = {"model": self.settings.ai_model, "max_tokens": 16000,
                    "messages": [system, *history, *new, {"role": "user", "content": "Tool budget exhausted. Give your final answer now based on what you found."}]}
            r = await client.post("chat/completions", json=body)
            r.raise_for_status()
            new.append({"role": "assistant", "content": r.json()["choices"][0]["message"].get("content") or ""})
            return new

    async def analyse(self, hours: int = 24) -> str:
        prompt = (f"Perform a full security review of the last {hours} hours. Check open alerts, blocked and allowed traffic, "
                  "inbound exposure, outbound anomalies from internal hosts, DNS, web server, IDS, CrowdSec, Zenarmor, Q-Feeds, "
                  "authentication and system health. Report: 1) executive summary, 2) findings ranked by severity with evidence, "
                  "3) recommended actions, 4) blind spots (missing log sources).")
        msgs = await self.chat([], prompt)
        return msgs[-1].get("content") or ""
