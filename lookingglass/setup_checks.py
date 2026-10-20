"""Setup checklist: per data source, what is arriving, through which channel, and what (not) to do.

Channels are told apart by the event's dedupe id: API pulls set ``uid`` (dns:, ngx:, ids:, cs-, qf:),
syslog lines don't. Zenarmor's Elasticsearch stream uses program ``zenarmor-es``.
Each check returns a status:
  ok        - receiving, nothing to do
  action    - something has to be done to get this data (``todo``)
  duplicate - the same data arrives twice; switch one channel off (``todo``)
  optional  - not set up / not installed; only needed if you use it
  info      - working, with a tip
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any

from . import db
from .config import Settings, local_time
from .ingest import STATS

PRIV = "System › Access › Users › (Looking Glass user) › Privileges"


def _job(poller: dict[str, Any], name: str) -> dict[str, Any]:
    return poller.get(name) or {}


def _api_problem(job: dict[str, Any], what: str) -> str | None:
    if job.get("forbidden"):
        return f"The OPNsense API user may not read {what}: add the matching page under {PRIV} (or 'GUI - All pages')."
    if job.get("ok") is False and not job.get("unsupported"):
        return f"API error: {job.get('error')}"
    return None


async def run(settings: Settings) -> dict[str, Any]:
    pool = db.pool()
    rows = await pool.fetch(
        "SELECT source, uid IS NOT NULL AS api, coalesce(program, '') AS program, count(*) n, max(ts) last, "
        "count(*) FILTER (WHERE action ~ '^http_') http, count(*) FILTER (WHERE src_ip IS NULL) no_ip, "
        # Unbound syslog lines that are query / reply log lines (service messages have no action)
        "count(*) FILTER (WHERE action IN ('query', 'reply') OR (source = 'unbound' AND action NOT IN ('block'))) queries, "
        "count(*) FILTER (WHERE action = 'block') blocks "
        "FROM events WHERE ts > now() - interval '24 hours' GROUP BY 1, 2, 3")
    agg: dict[str, dict[str, Any]] = {}

    def add(key: str, r: Any) -> None:
        a = agg.setdefault(key, {"n": 0, "last": None, "http": 0, "no_ip": 0, "queries": 0, "blocks": 0})
        a["n"] += r["n"]
        a["http"] += r["http"]
        a["queries"] += r["queries"]
        a["blocks"] += r["blocks"]
        a["no_ip"] += r["no_ip"]
        if r["last"] and (a["last"] is None or r["last"] > a["last"]):
            a["last"] = r["last"]

    for r in rows:
        src = r["source"]
        add(src, r)
        add(f"{src}:{'api' if r['api'] else 'syslog'}", r)
        if src == "zenarmor":
            add("zenarmor:es" if r["program"] == "zenarmor-es" else "zenarmor:syslog", r)

    def n(key: str) -> int:
        return agg.get(key, {}).get("n", 0)

    def last(*keys: str) -> Any:
        vals = [agg[k]["last"] for k in keys if k in agg and agg[k]["last"]]
        return max(vals).isoformat() if vals else None

    poller = await db.get_snapshot("poller_status") or {}
    vpn = await db.get_snapshot("vpn") or {}
    # syslog evidence: lines received since start, or syslog-born events stored in the last 24 hours
    syslog_db = sum(r["n"] for r in rows if not r["api"] and r["program"] != "zenarmor-es" and r["source"] not in ("unraid", "docker"))
    syslog_total = max(STATS.received, syslog_db)
    checks: list[dict[str, Any]] = []

    def check(id_: str, name: str, status: str, via: list[str], summary: str, todo: list[str] | None = None,
              avoid: list[str] | None = None, count: int | None = None, last_seen: Any = None, link: str | None = None) -> None:
        checks.append({"id": id_, "name": name, "status": status, "via": via, "summary": summary, "todo": todo or [],
                       "avoid": avoid or [], "count": count, "last": last_seen, "link": link})

    # ------------------------------------------------------------- basics ---
    sysjob = _job(poller, "system")
    if not settings.opnsense_enabled:
        check("api", "OPNsense API", "action", [], "Not configured - system state, DNS statistics, VPN, nginx, IDS, "
              "CrowdSec and Q-Feeds all come from the API.",
              ["Looking Glass › Settings › OPNsense: enter URL, API key and secret, Test connection, Save."], link="/settings#opnsense")
    elif sysjob.get("ok"):
        forbidden = sorted(k for k, v in poller.items() if v.get("forbidden"))
        check("api", "OPNsense API", "info" if forbidden else "ok", ["API"],
              "Connected." + (f" Refused for: {', '.join(forbidden)}." if forbidden else ""),
              [f"{PRIV}: allow the pages for {', '.join(forbidden)} (simplest: 'GUI - All pages')."] if forbidden else [],
              last_seen=sysjob.get("last"))
    else:
        check("api", "OPNsense API", "action", ["API"], f"Not working: {sysjob.get('error') or 'waiting for the first poll'}",
              ["Check URL, key and secret under Looking Glass › Settings › OPNsense (Test connection)."], link="/settings#opnsense")

    if not settings.syslog_enabled:
        check("syslog", "Remote syslog", "optional", [], "The syslog receiver is disabled (SYSLOG_ENABLED=false).")
    elif not syslog_total:
        check("syslog", "Remote syslog", "action", [], "Nothing received yet. Firewall, login and system logs only arrive this way.",
              ["OPNsense › System › Settings › Logging › Remote › +: Transport UDP(4), Applications empty, Levels info and up, "
               "Hostname = Docker host IP, Port = the published syslog port (514), rfc5424 ✓, Save, Apply."])
    else:
        check("syslog", "Remote syslog", "ok", ["syslog"],
              f"{syslog_db:,} syslog events stored in 24 hours"
              + (f"; sending: {', '.join(STATS.senders)}." if STATS.senders else "."), count=syslog_db)

    # ----------------------------------------------------------- firewall ---
    fw_sys, fw_api = n("firewall:syslog"), _job(poller, "firewall_log")
    pull = settings.firewall_log_pull.lower()
    if STATS.by_source.get("firewall") and pull == "always":
        check("firewall", "Firewall", "duplicate", ["syslog", "API"], "filterlog arrives via syslog and is also pulled via the API.",
              ["Looking Glass › Settings › OPNsense › Pull firewall log via API: set to 'auto'."], count=fw_sys, last_seen=last("firewall"))
    elif fw_sys:
        check("firewall", "Firewall", "ok", ["syslog"], "filterlog via syslog (the API pull switches itself off).",
              avoid=["Pull firewall log via API = 'always' (would duplicate)."], count=fw_sys, last_seen=last("firewall"), link="/dash/firewall")
    elif n("firewall"):
        check("firewall", "Firewall", "info", ["API"], "Pulled from the live firewall log via the API (up to 1000 lines per poll, "
              "busy periods can be incomplete).",
              ["For complete logs send filterlog via remote syslog (Applications empty or 'filter (filterlog)')."],
              count=n("firewall"), last_seen=last("firewall"), link="/dash/firewall")
    else:
        check("firewall", "Firewall", "action", [], "No firewall log lines in 24 hours.",
              ["Set up remote syslog (above).", "OPNsense › Firewall › Rules: tick 'Log packets' on the rules you care about "
               "(default block rules are logged already)."])

    # ---------------------------------------------------------------- DNS ---
    # only query / reply / blocked-name log lines duplicate the API - Unbound's own service messages don't
    dns_api = n("unbound:api")
    dns_q_sys = agg.get("unbound:syslog", {}).get("queries", 0)
    dns_b_sys = agg.get("unbound:syslog", {}).get("blocks", 0)
    dns_sys = dns_q_sys + dns_b_sys
    uq = _job(poller, "unbound_queries")
    dns_link = "/dash/dns"
    if not settings.unbound_query_pull and not dns_sys:
        check("dns", "DNS (Unbound)", "action", [], "API pull is switched off and no Unbound query logs arrive via syslog.",
              ["Looking Glass › Settings › OPNsense › Pull Unbound DNS queries: on."])
    elif dns_api and dns_sys:
        what = [x for x, on in (("'Log queries'", dns_q_sys), ("'Log local actions'", dns_b_sys)) if on]
        check("dns", "DNS (Unbound)", "duplicate", ["API", "syslog"],
              f"Queries arrive twice: from the Unbound statistics API and as Unbound log lines ({dns_q_sys:,} query / reply "
              f"lines, {dns_b_sys:,} blocked-name lines in 24h).",
              [f"OPNsense › Services › Unbound DNS › Advanced: untick {' and '.join(what)} (and 'Log replies' if ticked), Save. "
               "The API already has every query with client and blocklist."],
              count=dns_api, last_seen=last("unbound"), link=dns_link)
    elif dns_api:
        miss = agg.get("unbound:api", {}).get("no_ip", 0)
        check("dns", "DNS (Unbound)", "info" if miss else "ok", ["API"],
              "Per-client queries from the Unbound statistics API." +
              (f" {miss:,} queries have a client hostname Looking Glass couldn't map to an IP." if miss else ""),
              ["Give those devices a DHCP lease or static mapping on OPNsense so they show up in the device list."] if miss else [],
              avoid=["Unbound › Advanced › Log queries / Log replies (would duplicate every query)."],
              count=dns_api, last_seen=last("unbound"), link=dns_link)
    elif uq.get("forbidden"):
        check("dns", "DNS (Unbound)", "action", ["API"], "The API user may not read Unbound statistics.",
              [f"{PRIV}: add 'Reporting: Unbound DNS' (or 'GUI - All pages')."])
    elif dns_sys:
        check("dns", "DNS (Unbound)", "info", ["syslog"], "Query log lines via syslog.",
              ["Better: OPNsense › Reporting › Settings › Unbound DNS statistics ✓ (adds blocklist info), then untick "
               "'Log queries' / 'Log replies' in Unbound › Advanced to avoid duplicates."], count=dns_sys, last_seen=last("unbound"), link=dns_link)
    else:
        check("dns", "DNS (Unbound)", "action", ["API"] if uq.get("ok") else [],
              "No DNS queries yet." + (f" {_api_problem(uq, 'Unbound statistics')}" if _api_problem(uq, "Unbound statistics") else ""),
              ["OPNsense › Reporting › Settings: tick 'Unbound DNS statistics', Save. (No Unbound query logging needed.)"])

    # -------------------------------------------------------------- nginx ---
    ngx_api, ngx_sys = n("nginx:api"), agg.get("nginx:syslog", {}).get("http", 0)
    nj = _job(poller, "nginx_logs")
    if ngx_api and ngx_sys:
        check("nginx", "Web server (nginx)", "duplicate", ["API", "syslog"], "Access logs arrive via the nginx API and via a "
              "nginx SYSLOG target - every request is counted twice.",
              ["Either remove the SYSLOG target (OPNsense › Services › Nginx › HTTP(S) › HTTP Server › SYSLOG targets), or switch "
               "off Looking Glass › Settings › OPNsense › Pull nginx access / error logs."],
              count=ngx_api, last_seen=last("nginx"), link="/dash/web")
    elif ngx_api or (nj.get("ok") and settings.nginx_pull):
        check("nginx", "Web server (nginx)", "ok", ["API"], "Access, error and stream logs via the nginx API (every minute)." +
              ("" if ngx_api else " No requests in 24 hours."),
              avoid=["A nginx SYSLOG target (would duplicate)."], count=ngx_api, last_seen=last("nginx"), link="/dash/web")
    elif ngx_sys:
        check("nginx", "Web server (nginx)", "ok", ["syslog"], "Access logs via a nginx SYSLOG target.",
              avoid=["Turning the nginx API pull back on (would duplicate)."], count=ngx_sys, last_seen=last("nginx"), link="/dash/web")
    elif nj.get("forbidden"):
        check("nginx", "Web server (nginx)", "action", [], "The API user may not read the nginx logs.",
              [f"{PRIV}: add the 'Services: Nginx' pages (or 'GUI - All pages')."])
    elif nj.get("unsupported") or not settings.nginx_pull:
        check("nginx", "Web server (nginx)", "optional", [], "nginx plugin not installed (or the pull is switched off). "
              "Only needed if you publish websites through OPNsense.")
    else:
        check("nginx", "Web server (nginx)", "info", [], _api_problem(nj, "nginx logs") or "Waiting for the first poll.")

    # ---------------------------------------------------------------- IDS ---
    ids_api, ids_sys = n("suricata:api"), n("suricata:syslog")
    ij = _job(poller, "ids")
    if ids_api and ids_sys:
        check("ids", "Intrusion detection (Suricata)", "duplicate", ["API", "syslog"], "Alerts arrive via the API and via syslog.",
              ["OPNsense › Services › Intrusion Detection › Administration: untick 'Enable syslog alerts' / 'Enable eve syslog "
               "output' (the API already pulls every alert), or switch off Looking Glass › Settings › OPNsense › Pull Suricata IDS alerts."],
              count=ids_api, last_seen=last("suricata"), link="/dash/threats")
    elif ij.get("ok") and settings.ids_pull:
        check("ids", "Intrusion detection (Suricata)", "ok", ["API"], "Alerts pulled via the API." + ("" if ids_api else " No alerts in 24 hours."),
              avoid=["'Enable syslog alerts' in Intrusion Detection (would duplicate)."], count=ids_api, last_seen=last("suricata"), link="/dash/threats")
    elif ids_sys:
        check("ids", "Intrusion detection (Suricata)", "ok", ["syslog"], "Alerts via syslog.", count=ids_sys, last_seen=last("suricata"))
    elif ij.get("forbidden"):
        check("ids", "Intrusion detection (Suricata)", "action", [], "The API user may not read IDS alerts.",
              [f"{PRIV}: add 'Services: Intrusion Detection' (or 'GUI - All pages')."])
    else:
        check("ids", "Intrusion detection (Suricata)", "optional", [], "Intrusion Detection not enabled on OPNsense (or the pull is off).")

    # ------------------------------------------------- CrowdSec / Q-Feeds ---
    for key, name, job, pulled, page, hint in (
            ("crowdsec", "CrowdSec", "crowdsec", settings.crowdsec_pull, "Services: CrowdSec", ""),
            ("qfeeds", "Q-Feeds", "qfeeds", settings.qfeeds_pull, "Q-Feeds",
             " Events only exist for logged firewall rules that use the Q-Feeds aliases.")):
        j = _job(poller, job)
        if j.get("ok") and pulled:
            check(key, name, "ok", ["API"], "Pulled via the API (no syslog needed)." + ("" if n(key) else f" Nothing in 24 hours.{hint}"),
                  count=n(key), last_seen=last(key), link="/dash/threats")
        elif j.get("forbidden"):
            check(key, name, "action", [], f"The API user may not read {name}.", [f"{PRIV}: add '{page}' (or 'GUI - All pages')."])
        else:
            check(key, name, "optional", [], f"{name} plugin not installed (or the pull is off).")

    # ----------------------------------------------------------- Zenarmor ---
    zes, zsys = n("zenarmor:es"), n("zenarmor:syslog")
    if zes and zsys:
        # Before program "zenarmor-es" existed, stream records were stored as "zenarmor" too: only syslog records
        # received after the first labelled stream record prove a real second channel.
        zsys = await pool.fetchval(
            "SELECT count(*) FROM events WHERE source = 'zenarmor' AND program = 'zenarmor' AND ts > now() - interval '24 hours' "
            "AND received_at > (SELECT min(received_at) FROM events WHERE source = 'zenarmor' AND program = 'zenarmor-es' "
            "AND ts > now() - interval '24 hours')") or 0
    if zes and zsys:
        check("zenarmor", "Zenarmor", "duplicate", ["ES stream", "syslog"], "Zenarmor streams both to the Elasticsearch receiver and to syslog.",
              ["OPNsense › Zenarmor › Settings › Streaming Data: keep one of the two streams."], count=zes, last_seen=last("zenarmor"), link="/dash/zenarmor")
    elif zes or zsys:
        check("zenarmor", "Zenarmor", "ok", ["ES stream" if zes else "syslog"], "Receiving Zenarmor records.",
              count=zes or zsys, last_seen=last("zenarmor"), link="/dash/zenarmor")
    else:
        check("zenarmor", "Zenarmor", "optional", [], "Nothing received. If you use Zenarmor: Zenarmor › Settings › Streaming Data › "
              "Stream Reporting Data to External Elasticsearch, URI http://<docker-host>:9200, version 8.11.3.")

    # -------------------------------------------------------- logins, VPN ---
    auth = n("auth")
    if auth:
        check("auth", "Logins (GUI, SSH, API)", "ok", ["syslog"], "Login events received.", count=auth, last_seen=last("auth"), link="/dash/auth")
    elif syslog_total:
        check("auth", "Logins (GUI, SSH, API)", "info", ["syslog"], "No login lines in 24 hours. That is normal if nobody logged in.",
              ["If you did log in: leave Applications empty in OPNsense remote logging (sshd and API-key failures have no "
               "entry in that list; GUI logins need 'audit')."], link="/dash/auth")
    else:
        check("auth", "Logins (GUI, SSH, API)", "action", [], "Logins only arrive via remote syslog.", ["Set up remote syslog (above)."])

    vj = _job(poller, "vpn")
    errs = (vpn.get("errors") or {}) if isinstance(vpn, dict) else {}
    parts = []
    wg = (vpn.get("wireguard") or {}) if isinstance(vpn, dict) else {}
    if wg.get("peers") is not None:
        parts.append(f"WireGuard {len(wg.get('peers') or [])} peer(s), {wg.get('online', 0)} online")
    if isinstance(vpn.get("openvpn") if isinstance(vpn, dict) else None, list):
        parts.append(f"OpenVPN {sum(1 for c in vpn['openvpn'] if c.get('common_name'))} session(s)")
    if isinstance(vpn.get("ipsec") if isinstance(vpn, dict) else None, list):
        parts.append(f"IPsec {len(vpn['ipsec'])} tunnel(s)")
    forbidden_vpn = [k for k, v in errs.items() if v in (401, 403)]
    if not settings.vpn_pull:
        check("vpn", "VPN (WireGuard, OpenVPN, IPsec)", "action", [], "VPN status pull is switched off - WireGuard has no logs at all.",
              ["Looking Glass › Settings › OPNsense › Pull VPN status: on."])
    elif forbidden_vpn:
        check("vpn", "VPN (WireGuard, OpenVPN, IPsec)", "action", ["API"], f"The API user may not read: {', '.join(forbidden_vpn)}.",
              [f"{PRIV}: add the VPN pages for {', '.join(forbidden_vpn)} (or 'GUI - All pages')."], link="/dash/vpn")
    elif vj.get("ok"):
        check("vpn", "VPN (WireGuard, OpenVPN, IPsec)", "ok", ["API"] + (["syslog"] if n("vpn:syslog") else []),
              ("; ".join(parts) or "No VPN configured") + ". Live status via the API (WireGuard writes no connection logs).",
              count=n("vpn"), last_seen=last("vpn"), link="/dash/vpn")
    else:
        check("vpn", "VPN (WireGuard, OpenVPN, IPsec)", "info", [], _api_problem(vj, "VPN status") or "Waiting for the first poll.")

    # ------------------------------------------------- devices, system ---
    arp, leases = _job(poller, "arp"), _job(poller, "leases")
    if arp.get("ok") or leases.get("ok"):
        check("devices", "Devices (ARP, DHCP leases)", "ok", ["API"], "ARP table and DHCP leases (Kea / dnsmasq / ISC) via the API. "
              "Nothing else needed; DHCP log lines over syslog are optional.", link="/devices")
    else:
        check("devices", "Devices (ARP, DHCP leases)", "info", [], _api_problem(arp, "ARP / DHCP leases") or "Waiting for the first poll.")

    opn_sys = n("system")
    if opn_sys:
        check("system", "OPNsense system logs", "ok", ["syslog"], "Kernel, service and other system messages received.",
              count=opn_sys, last_seen=last("system"), link="/dash/syslog")
    elif syslog_total:
        check("system", "OPNsense system logs", "action", ["syslog"], "Syslog arrives, but no general system messages.",
              ["OPNsense › System › Settings › Logging › Remote › your destination: clear the Applications selection "
               "(general system messages have no entry in that list), Save, Apply."], link="/dash/syslog")
    else:
        check("system", "OPNsense system logs", "action", [], "Only via remote syslog.", ["Set up remote syslog (above)."])

    # --------------------------------------------------------- time stamps ---
    if STATS.clock_offsets:
        offs = ", ".join(f"{ip}: {o / 3600:+g} h" for ip, o in STATS.clock_offsets.items())
        check("clock", "Syslog time stamps", "action", ["syslog"],
              f"Time stamps from {offs} are off by whole hours: the sender writes local time without a time zone "
              f"(BSD syslog format) and Looking Glass reads it as {settings.timezone or 'UTC'}. Corrected automatically, "
              "but fix it at the source so times are exact around daylight-saving changes.",
              ["OPNsense › System › Settings › Logging › Remote › your destination (pencil): tick 'RFC5424' (time "
               "stamps with zone), Save, Apply.",
               "Or: Looking Glass › Settings › Ingestion & network › Time zone: the zone of OPNsense, e.g. Europe/Amsterdam "
               "(same as OPNsense › System › Settings › General › Timezone)."])
    elif STATS.future_clamped > 20:
        parts, steps = [], []
        hours = minutes = False
        for src, f in sorted(STATS.future_by_source.items(), key=lambda x: -x[1]["n"]):
            ahead = f["max_ahead"]
            whole_h = ahead >= 3000 and min(ahead % 3600, 3600 - ahead % 3600) <= 180
            hours |= whole_h
            minutes |= not whole_h
            when = f"{round(ahead / 3600)} h" if whole_h else f"{ahead // 60} min" if ahead >= 120 else f"{ahead} s"
            parts.append(f"{src} ({f['n']:,}×, up to {when} ahead{', from ' + f['host'] if f.get('host') else ''})")
        if hours:
            steps += ["Whole hours ahead = a time zone mix-up. OPNsense › System › Settings › General › Timezone must be "
                      "your real zone (e.g. Europe/Amsterdam), and Looking Glass › Settings › Ingestion & network › "
                      f"Time zone the same zone (now: {settings.timezone or 'UTC'}).",
                      "For syslog: OPNsense › System › Settings › Logging › Remote › your destination (pencil): tick "
                      "'RFC5424' (time stamps with zone), Save, Apply."]
        if minutes:
            steps += ["Minutes ahead = a clock running fast, on OPNsense or on the Docker host. Compare: OPNsense › "
                      "Lobby › Dashboard (System time) against a shell on the Docker host: date -u (Looking Glass uses "
                      "the host's clock).",
                      "OPNsense running fast: Services › Network Time › General: add time servers (e.g. pool.ntp.org), "
                      "Save. Docker host running slow: enable NTP there (e.g. timedatectl set-ntp true; on Unraid: "
                      "Settings › Date and Time › Use NTP: Yes)."]
        check("clock", "Event time stamps", "info", [], f"{STATS.future_clamped:,} events since the last start claimed a "
              f"time in the future and were stored with their receive time instead: {'; '.join(parts) or 'unknown source'}. "
              f"Looking Glass clock now: {local_time(settings, seconds=True)} {settings.timezone or 'UTC'} "
              f"({datetime.now(timezone.utc):%H:%M:%S} UTC).", steps)

    # ------------------------------------------------- behaviour & intel ---
    if settings.behavior_enabled:
        prof = await db.pool().fetchrow("SELECT count(DISTINCT key) devices, min(first_seen) since FROM device_profile")
        profiled, since = (prof["devices"], prof["since"]) if prof else (0, None)  # not "n": that is the count helper
        days = (time.time() - since.timestamp()) / 86400 if since else 0
        check("behavior", "Behaviour learning", "ok" if days >= settings.behavior_min_days else "info", [],
              f"{profiled} devices profiled, learning for {days:.1f} days." + ("" if days >= settings.behavior_min_days else
              f" New-behaviour alerts start after {settings.behavior_min_days} days per device."),
              link="/settings#behavior")
    feeds = await db.kv_get("intel:status", {}) or {}
    bad = {k: v for k, v in feeds.items() if v.get("enabled") and v.get("ok") is False}
    if bad:
        need_key = any("Auth-Key" in (v.get("error") or "") for v in bad.values())
        check("intel", "Threat feeds", "action", ["internet"], "Not downloaded: " + "; ".join(
              f"{k}: {v.get('error')}" for k, v in bad.items())[:600],
              ["Looking Glass › Settings › Threat intel & traps › abuse.ch Auth-Key: get a free key at auth.abuse.ch "
               "(log in, Optional › Generate Auth-Key), Save, then Update feeds now."] if need_key else
              ["The container needs internet access (HTTPS) to abuse.ch and torproject.org; or switch the feed off."],
              link="/settings#intel")
    elif any(v.get("ok") for v in feeds.values()):
        total = sum(v.get("count") or 0 for v in feeds.values())
        check("intel", "Threat feeds", "ok", ["internet"], f"{total:,} indicators from "
              f"{sum(1 for v in feeds.values() if v.get('ok'))} feeds.", link="/settings#intel")
    tls = await db.pool().fetchval("SELECT count(*) FROM events WHERE ts > now() - interval '1 day' AND source IN "
                                   "('suricata', 'zenarmor') AND coalesce(data->>'ja3', data->>'ja4', data->>'ja3_hash') IS NOT NULL")
    if settings.intel_ja3 or settings.behavior_new_tls:
        check("tls", "TLS fingerprints (JA3/JA4)", "ok" if tls else "optional", ["syslog"],
              f"{tls:,} TLS records with fingerprints in 24 h." if tls else
              "None received - malware TLS fingerprints and 'new TLS program' need them.",
              [] if tls else ["Optional: OPNsense › Services › Intrusion Detection › Administration › Settings: enable "
                              "'Enable eve syslog output' with TLS logging, so Suricata sends its tls records (JA3/JA4) "
                              "to the remote syslog destination."])
    if settings.exposure_watch:
        ex = await db.kv_get("exposure:status")
        if ex:
            check("exposure", "Exposure watch", "ok" if ex.get("api") else "info", ["API"],
                  f"{ex.get('rules')} rules / port forwards compared." + ("" if ex.get("api") else
                  " Port forwards and rule details are not in this OPNsense version's API (25.7+); only rule names are compared."),
                  [] if ex.get("api") else ["Optional: give the API user the privileges 'Firewall: Rules' and "
                                            "'Firewall: NAT: Port Forward' (System › Access › Users › your API user)."])
    canaries = settings.canary_targets.strip()
    check("canary", "Canary addresses", "ok" if canaries else "optional", [],
          "Configured." if canaries else "None set. A canary is an address / port nothing should ever use - any contact is "
          "a strong sign of someone exploring the network.",
          [] if canaries else ["Looking Glass › Settings › Threat intel & traps › Canary addresses, e.g. "
                               "192.168.1.1:23 and 192.168.1.1:445 (unused ports on the firewall's LAN address).",
                               "OPNsense › Firewall › Rules › LAN: a block rule for those ports with 'Log' ticked, above the "
                               "allow rules - so the firewall logs every attempt."], link="/settings#intel")

    # ------------------------------------------------------------- extras ---
    status = await db.get_snapshot("unraid_status") or {}
    for sid, st in status.items():
        check(f"unraid{sid}", f"Unraid: {st.get('name')}", "ok" if st.get("ok") else "action", ["API"],
              "Connected." if st.get("ok") else f"Not reachable: {st.get('error')}",
              [] if st.get("ok") else ["Looking Glass › Settings › Unraid servers: check URL and API key (Test connection)."],
              last_seen=st.get("last"), link="/unraid")
    uni = await db.get_snapshot("unifi:status") or {}
    if not settings.unifi_enabled:
        check("unifi", "UniFi controller", "optional", [], "Not configured. Optional: access points, switches, Wi-Fi clients "
              "and where each device is connected (shown in alerts).", ["Looking Glass › Settings › UniFi: URL + API key "
              "(UniFi OS console) or a local username / password (self-hosted Network Application)."], link="/settings#unifi")
    elif uni.get("ok") is False:
        check("unifi", "UniFi controller", "action", ["API"], f"Not reachable: {uni.get('error')}",
              ["Looking Glass › Settings › UniFi: check URL, port and credentials with Test connection."],
              last_seen=uni.get("last"), link="/settings#unifi")
    elif not uni:
        check("unifi", "UniFi controller", "info", ["API"], "Connecting…", link="/unifi")
    else:
        classic = "classic" in str(uni.get("mode") or "")
        sections = uni.get("sections") or {}
        failed = [k for k, v in sections.items() if not v.get("ok")]
        check("unifi", "UniFi controller", "ok" if classic and not failed else "info", ["API"],
              f"Connected ({uni.get('mode')}, Network {uni.get('version')})." +
              (f" Not working: {', '.join(failed)}." if failed else "") +
              ("" if classic else " Only the integration API answers: no SSID, signal, switch ports, events or rogue APs."),
              [] if classic else ["For full data: also enter a local UniFi username / password with a View Only role "
                                  "(Looking Glass › Settings › UniFi)."],
              avoid=["Turning on UniFi's SIEM / remote syslog towards Looking Glass as well - the API already delivers "
                     "these events."], count=n("unifi"), last_seen=last("unifi") or uni.get("last"), link="/unifi")
    geo = settings.geoip_db and os.path.exists(settings.geoip_db)
    check("geoip", "GeoIP countries", "ok" if geo else "optional", [], "GeoLite2 database loaded." if geo else
          "No GeoLite2 database - countries stay empty. Optional: download GeoLite2-City.mmdb (free MaxMind account) "
          "into the data folder and restart.")
    check("ai", "AI analyst", "ok" if settings.ai_enabled else "optional", [],
          f"{settings.ai_model} configured." if settings.ai_enabled else "Not configured. Optional: Settings › AI analyst.",
          link="/settings#ai")

    order = {"action": 0, "duplicate": 1, "info": 2, "ok": 3, "optional": 4}
    summary = {k: sum(1 for c in checks if c["status"] == k) for k in order}
    return {"checks": checks, "summary": summary, "generated": time.time()}
