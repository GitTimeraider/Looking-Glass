"""Aggregated statistics used by dashboards, reports and the AI analyst."""
from __future__ import annotations

import asyncio
import html
import logging
from datetime import date
from typing import Any

from . import db
from .alert_filters import RULES
from .parsers.filterlog import QFEEDS

log = logging.getLogger(__name__)

# what a report can cover (Reports page, Settings › Reports): key -> name. All of them = the full report.
CATEGORIES: dict[str, str] = {"opnsense": "OPNsense", "unifi": "UniFi", "unraid": "Unraid", "backups": "Backups"}

# the category of an event (logins come from OPNsense, UniFi and the Unraid servers' syslog): used where a section
# mixes sources. $2 = the selected categories, NULL = all
EVENT_CATEGORY = ("CASE WHEN source = 'unifi' THEN 'unifi' WHEN source IN ('unraid', 'docker') "
                  "OR host IN (SELECT name FROM unraid_servers) THEN 'unraid' ELSE 'opnsense' END")
CATEGORY_FILTER = f"AND ($2::text[] IS NULL OR {EVENT_CATEGORY} = ANY($2))"
# alerts: by the rule groups of Settings › Alert filters; $2 = the rules of the selected categories, NULL = all
RULE_FILTER = "AND ($2::text[] IS NULL OR rule = ANY($2))"
_RULE_GROUP_CATEGORY = {"UniFi": ("unifi",), "Unraid": ("unraid",), "Backups": ("backups",),
                        "Devices": ("opnsense", "unifi")}  # every other group: OPNsense

# name -> (sql, description). $1 = window in seconds
QUERIES: dict[str, str] = {
    "totals_by_source": "SELECT source, count(*)::bigint n FROM events WHERE ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC",
    "firewall_actions": "SELECT action, count(*)::bigint n FROM events WHERE source = 'firewall' AND ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC",
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
    "top_talkers_internal": "SELECT host(src_ip) ip, count(*) n, count(DISTINCT dst_ip) peers FROM events WHERE source = 'firewall' "
                            "AND ts > now() - make_interval(secs => $1) AND (src_ip << '10.0.0.0/8' OR src_ip << '172.16.0.0/12' "
                            "OR src_ip << '192.168.0.0/16') GROUP BY 1 ORDER BY 2 DESC LIMIT 15",
    "dns_top_domains": "SELECT domain, count(*) n, count(DISTINCT src_ip) clients FROM events WHERE source = 'unbound' AND ts > now() - make_interval(secs => $1) "
                       "AND domain IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 15",
    "dns_blocked": "SELECT domain, coalesce(data->>'blocklist', '') blocklist, count(*) n FROM events WHERE source = 'unbound' AND action IN ('block', 'drop') "
                   "AND ts > now() - make_interval(secs => $1) GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15",
    "dns_clients": "SELECT host(src_ip) client, count(*) n, count(*) FILTER (WHERE action IN ('block', 'drop')) blocked FROM events "
                   "WHERE source = 'unbound' AND src_ip IS NOT NULL AND ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC LIMIT 15",
    "web_status": "SELECT action status, count(*)::bigint n FROM events WHERE source = 'nginx' AND ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC LIMIT 15",
    "web_top_clients": "SELECT host(src_ip) ip, src_country country, count(*) n, count(*) FILTER (WHERE action ~ '^http_[45]') errors FROM events "
                       "WHERE source = 'nginx' AND src_ip IS NOT NULL AND ts > now() - make_interval(secs => $1) GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15",
    "web_attack_tags": "SELECT tag, count(*) n, count(DISTINCT src_ip) ips FROM (SELECT src_ip, jsonb_array_elements_text(data->'tags') tag FROM events "
                       "WHERE source = 'nginx' AND ts > now() - make_interval(secs => $1) AND jsonb_typeof(data->'tags') = 'array') t GROUP BY 1 ORDER BY 2 DESC",
    "auth_failures": "SELECT host(src_ip) ip, source, count(*) n, array_agg(DISTINCT username) FILTER (WHERE username IS NOT NULL) users FROM events "
                     f"WHERE action = 'login_failed' AND ts > now() - make_interval(secs => $1) {CATEGORY_FILTER} "
                     "GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15",
    "auth_success": "SELECT host(src_ip) ip, username, program, count(*) n, max(ts) last FROM events WHERE action = 'login_success' "
                    f"AND ts > now() - make_interval(secs => $1) {CATEGORY_FILTER} GROUP BY 1, 2, 3 ORDER BY 5 DESC LIMIT 15",
    "ids_signatures": "SELECT message signature, max(data->>'classification') classification, count(*) n, count(DISTINCT src_ip) sources FROM events "
                      "WHERE source = 'suricata' AND ts > now() - make_interval(secs => $1) AND action IN ('alert', 'drop', 'blocked', 'reject') GROUP BY 1 ORDER BY 3 DESC LIMIT 15",
    "ids_top_sources": "SELECT host(src_ip) ip, max(src_country) country, count(DISTINCT message) sigs, count(*) n FROM events "
                       "WHERE source = 'suricata' AND action IN ('alert', 'drop', 'blocked', 'reject') AND src_ip IS NOT NULL "
                       "AND ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 4 DESC LIMIT 15",
    "ids_top_targets": "SELECT host(dst_ip) ip, dst_port port, count(DISTINCT src_ip) sources, count(*) n FROM events "
                       "WHERE source = 'suricata' AND action IN ('alert', 'drop', 'blocked', 'reject') AND dst_ip IS NOT NULL "
                       "AND ts > now() - make_interval(secs => $1) GROUP BY 1, 2 ORDER BY 4 DESC LIMIT 15",
    "ids_classifications": "SELECT coalesce(data->>'classification', data->>'category', '?') classification, count(*) n, "
                           "count(*) FILTER (WHERE action IN ('drop', 'blocked')) dropped FROM events "
                           "WHERE source = 'suricata' AND action IN ('alert', 'drop', 'blocked', 'reject') "
                           "AND ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC LIMIT 15",
    "ids_internal_hosts": "SELECT host(src_ip) ip, count(DISTINCT message) sigs, count(*) n FROM events "
                          "WHERE source = 'suricata' AND action IN ('alert', 'drop', 'blocked', 'reject') AND (src_ip << '10.0.0.0/8' "
                          "OR src_ip << '172.16.0.0/12' OR src_ip << '192.168.0.0/16' OR src_ip << 'fc00::/7') "
                          "AND ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 3 DESC LIMIT 15",
    "crowdsec_scenarios": "SELECT coalesce(data->>'scenario', data->>'reason') scenario, count(*) n, count(DISTINCT src_ip) ips FROM events "
                          "WHERE source = 'crowdsec' AND ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC LIMIT 15",
    # Q-Feeds: its firewall log lines too; direction from the addresses (a LAN rule logs outgoing traffic as "in")
    "qfeeds_hits": "SELECT host(src_ip) src, host(dst_ip) dst, CASE WHEN src_ip << '10.0.0.0/8' OR src_ip << '172.16.0.0/12' "
                   "OR src_ip << '192.168.0.0/16' OR src_ip << 'fc00::/7' OR src_ip << '100.64.0.0/10' THEN 'out' ELSE 'in' END direction, "
                   f"count(*) n FROM events WHERE {QFEEDS} "
                   "AND ts > now() - make_interval(secs => $1) GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT 15",
    "alerts_by_severity": f"SELECT severity, count(*) n FROM alerts WHERE last_seen > now() - make_interval(secs => $1) {RULE_FILTER} GROUP BY 1 "
                          "ORDER BY array_position(ARRAY['critical','high','medium','low','info'], severity)",
    "alerts": "SELECT id, severity, rule, title, host(src_ip) src, count, status, last_seen FROM alerts WHERE last_seen > now() - make_interval(secs => $1) "
              f"{RULE_FILTER} "
              "ORDER BY array_position(ARRAY['critical','high','medium','low','info'], severity), last_seen DESC LIMIT 50",
    "new_devices": "SELECT mac, host(ip) ip, hostname, conn_where, first_seen FROM devices WHERE first_seen > now() - make_interval(secs => $1) "
                   "ORDER BY first_seen DESC LIMIT 25",
    "unifi_events": "SELECT action, count(*) n, count(DISTINCT data->>'mac') clients FROM events WHERE source = 'unifi' "
                    "AND ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC",
    # access points / switches that went offline or restarted
    "unifi_devices": "SELECT coalesce(data->>'ap_name', data->>'sw_name', data->>'ap', data->>'sw', '(unknown)') device, "
                     "count(*) FILTER (WHERE action = 'device_offline') offline, count(*) FILTER (WHERE action = 'device_restart') restarts, "
                     "count(*) FILTER (WHERE action = 'poe_disconnect') poe, count(*) n FROM events WHERE source = 'unifi' "
                     "AND action IN ('device_offline', 'device_online', 'device_restart', 'poe_disconnect') "
                     "AND ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC, 3 DESC, 5 DESC LIMIT 15",
    # clients that drop off or roam the most (Wi-Fi problems)
    "unifi_clients": "SELECT coalesce(d.hostname, e.data->>'hostname', e.data->>'mac') client, e.data->>'mac' mac, "
                     "count(*) FILTER (WHERE e.action = 'client_disconnect') disconnects, count(*) FILTER (WHERE e.action = 'client_roam') roams, "
                     "count(*) n FROM events e LEFT JOIN devices d ON d.mac = e.data->>'mac' WHERE e.source = 'unifi' "
                     "AND e.action IN ('client_connect', 'client_disconnect', 'client_roam') AND e.data ? 'mac' "
                     "AND e.ts > now() - make_interval(secs => $1) GROUP BY 1, 2 ORDER BY 3 DESC, 4 DESC, 5 DESC LIMIT 15",
    # Unraid: notifications, container log problems, storage now, CPU / memory over the period
    "unraid_notifications": "SELECT host server, coalesce(data->>'importance', 'INFO') importance, "
                            "coalesce(nullif(data->>'subject', ''), data->>'title', message) subject, count(*) n, max(ts) last FROM events "
                            "WHERE source = 'unraid' AND action = 'notification' AND ts > now() - make_interval(secs => $1) GROUP BY 1, 2, 3 "
                            "ORDER BY array_position(ARRAY['ALERT', 'WARNING', 'NORMAL', 'INFO'], coalesce(data->>'importance', 'INFO')), 5 DESC LIMIT 25",
    "unraid_container_logs": "SELECT host server, program container, count(*) FILTER (WHERE severity <= 3) errors, "
                             "count(*) FILTER (WHERE severity = 4) warnings FROM events WHERE source = 'docker' AND action = 'container_log' "
                             "AND severity <= 4 AND ts > now() - make_interval(secs => $1) GROUP BY 1, 2 ORDER BY 3 DESC, 4 DESC LIMIT 15",
    # the latest state (not older than the period, at least a day): sizes are in kB
    "unraid_storage": "SELECT s.name server, g->>'name' grp, g->>'kind' kind, sn.data->>'state' state, "
                      "(g->>'used_pct')::float8 used_pct, (g->>'free')::float8 * 1024 free, (g->>'disks')::int disks, "
                      "(g->>'errors')::int errors, (g->>'max_temp')::float8 max_temp FROM snapshots sn "
                      "JOIN unraid_servers s ON sn.key = 'unraid:' || s.id || ':storage' "
                      "CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(sn.data->'groups') = 'array' "
                      "THEN sn.data->'groups' ELSE '[]'::jsonb END) g "
                      "WHERE NOT coalesce((g->>'excluded')::boolean, false) AND sn.ts > now() - make_interval(secs => greatest($1, 86400)) "
                      "ORDER BY 1, 3, 2",
    "unraid_resources": "SELECT s.name server, round(avg(m.value) FILTER (WHERE m.name = 'unraid_cpu_pct')::numeric, 1)::float8 cpu_avg, "
                        "round(max(m.value) FILTER (WHERE m.name = 'unraid_cpu_pct')::numeric, 1)::float8 cpu_max, "
                        "round(avg(m.value) FILTER (WHERE m.name = 'unraid_mem_pct')::numeric, 1)::float8 mem_avg, "
                        "round(max(m.value) FILTER (WHERE m.name = 'unraid_mem_pct')::numeric, 1)::float8 mem_max FROM metrics m "
                        "JOIN unraid_servers s ON m.labels = s.id::text WHERE m.name IN ('unraid_cpu_pct', 'unraid_mem_pct') "
                        "AND m.ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 1",
    "backups": "SELECT source, job, count(*) FILTER (WHERE status = 'success') ok, count(*) FILTER (WHERE status = 'warning') warnings, "
               "count(*) FILTER (WHERE status = 'error') failed, max(coalesce(ended, started)) FILTER (WHERE status IN ('success', 'warning')) last_good, "
               "sum(bytes_added) FILTER (WHERE status IN ('success', 'warning')) added FROM backup_runs WHERE kind = 'backup' AND job <> '' "
               "AND started > now() - make_interval(secs => $1) GROUP BY 1, 2 ORDER BY 5 DESC, 2",
    # UniFi location + OPNsense findings: which device, where it is connected and what it did
    "clients_with_security_events": "WITH ev AS (SELECT src_ip, count(*) FILTER (WHERE source = 'firewall' AND action = 'block') fw, "
        "count(*) FILTER (WHERE source = 'unbound' AND action IN ('block', 'drop')) dns, "
        "count(*) FILTER (WHERE source IN ('suricata', 'crowdsec', 'qfeeds') OR lower(data->>'blocklist') = 'q-feeds') threats "
        "FROM events WHERE ts > now() - make_interval(secs => $1) AND src_ip IS NOT NULL "
        "AND source IN ('firewall', 'unbound', 'suricata', 'crowdsec', 'qfeeds') GROUP BY 1) "
        "SELECT coalesce(d.hostname, d.mac) name, host(d.ip) ip, d.conn_where, ev.fw, ev.dns, ev.threats FROM devices d "
        "JOIN ev ON ev.src_ip = d.ip WHERE d.conn_where IS NOT NULL ORDER BY 6 DESC, 4 + 5 DESC LIMIT 15",
}

# the categories a section belongs to (not listed: OPNsense); in every report: the event totals and the alerts (those
# filtered to the categories' rules)
_ALL = tuple(CATEGORIES)
SECTION_CATEGORIES: dict[str, tuple[str, ...]] = {
    "totals_by_source": _ALL, "alerts_by_severity": _ALL, "alerts": _ALL,
    "auth_failures": ("opnsense", "unifi", "unraid"), "auth_success": ("opnsense", "unifi", "unraid"),
    "new_devices": ("opnsense", "unifi"), "clients_with_security_events": ("opnsense", "unifi"),
    "unifi_events": ("unifi",), "unifi_devices": ("unifi",), "unifi_clients": ("unifi",),
    "unraid_notifications": ("unraid",), "unraid_container_logs": ("unraid",), "unraid_storage": ("unraid",),
    "unraid_resources": ("unraid",), "backups": ("backups",),
}
# $2 of these: the selected categories (CATEGORY_FILTER) or their alert rules (RULE_FILTER)
_CATEGORY_PARAM = {"auth_failures", "auth_success"}
_RULE_PARAM = {"alerts_by_severity", "alerts"}


def parse_categories(value: Any) -> list[str]:
    """Categories from a list or a comma separated text ("OPNsense, Unraid" or keys); nothing valid = all, in the
    order of CATEGORIES."""
    items = value if isinstance(value, (list, tuple, set)) else str(value or "").split(",")
    wanted = {str(v).strip().lower() for v in items}
    return [k for k in CATEGORIES if k in wanted] or list(CATEGORIES)


def is_all(categories: list[str]) -> bool:
    return set(categories) >= set(CATEGORIES)


def category_label(categories: list[str]) -> str:
    """'' for all, else 'UniFi + Unraid'."""
    return "" if is_all(categories) else " + ".join(CATEGORIES[c] for c in categories)


def report_title(prefix: str, categories: list[str], suffix: str = "") -> str:
    """'Weekly security report' (all) / 'Weekly Unraid report' / 'Weekly OPNsense + UniFi report'."""
    what = category_label(categories) or "security"
    return " ".join(x for x in (prefix, what, "report", suffix) if x)


def alert_rules(categories: list[str]) -> list[str] | None:
    """The alert rules of these categories; None = all (also alerts of rules not in the list)."""
    if is_all(categories):
        return None
    return sorted({r for group, rules in RULES.items() for r, _ in rules
                   if set(_RULE_GROUP_CATEGORY.get(group, ("opnsense",))) & set(categories)})


def event_category(source: str | None) -> str:
    """Python twin of EVENT_CATEGORY, by source only (for the per-source totals)."""
    return "unifi" if source == "unifi" else "unraid" if source in ("unraid", "docker") else "opnsense"


def sections_for(categories: list[str]) -> list[str]:
    return [n for n in QUERIES if set(SECTION_CATEGORIES.get(n, ("opnsense",))) & set(categories)]


# only count events per source / action: from 2 days on read from the hourly counts (rollup.py), same numbers
# (::bigint keeps them whole numbers there: sum(n) is a numeric)
ROLLUP_QUERIES = {"totals_by_source", "firewall_actions", "web_status"}


async def build_report(hours: float = 24, categories: Any = None) -> dict[str, Any]:
    """The report data: the sections of the given categories (None / all = everything)."""
    secs = float(hours) * 3600
    cats = parse_categories(categories)
    rules = alert_rules(cats)

    from . import rollup

    failed: list[str] = []

    async def run(name: str, sql: str) -> tuple[str, list[dict[str, Any]]]:
        args: list[Any] = [secs]
        if name in _CATEGORY_PARAM:
            args.append(None if is_all(cats) else cats)
        elif name in _RULE_PARAM:
            args.append(rules)
        # one query that fails (e.g. the 2-minute limit on a 30-day window) leaves that section empty instead of
        # failing the whole report: otherwise nothing was cached and every refresh ran all queries again
        try:
            async with db.heavy(hours), db.pool().acquire() as conn:
                if hours >= rollup.MIN_HOURS and name in ROLLUP_QUERIES:
                    return name, db.records(await rollup.fetch(conn, sql, secs))
                return name, db.records(await conn.fetch(sql, *args))
        except Exception as exc:  # noqa: BLE001
            log.warning("report section %s (%s h) failed: %r", name, hours, exc)
            failed.append(name)
            return name, []

    results = await asyncio.gather(*(run(n, QUERIES[n]) for n in sections_for(cats)))
    # the sections whose query failed (e.g. timed out): shown as "could not be counted" instead of "no data"
    report: dict[str, Any] = {"hours": hours, "categories": cats, **dict(results), "failed": sorted(failed)}
    report["totals_by_source"] = [r for r in report["totals_by_source"] if event_category(r.get("source")) in cats]
    report["totals"] = {r["source"]: r["n"] for r in report["totals_by_source"]}
    return report


async def timeline(hours: float = 24, buckets: int = 48) -> dict[str, Any]:
    """Events per source and blocked events over time (Overview). From 2 days on in whole hours, counted from the
    hourly counts (rollup.py) - same numbers, a fraction of the work."""
    from . import rollup
    secs = float(hours) * 3600
    step = max(60, int(secs / buckets))
    by_source = ("SELECT to_timestamp(floor(extract(epoch FROM ts) / $2) * $2) AS bucket, source, count(*) n FROM events "
                 "WHERE ts > now() - make_interval(secs => $1) GROUP BY 1, 2 ORDER BY 1")
    blocked = ("SELECT to_timestamp(floor(extract(epoch FROM ts) / $2) * $2) AS bucket, count(*) n FROM events "
               "WHERE ts > now() - make_interval(secs => $1) AND action IN ('block', 'drop', 'ban') GROUP BY 1 ORDER BY 1")
    async with db.pool().acquire() as conn:
        if hours >= rollup.MIN_HOURS:
            step = -(-step // 3600) * 3600
            rows, blk = await rollup.fetch(conn, by_source, secs, step), await rollup.fetch(conn, blocked, secs, step)
        else:
            rows, blk = await conn.fetch(by_source, secs, step), await conn.fetch(blocked, secs, step)
    return {"step": step, "series": db.records(rows), "blocked": db.records(blk)}


def report_due(last: str | None, today: date, every_days: int) -> bool:
    """A scheduled report is due when the last one ("YYYY-MM-DD", local date) is ``every_days`` or more days ago."""
    if not last:
        return True
    try:
        return (today - date.fromisoformat(last)).days >= max(1, every_days)
    except ValueError:
        return True


SEVERITY_COLOURS = {"critical": "#a21caf", "high": "#b91c1c", "medium": "#b45309", "low": "#0e7490", "info": "#475569"}


async def report_mail(report_id: int, link: str = "") -> tuple[str, str, str] | None:
    """(subject, text, html) of a stored report: alerts per severity, the most important alerts, the AI analysis and a
    link to the report page."""
    row = await db.pool().fetchrow("SELECT title, period_h, data, ai_summary, ai_state, ai_error FROM reports WHERE id = $1",
                                   report_id)
    if not row:
        return None
    data = row["data"] or {}
    url = f"{link.rstrip('/')}/reports/{report_id}" if link else ""
    by_sev = {r["severity"]: r["n"] for r in data.get("alerts_by_severity") or []}
    counts = ", ".join(f"{n} {sev}" for sev, n in by_sev.items()) or "no alerts"
    top = [a for a in data.get("alerts") or [] if a.get("severity") in ("critical", "high", "medium")][:10]
    cats = parse_categories(data.get("categories"))
    blocked = sum(r.get("n", 0) for r in data.get("firewall_actions") or [] if r.get("action") == "block")
    days = row["period_h"] / 24
    period = f"last {days:g} day{'s' if days != 1 else ''}"
    if not is_all(cats):
        period += f" · covers {category_label(cats)}"
    # the firewall line only when the report covers OPNsense
    fw_text = f"\nFirewall blocks: {blocked}" if "opnsense" in cats else ""
    fw_html = f" · Firewall blocks: <b>{blocked}</b>" if "opnsense" in cats else ""
    ai = row["ai_summary"] or ""
    ai_note = "" if ai else ("The AI analysis failed: " + (row["ai_error"] or "unknown error") if row["ai_state"] == "failed"
                             else "No AI analysis (AI analyst not set up).")
    subject = f"[Looking Glass] {row['title']}: {counts}"[:200]
    text = (f"{row['title']} ({period})\n\nAlerts: {counts}{fw_text}\n"
            + ("".join(f"\n[{a['severity'].upper()}] {a['title']}" for a in top) + "\n" if top else "")
            + (f"\n{ai}\n" if ai else f"\n{ai_note}\n")
            + (f"\nFull report: {url}\n" if url else "")
            + "\nChange or stop these mails: Looking Glass › Settings › Reports.\n")
    rows = "".join(
        f'<tr><td style="padding:4px 8px;vertical-align:top"><span style="background:{SEVERITY_COLOURS[a["severity"]]};'
        f'color:#fff;border-radius:9px;padding:1px 8px;font-size:12px;font-weight:600">{a["severity"].upper()}</span></td>'
        f'<td style="padding:4px 8px">{html.escape(a["title"])}</td></tr>' for a in top)
    body = (f'<div style="font-family:system-ui,Segoe UI,sans-serif;font-size:14px"><h2 style="margin:0 0 4px">'
            f'{html.escape(row["title"])}</h2><p style="color:#555;margin:0 0 12px">{period}</p>'
            f'<p>Alerts: <b>{html.escape(counts)}</b>{fw_html}</p>'
            + (f'<table style="border-collapse:collapse">{rows}</table>' if rows else "")
            + (f'<h3>AI analysis</h3><div style="white-space:pre-wrap">{html.escape(ai)}</div>' if ai
               else f'<p style="color:#555">{html.escape(ai_note)}</p>')
            + (f'<p><a href="{html.escape(url)}">Full report</a></p>' if url else "")
            + '<p style="color:#777;font-size:12px">Change or stop these mails: Looking Glass › Settings › Reports.</p></div>')
    return subject, text, body


async def run_ai_summary(analyst, report_id: int) -> None:
    """Fill in the AI analysis of a stored report (runs in the background; state in reports.ai_state / ai_error)."""
    row = await db.pool().fetchrow("SELECT period_h, data FROM reports WHERE id = $1", report_id)
    if not row:
        return
    await db.pool().execute("UPDATE reports SET ai_state = 'running', ai_error = NULL WHERE id = $1", report_id)
    try:
        summary = await analyst.analyse(row["period_h"], row["data"])
        await db.pool().execute("UPDATE reports SET ai_summary = $2, ai_state = 'done', ai_error = NULL WHERE id = $1",
                                report_id, summary)
    except Exception as exc:  # noqa: BLE001
        log.warning("AI analysis of report %s failed: %s", report_id, exc)
        await db.pool().execute("UPDATE reports SET ai_state = 'failed', ai_error = $2 WHERE id = $1", report_id, str(exc)[:2000])
