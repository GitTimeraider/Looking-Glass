"""Aggregated statistics used by dashboards, reports and the AI analyst."""
from __future__ import annotations

import asyncio
import html
import logging
from datetime import date
from typing import Any

from . import db
from .parsers.filterlog import QFEEDS

log = logging.getLogger(__name__)

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
    "zenarmor_top": "SELECT coalesce(data->>'app_name', data->>'app_category', action) app, action, count(*) n FROM events "
                    "WHERE source = 'zenarmor' AND ts > now() - make_interval(secs => $1) GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15",
    # Q-Feeds: its firewall log lines too; direction from the addresses (a LAN rule logs outgoing traffic as "in")
    "qfeeds_hits": "SELECT host(src_ip) src, host(dst_ip) dst, CASE WHEN src_ip << '10.0.0.0/8' OR src_ip << '172.16.0.0/12' "
                   "OR src_ip << '192.168.0.0/16' OR src_ip << 'fc00::/7' OR src_ip << '100.64.0.0/10' THEN 'out' ELSE 'in' END direction, "
                   f"count(*) n FROM events WHERE {QFEEDS} "
                   "AND ts > now() - make_interval(secs => $1) GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT 15",
    "alerts_by_severity": "SELECT severity, count(*) n FROM alerts WHERE last_seen > now() - make_interval(secs => $1) GROUP BY 1 "
                          "ORDER BY array_position(ARRAY['critical','high','medium','low','info'], severity)",
    "alerts": "SELECT id, severity, rule, title, host(src_ip) src, count, status, last_seen FROM alerts WHERE last_seen > now() - make_interval(secs => $1) "
              "ORDER BY array_position(ARRAY['critical','high','medium','low','info'], severity), last_seen DESC LIMIT 50",
    "new_devices": "SELECT mac, host(ip) ip, hostname, conn_where, first_seen FROM devices WHERE first_seen > now() - make_interval(secs => $1) "
                   "ORDER BY first_seen DESC LIMIT 25",
    "unifi_events": "SELECT action, count(*) n, count(DISTINCT data->>'mac') clients FROM events WHERE source = 'unifi' "
                    "AND ts > now() - make_interval(secs => $1) GROUP BY 1 ORDER BY 2 DESC",
    "backups": "SELECT source, job, count(*) FILTER (WHERE status = 'success') ok, count(*) FILTER (WHERE status = 'warning') warnings, "
               "count(*) FILTER (WHERE status = 'error') failed, max(coalesce(ended, started)) FILTER (WHERE status IN ('success', 'warning')) last_good, "
               "sum(bytes_added) FILTER (WHERE status IN ('success', 'warning')) added FROM backup_runs WHERE kind = 'backup' AND job <> '' "
               "AND started > now() - make_interval(secs => $1) GROUP BY 1, 2 ORDER BY 5 DESC, 2",
    # UniFi location + OPNsense findings: which device, where it is connected and what it did
    "clients_with_security_events": "WITH ev AS (SELECT src_ip, count(*) FILTER (WHERE source = 'firewall' AND action = 'block') fw, "
        "count(*) FILTER (WHERE source = 'unbound' AND action IN ('block', 'drop')) dns, "
        "count(*) FILTER (WHERE source IN ('suricata', 'crowdsec', 'qfeeds') OR lower(data->>'blocklist') = 'q-feeds' OR (source = 'zenarmor' AND action = 'block')) threats "
        "FROM events WHERE ts > now() - make_interval(secs => $1) AND src_ip IS NOT NULL "
        "AND source IN ('firewall', 'unbound', 'suricata', 'crowdsec', 'qfeeds', 'zenarmor') GROUP BY 1) "
        "SELECT coalesce(d.hostname, d.mac) name, host(d.ip) ip, d.conn_where, ev.fw, ev.dns, ev.threats FROM devices d "
        "JOIN ev ON ev.src_ip = d.ip WHERE d.conn_where IS NOT NULL ORDER BY 6 DESC, 4 + 5 DESC LIMIT 15",
}

# only count events per source / action: from 2 days on read from the hourly counts (rollup.py), same numbers
# (::bigint keeps them whole numbers there: sum(n) is a numeric)
ROLLUP_QUERIES = {"totals_by_source", "firewall_actions"}


async def build_report(hours: float = 24) -> dict[str, Any]:
    secs = float(hours) * 3600

    from . import rollup

    async def run(name: str, sql: str) -> tuple[str, list[dict[str, Any]]]:
        # one query that fails (e.g. the 2-minute limit on a 30-day window) leaves that section empty instead of
        # failing the whole report: otherwise nothing was cached and every refresh ran all queries again
        try:
            async with db.heavy(hours), db.pool().acquire() as conn:
                if hours >= rollup.MIN_HOURS and name in ROLLUP_QUERIES:
                    return name, db.records(await rollup.fetch(conn, sql, secs))
                return name, db.records(await conn.fetch(sql, secs))
        except Exception as exc:  # noqa: BLE001
            log.warning("report section %s (%s h) failed: %r", name, hours, exc)
            return name, []

    results = await asyncio.gather(*(run(n, q) for n, q in QUERIES.items()))
    report: dict[str, Any] = {"hours": hours, **dict(results)}
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
    blocked = sum(r.get("n", 0) for r in data.get("firewall_actions") or [] if r.get("action") == "block")
    days = row["period_h"] / 24
    period = f"last {days:g} day{'s' if days != 1 else ''}"
    ai = row["ai_summary"] or ""
    ai_note = "" if ai else ("The AI analysis failed: " + (row["ai_error"] or "unknown error") if row["ai_state"] == "failed"
                             else "No AI analysis (AI analyst not set up).")
    subject = f"[Looking Glass] {row['title']}: {counts}"[:200]
    text = (f"{row['title']} ({period})\n\nAlerts: {counts}\nFirewall blocks: {blocked}\n"
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
            f'<p>Alerts: <b>{html.escape(counts)}</b> · Firewall blocks: <b>{blocked}</b></p>'
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
