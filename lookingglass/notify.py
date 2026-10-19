"""Email notifications: SMTP sending and notification rules ("mail me when …").

A rule uses the same conditions as alert filters (minimum severity, rules, text, IPs, AND / OR). Every 30 seconds the
notifier collects the open / acknowledged alerts each rule matches that it has not mailed yet (or, with
``on_escalation``, whose severity went up since), and sends them in ONE mail per rule. ``min_interval`` (minutes)
bundles alerts further: a rule mails at most that often. What was mailed is remembered per alert
(``data.notified[<rule id>] = severity``); only alerts seen after a rule was created are mailed by it.
"""
from __future__ import annotations

import asyncio
import html
import logging
import re
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any

from . import alert_filters as af
from . import db
from .config import Settings, local_time

log = logging.getLogger("lookingglass.notify")
_ADDR = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")


class MailError(Exception):
    pass


def recipients(value: Any) -> list[str]:
    out = []
    for part in re.split(r"[,;\s]+", str(value or "")):
        if not part:
            continue
        if not _ADDR.match(part):
            raise ValueError(f"'{part}' is not a mail address")
        out.append(part)
    return out


def _send_sync(s: Settings, to: list[str], subject: str, text: str, html_body: str | None) -> None:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = s.smtp_from, ", ".join(to), subject
    msg["Date"], msg["Message-ID"] = formatdate(localtime=True), make_msgid(domain="looking-glass")
    msg.set_content(text)
    if html_body:
        msg.add_alternative(html_body, subtype="html")
    ctx = ssl.create_default_context()
    try:
        if s.smtp_security == "ssl":
            server: smtplib.SMTP = smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, timeout=20, context=ctx)
        else:
            server = smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=20)
        with server:
            server.ehlo()
            if s.smtp_security == "starttls":
                server.starttls(context=ctx)
                server.ehlo()
            if s.smtp_username:
                server.login(s.smtp_username, s.smtp_password)
            server.send_message(msg)
    except smtplib.SMTPAuthenticationError as exc:
        raise MailError(f"login refused ({exc.smtp_code}): wrong username / password, or the provider needs an app "
                        "password") from exc
    except smtplib.SMTPNotSupportedError as exc:
        raise MailError(f"{exc} - try another encryption setting (starttls / ssl / none)") from exc
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        raise MailError(f"{type(exc).__name__}: {exc}") from exc


async def send(s: Settings, to: list[str], subject: str, text: str, html_body: str | None = None) -> None:
    if not s.smtp_enabled:
        raise MailError("SMTP is not configured (Settings › Email)")
    await asyncio.to_thread(_send_sync, s, to, subject, text, html_body)


# ------------------------------------------------------------------ rules ---
def clean(payload: dict[str, Any]) -> dict[str, Any]:
    to = recipients(payload.get("recipients"))
    if not to:
        raise ValueError("Enter at least one mail address.")
    min_sev = payload.get("min_severity") or None
    if min_sev not in (None, *af.SEVERITIES):
        raise ValueError("unknown severity")
    rules = sorted({str(r) for r in payload.get("rules") or [] if str(r).strip()})
    contains = ", ".join(af.terms(payload.get("contains")))[:300] or None
    nets = af.parse_nets(payload.get("networks"))
    match_mode = payload.get("match_mode") or "all"
    text_mode = payload.get("text_mode") or "any"
    if match_mode not in af.MODES or text_mode not in af.MODES:
        raise ValueError("unknown match mode")
    try:
        interval = max(0, min(1440, int(payload.get("min_interval") or 0)))
    except (TypeError, ValueError) as exc:
        raise ValueError("the interval must be a number of minutes") from exc
    if not (min_sev or rules or contains or nets):
        raise ValueError("Fill in at least one condition (e.g. a minimum severity) - otherwise every alert is mailed.")
    return {"name": str(payload.get("name") or "").strip()[:100] or None, "enabled": bool(payload.get("enabled", True)),
            "recipients": ", ".join(to), "min_severity": min_sev, "rules": rules, "contains": contains,
            "networks": ", ".join(str(n) for n in nets) or None, "match_mode": match_mode, "text_mode": text_mode,
            "on_escalation": bool(payload.get("on_escalation", True)), "min_interval": interval}


def _matches(rule: dict[str, Any], a: dict[str, Any]) -> bool:
    return af.matches(rule, a["rule"], a["severity"], a["title"], a.get("description") or "", a.get("src_ip"), a.get("dst_ip"))


def _due(rule: dict[str, Any], a: dict[str, Any]) -> bool:
    """Not mailed by this rule yet - or (on_escalation) mailed with a lower severity."""
    done = ((a.get("data") or {}).get("notified") or {}).get(str(rule["id"]))
    if done is None:
        return True
    return bool(rule.get("on_escalation")) and af.SEVERITIES.index(a["severity"]) > af.SEVERITIES.index(done)


def compose(rule: dict[str, Any], alerts: list[dict[str, Any]], link: str, s: Settings | None = None) -> tuple[str, str, str]:
    order = {s: i for i, s in enumerate(reversed(af.SEVERITIES))}
    alerts = sorted(alerts, key=lambda a: (order[a["severity"]], a["title"]))
    worst = alerts[0]["severity"]
    subject = (f"[Looking Glass] {worst.upper()}: {alerts[0]['title']}" if len(alerts) == 1
               else f"[Looking Glass] {len(alerts)} alerts, worst {worst}: {alerts[0]['title']}")[:200]
    base = link.rstrip("/")
    lines, rows = [], []
    for a in alerts:
        d = a.get("data") or {}
        why = "; ".join(d.get("severity_why") or [])
        dev = d.get("device") or {}
        where = " · ".join(x for x in (dev.get("hostname"), a.get("src_ip"), dev.get("conn_where")) if x)
        seen = a.get("last_seen")
        when = f"{local_time(s, seen, date=True)} ({s.timezone or 'UTC'})" if s and isinstance(seen, datetime) else ""
        url = f"{base}/alerts#{a['id']}" if base else ""
        lines.append(f"[{a['severity'].upper()}] {a['title']}\n" + (f"  Time: {when}\n" if when else "") +
                     (f"  Device: {where}\n" if where else "") +
                     (f"  Why: {why}\n" if why else "") + (f"  {url}\n" if url else ""))
        colour = {"critical": "#a21caf", "high": "#b91c1c", "medium": "#b45309", "low": "#0e7490", "info": "#475569"}[a["severity"]]
        title = html.escape(a["title"])
        rows.append(
            f'<tr><td style="padding:6px 8px;vertical-align:top"><span style="background:{colour};color:#fff;border-radius:9px;'
            f'padding:1px 8px;font-size:12px;font-weight:600">{a["severity"].upper()}</span></td>'
            f'<td style="padding:6px 8px">{f"<a href={html.escape(url)!r}>{title}</a>" if url else title}'
            + (f'<div style="color:#555;font-size:12px">{html.escape(" · ".join(x for x in (when, where) if x))}</div>'
               if when or where else "")
            + (f'<div style="color:#555;font-size:12px">Why: {html.escape(why)}</div>' if why else "") + "</td></tr>")
    name = rule.get("name") or f"rule #{rule['id']}"
    text = (f"Looking Glass - notification rule “{name}”\n\n" + "\n".join(lines) +
            (f"\nAll alerts: {base}/alerts\n" if base else "") +
            "\nChange or stop these mails: Looking Glass › Settings › Email & notifications.\n")
    body = (f'<div style="font-family:system-ui,Segoe UI,sans-serif;font-size:14px"><p>Notification rule <b>{html.escape(name)}</b></p>'
            f'<table style="border-collapse:collapse">{"".join(rows)}</table>'
            + (f'<p><a href="{html.escape(base)}/alerts">All alerts</a></p>' if base else "")
            + '<p style="color:#777;font-size:12px">Change or stop these mails: Looking Glass › Settings › Email &amp; notifications.</p></div>')
    return subject, text, body


async def run_once(s: Settings) -> int:
    """Send the mails that are due; returns the number of mails sent."""
    pool = db.pool()
    rules = [dict(r) for r in await pool.fetch("SELECT * FROM notification_rules WHERE enabled ORDER BY id")]
    if not rules or not s.smtp_enabled:
        return 0
    rows = await pool.fetch(
        "SELECT id, rule, severity, title, coalesce(description, '') description, host(src_ip) src_ip, host(dst_ip) dst_ip, "
        "data, created_at, last_seen FROM alerts WHERE status <> 'closed' AND last_seen > now() - interval '1 day' "
        "ORDER BY id")
    alerts = [dict(r) for r in rows]
    link = s.mail_link_url or s.public_url
    sent = 0
    now = datetime.now(timezone.utc)
    for rule in rules:
        try:
            rule["_nets"] = af.parse_nets(rule.get("networks"))
        except ValueError:
            continue
        due = [a for a in alerts if a["last_seen"] >= rule["created_at"] and _due(rule, a) and _matches(rule, a)]
        if not due:
            continue
        if rule.get("last_sent") and (now - rule["last_sent"]).total_seconds() < rule["min_interval"] * 60:
            continue  # bundled into the next mail
        subject, text, body = compose(rule, due, link, s)
        try:
            await send(s, recipients(rule["recipients"]), subject, text, body)
        except (MailError, ValueError) as exc:
            log.warning("notification rule %s: %s", rule["id"], exc)
            await pool.execute("UPDATE notification_rules SET last_error = $2, last_error_at = now() WHERE id = $1",
                               rule["id"], str(exc)[:500])
            continue
        sent += 1
        await pool.execute("UPDATE notification_rules SET last_sent = now(), sent_count = sent_count + 1, last_error = NULL "
                           "WHERE id = $1", rule["id"])
        for a in due:
            await pool.execute(
                "UPDATE alerts SET data = jsonb_set(coalesce(data, '{}'::jsonb), '{notified}', "
                "coalesce(data->'notified', '{}'::jsonb) || jsonb_build_object($2::text, $3::text)) WHERE id = $1",
                a["id"], str(rule["id"]), a["severity"])
        log.info("notification rule %s: mailed %d alert(s)", rule["id"], len(due))
    return sent


async def notifier(s: Settings) -> None:
    await asyncio.sleep(30)
    while True:
        try:
            await run_once(s)
        except Exception:  # noqa: BLE001
            log.exception("notifier failed")
        await asyncio.sleep(30)
