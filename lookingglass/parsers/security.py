"""Parsers for Unbound, CrowdSec, Suricata, Zenarmor and authentication / VPN / DHCP messages."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from .common import event, find_ips, int_or_none, ip_or_none
from .syslog import parse_iso

# ---------------------------------------------------------------- Unbound ---
# "info: 192.168.1.10 www.example.com. A IN"  (log-queries)
_UNB_QUERY = re.compile(r"^(?:\[\d+:\d+\] )?info: (?P<client>[0-9a-fA-F:.]+) (?P<domain>\S+?)\.? (?P<type>[A-Z0-9]+) (?P<cls>IN|CH|HS|ANY)\s*$")
# "reply: 192.168.1.10 www.example.com. A IN NOERROR 0.000000 1 63"  (log-replies)
_UNB_REPLY = re.compile(r"^(?:\[\d+:\d+\] )?reply: (?P<client>[0-9a-fA-F:.]+) (?P<domain>\S+?)\.? (?P<type>[A-Z0-9]+) (?P<cls>\S+) (?P<rcode>[A-Z]+)(?P<rest>.*)$")
_UNB_LOCAL = re.compile(r"^(?:\[\d+:\d+\] )?info: (?P<domain>\S+?)\.? (?P<zone>always_nxdomain|always_refuse|static|redirect|refuse|deny|inform_deny|always_null)\s+(?P<client>[0-9a-fA-F:.]+)@\d+ (?P<qname>\S+) (?P<type>\S+)", re.I)


def parse_unbound(ts: datetime, host: str | None, program: str | None, message: str) -> dict[str, Any]:
    msg = message.strip()
    m = _UNB_QUERY.match(msg)
    if m:
        return event(ts, "unbound", host=host, program=program, severity=6, action="query", src_ip=m["client"],
                     domain=m["domain"].lower(), proto="dns", dst_port=53, message=f'{m["type"]} {m["domain"]}',
                     data={"qtype": m["type"]})
    m = _UNB_REPLY.match(msg)
    if m:
        rcode = m["rcode"]
        return event(ts, "unbound", host=host, program=program, severity=6 if rcode == "NOERROR" else 5,
                     action="reply" if rcode == "NOERROR" else rcode.lower(), src_ip=m["client"],
                     domain=m["domain"].lower(), proto="dns", dst_port=53,
                     message=f'{m["type"]} {m["domain"]} {rcode}', data={"qtype": m["type"], "rcode": rcode})
    m = _UNB_LOCAL.match(msg)
    if m:
        return event(ts, "unbound", host=host, program=program, severity=5, action="block", src_ip=m["client"],
                     domain=m["qname"].rstrip(".").lower(), proto="dns", dst_port=53,
                     message=f'blocked {m["qname"]} ({m["zone"]})', data={"zone": m["zone"], "qtype": m["type"]})
    sev = 3 if "error" in msg.lower() else 6
    return event(ts, "unbound", host=host, program=program, severity=sev, message=msg[:4000])


# Unbound reporting database codes (core: src/opnsense/scripts/unbound/stats.py). The API may return the
# numbers or the names, depending on the OPNsense version - both are accepted.
UNB_ACTIONS = {0: "pass", 1: "block", 2: "drop"}
UNB_SOURCES = {0: "Recursion", 1: "Local", 2: "Local-data", 3: "Cache"}
UNB_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMPL", 5: "REFUSED", 6: "YXDOMAIN",
              7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE"}
UNB_DNSSEC = {0: "Unchecked", 1: "Bogus", 2: "Indeterminate", 3: "Insecure", 5: "Secure"}


def _code(value: Any, names: dict[int, str]) -> str | None:
    if value is None or value == "":
        return None
    try:
        return names.get(int(value), str(value))
    except (TypeError, ValueError):
        return str(value)


def unbound_from_api(row: dict[str, Any], ip_by_name: dict[str, str] | None = None) -> dict[str, Any] | None:
    """Entry from ``/api/unbound/overview/searchQueries`` (Unbound reporting database, newest 1000 queries).

    ``client`` is the client IP, or its hostname when Unbound knows one - ``ip_by_name`` maps those back."""
    t = row.get("time")
    try:
        ts = datetime.fromtimestamp(float(t), tz=timezone.utc)
    except (TypeError, ValueError):
        return None
    action = (_code(row.get("action"), UNB_ACTIONS) or "pass").lower()
    rcode = (_code(row.get("rcode"), UNB_RCODES) or "").upper()
    source = _code(row.get("source"), UNB_SOURCES)
    client = str(row.get("client") or "").strip()
    client_ip = ip_or_none(client)
    client_name = None
    if client and not client_ip:
        client_name = client
        client_ip = (ip_by_name or {}).get(client.lower()) or (ip_by_name or {}).get(client.lower().split(".")[0])
    domain = (row.get("domain") or "").rstrip(".").lower()
    data = {k: row.get(k) for k in ("type", "blocklist", "resolve_time_ms", "ttl", "category", "policy", "family")
            if row.get(k) not in (None, "")}
    data.update({k: v for k, v in (("rcode", rcode or None), ("source", source), ("client_name", client_name),
                                   ("qtype", row.get("type")), ("dnssec_status", _code(row.get("dnssec_status"), UNB_DNSSEC)))
                 if v})
    return event(
        ts, "unbound", program="unbound", severity=5 if action in ("block", "drop") or rcode not in ("", "NOERROR") else 6,
        action="query" if action == "pass" else action, src_ip=client_ip, domain=domain, proto="dns", dst_port=53,
        message=f'{row.get("type", "")} {domain} {rcode} {source or ""}'.strip() + (f" from {client_name}" if client_name else ""),
        data=data,
        uid=f'dns:{row.get("uuid")}' if row.get("uuid") else f'dns:{t}:{client}:{domain}:{row.get("type")}',
    )


# --------------------------------------------------------------- CrowdSec ---
_LOGFMT = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
_CS_PERFORMED = re.compile(r"Ip (?P<ip>[0-9a-fA-F:.]+) performed '(?P<scenario>[^']+)' \((?P<count>\d+) events")
_CS_SCENARIO = re.compile(r"\) (?P<scenario>[\w./-]+) by (?:ip|range|\w+) ")
_CS_DECISION = re.compile(r"\(?(?P<origin>\w+)?/?(?P<source>[^)]*)\)? ?(?P<type>ban|captcha|throttle) on (?P<scope>\w+) (?P<ip>[0-9a-fA-F:./]+)", re.I)


def parse_crowdsec(ts: datetime, host: str | None, program: str | None, message: str) -> dict[str, Any]:
    msg = message.strip()
    fields = {k: v.strip('"').replace('\\"', '"') for k, v in _LOGFMT.findall(msg)}
    text = fields.get("msg", msg)
    level = fields.get("level", "info")
    sev = {"panic": 0, "fatal": 2, "error": 3, "warning": 4, "info": 6, "debug": 7, "trace": 7}.get(level, 6)
    m = _CS_PERFORMED.search(text)
    if m:
        return event(parse_iso(fields.get("time", "")) or ts, "crowdsec", host=host, program=program, severity=4,
                     action="alert", src_ip=m["ip"], message=text[:4000],
                     data={"scenario": m["scenario"], "events": int(m["count"])})
    m = _CS_DECISION.search(text)
    if m and ("decision" in text.lower() or "ban" in text.lower()):
        return event(parse_iso(fields.get("time", "")) or ts, "crowdsec", host=host, program=program, severity=4,
                     action=m["type"].lower(), src_ip=m["ip"].split("/")[0], message=text[:4000],
                     data={"scope": m["scope"], "origin": m["origin"],
                           "scenario": (sc.group("scenario") if (sc := _CS_SCENARIO.search(text)) else None)})
    ips = find_ips(text)
    return event(ts, "crowdsec", host=host, program=program, severity=sev, src_ip=ips[0] if ips else None,
                 message=text[:4000], data={k: v for k, v in fields.items() if k != "msg"} or None)


_CS_SCOPE = re.compile(r"^([A-Za-z_]*[g-zG-Z_][A-Za-z_]*):(.*)$")  # "Ip:1.2.3.4", "Range:1.2.3.0/24" - not an IPv6 address


def crowdsec_scope_value(value: Any) -> tuple[str | None, str]:
    """OPNsense joins scope and value: 'Ip:1.2.3.4' / 'Range:2001:db8::/48' / 'Country:NL' -> (scope, value)."""
    v = str(value or "").strip()
    m = _CS_SCOPE.match(v)
    return (m[1], m[2].strip()) if m else (None, v)


def _crowdsec_ip(scope: str | None, value: str) -> str | None:
    if scope and scope.lower() not in ("ip", "range"):
        return None
    return ip_or_none(value.split("/")[0]) if value else None


def crowdsec_alert_from_api(row: dict[str, Any]) -> dict[str, Any] | None:
    """Row of ``/api/crowdsec/alerts/search`` (OPNsense: id, value, reason, country, as, decisions, created)."""
    ts = parse_iso(str(row.get("created_at") or row.get("created") or row.get("start_at") or "")) or datetime.now(timezone.utc)
    src = row.get("source") or {}
    ip = src.get("ip") if isinstance(src, dict) else None
    if not ip:
        ip = _crowdsec_ip(*crowdsec_scope_value(row.get("value") or row.get("source_value")))
    scenario = row.get("scenario") or row.get("reason")
    return event(ts, "crowdsec", program="crowdsec", severity=4, action="alert", src_ip=ip,
                 message=f'{scenario} from {ip} ({row.get("events_count", "?")} events) decisions: {row.get("decisions", "")}',
                 src_country=(src.get("cn") if isinstance(src, dict) else None) or row.get("country"),
                 # OPNsense calls the scenario "reason" (cscli: "scenario")
                 data={k: v for k, v in {**{k: row.get(k) for k in ("id", "events_count", "decisions", "as", "country", "message",
                                                                    "machine_id")}, "scenario": scenario}.items() if v not in (None, "")},
                 uid=f'cs-alert:{row.get("id")}:{ts.isoformat()}')


def crowdsec_decision_from_api(row: dict[str, Any]) -> dict[str, Any] | None:
    """Row of ``/api/crowdsec/decisions/search`` (OPNsense: id, source (origin), scope_value, reason, action,
    country, as, events_count, expiration, alert_id)."""
    ts = parse_iso(str(row.get("created_at") or row.get("created") or "")) or datetime.now(timezone.utc)
    scope, value = crowdsec_scope_value(row.get("scope_value") or row.get("value"))
    row = {**row, "value": value, "scope": row.get("scope") or scope, "origin": row.get("origin") or row.get("source"),
           "type": row.get("type") or row.get("action")}
    return event(ts, "crowdsec", program="crowdsec", severity=4, action=str(row.get("type") or "ban").lower(),
                 src_ip=_crowdsec_ip(row["scope"], value),
                 message=f'decision {row.get("type", "ban")} on {row.get("scope", "Ip")} {value} ({row.get("reason") or row.get("scenario", "")}), '
                         f'origin {row.get("origin", "")}, expires {row.get("expiration") or row.get("duration", "")}',
                 data={k: row.get(k) for k in ("id", "scope", "value", "reason", "scenario", "origin", "duration", "expiration", "country", "as",
                                               "events_count", "alert_id")
                       if row.get(k) not in (None, "")},
                 uid=f'cs-dec:{row.get("id")}')


# --------------------------------------------------------------- Suricata ---
# [1:2010935:3] ET SCAN Suspicious inbound to MSSQL port 1433 [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 1.2.3.4:51234 -> 10.0.0.1:1433
_SURI_LOOSE = re.compile(
    r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\] (?P<sig>.*?)\s*(?:\[\*\*\]\s*)?(?:\[Classification: (?P<cls>[^\]]*)\]\s*)?"
    r"\[Priority: (?P<prio>\d+)\]\s*\{(?P<proto>[^}]+)\} (?P<src>\S+) -> (?P<dst>\S+)"
)


def _split_hostport(value: str) -> tuple[str | None, str | None]:
    if value.count(":") == 1:
        h, p = value.split(":")
        return h, p
    if value.count(":") > 1 and value.rsplit(":", 1)[1].isdigit() and ip_or_none(value.rsplit(":", 1)[0]):
        h, p = value.rsplit(":", 1)
        return h, p
    return value, None


def parse_suricata(ts: datetime, host: str | None, program: str | None, message: str) -> dict[str, Any]:
    msg = message.strip()
    if msg.startswith("{"):
        try:
            return suricata_from_eve(json.loads(msg), ts, host)
        except ValueError:
            pass
    m = _SURI_LOOSE.search(msg)
    if m:
        src, sport = _split_hostport(m["src"])
        dst, dport = _split_hostport(m["dst"])
        prio = int(m["prio"])
        sig = m["sig"].replace("[**]", "").strip()
        return event(ts, "suricata", host=host, program=program, severity={1: 2, 2: 3, 3: 4}.get(prio, 5),
                     action="drop" if "Drop" in msg or "[Drop]" in msg else "alert", src_ip=src, src_port=sport,
                     dst_ip=dst, dst_port=dport, proto=m["proto"].lower(), message=sig,
                     data={"sid": int(m["sid"]), "gid": int(m["gid"]), "rev": int(m["rev"]), "signature": sig,
                           "classification": m["cls"], "priority": prio})
    return event(ts, "suricata", host=host, program=program, severity=6, message=msg[:4000])


def suricata_from_eve(d: dict[str, Any], ts: datetime, host: str | None = None, uid: str | None = None) -> dict[str, Any]:
    alert = d.get("alert") or {}
    prio = int_or_none(alert.get("severity")) or 3
    t = parse_iso(str(d.get("timestamp", ""))) or ts
    if d.get("event_type") == "tls" and isinstance(d.get("tls"), dict):
        # TLS records (eve "tls" logging): JA3 / JA4 fingerprints identify the client program
        tls = d["tls"]
        ja3 = tls.get("ja3") if isinstance(tls.get("ja3"), dict) else {}
        ja3s = tls.get("ja3s") if isinstance(tls.get("ja3s"), dict) else {}
        return event(t, "suricata", host=host, program="suricata", severity=6, action="tls",
                     src_ip=d.get("src_ip"), src_port=d.get("src_port"), dst_ip=d.get("dest_ip"), dst_port=d.get("dest_port"),
                     proto=(d.get("proto") or "").lower() or None, domain=(tls.get("sni") or "").lower() or None,
                     message=f"TLS {tls.get('sni') or d.get('dest_ip')} {tls.get('version') or ''}".strip(), uid=uid,
                     data={k: v for k, v in {"ja3": ja3.get("hash"), "ja3s": ja3s.get("hash"), "ja4": tls.get("ja4"),
                                             "subject": tls.get("subject"), "issuer": tls.get("issuerdn"),
                                             "version": tls.get("version")}.items() if v})
    return event(t, "suricata", host=host, program="suricata", severity={1: 2, 2: 3, 3: 4}.get(prio, 5),
                 action=alert.get("action", d.get("event_type", "alert")) if alert.get("action") != "allowed" else "alert",
                 src_ip=d.get("src_ip"), src_port=d.get("src_port"), dst_ip=d.get("dest_ip"), dst_port=d.get("dest_port"),
                 proto=(d.get("proto") or "").lower() or None, interface=d.get("in_iface"),
                 message=alert.get("signature") or d.get("event_type"),
                 data={"sid": alert.get("signature_id"), "signature": alert.get("signature"), "category": alert.get("category"),
                       "priority": prio, "app_proto": d.get("app_proto")}, uid=uid)


def ids_from_api(row: dict[str, Any]) -> dict[str, Any]:
    """Row of ``/api/ids/service/queryAlerts`` (EVE json with an extra filepos/fileid)."""
    uid = f'ids:{row.get("timestamp")}:{row.get("flow_id")}:{row.get("alert_sid") or (row.get("alert") or {}).get("signature_id")}'
    if "alert" not in row and row.get("alert_sid"):
        row = {**row, "alert": {"signature": row.get("alert"), "signature_id": row.get("alert_sid"),
                                "action": row.get("alert_action"), "severity": row.get("alert_severity", 3)}}
    elif isinstance(row.get("alert"), str):
        row = {**row, "alert": {"signature": row["alert"], "signature_id": row.get("alert_sid"),
                                "action": row.get("alert_action"), "severity": 3}}
    return suricata_from_eve(row, datetime.now(timezone.utc), uid=uid)


# --------------------------------------------------------------- Zenarmor ---
# Zenarmor (ipdrstreamer) streams one record per line, both over syslog and Elasticsearch _bulk:
#   syslog:  "daemon=zenarmor, index=conn, data={...json...}"
#   ES bulk: index "zenarmor_<id>_<uuid>_conn_write" with the JSON document
# Families: conn (flows), dns, tls, http, alert, sip. Field names verified against
# github.com/rknightion/opnsense2otel internal/logship/zenarmor/parse.go (zenDoc).
ZEN_FAMILIES = {"conn": "conn", "dns": "dns", "tls": "tls", "http": "http", "alert": "alert", "sip": "sip"}
_ZEN_SYSLOG = re.compile(r"index=(?P<fam>[\w-]+)\s*,?\s*.*?data=(?P<data>\{.*\})\s*$", re.S)


def zen_family_from_index(index: str) -> str | None:
    tok = index[:-len("_write")] if index.endswith("_write") else index
    tok = tok.rsplit("_", 1)[-1]
    if "-" in tok:
        tok = tok.rsplit("-", 1)[0]  # dated index: ..._conn-260716
    return ZEN_FAMILIES.get(tok)


def _zen_ts(d: dict[str, Any], fallback: datetime) -> datetime:
    for k in ("start_time", "end_time", "timestamp", "@timestamp", "time"):
        v = d.get(k)
        if isinstance(v, (int, float)) and v > 0:
            return datetime.fromtimestamp(v / 1000 if v > 1e11 else v, tz=timezone.utc)
        if isinstance(v, str) and parse_iso(v):
            return parse_iso(v)
    return fallback


def _flat(v: Any) -> str:
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return "" if v is None else str(v)


def zen_details(d: dict[str, Any]) -> dict[str, str]:
    """What a Zenarmor record is about - application, its category, web category, security category, policy - from
    whichever fields this record type carries (Zenarmor has no separate "block reason": these say why)."""
    alert_info = d.get("alertinfo") if isinstance(d.get("alertinfo"), dict) else {}
    out = {
        "app": d.get("app_name") or d.get("application") or d.get("app_proto"),
        "app_category": d.get("app_category") or d.get("application_category"),
        "web_category": d.get("category") or _flat(d.get("domain_categories")) or d.get("web_category"),
        "security": d.get("alert_category") or _flat(alert_info.get("category")) or _flat(d.get("security_tags"))
                    or alert_info.get("signature"),
        "policy": d.get("policy_name") or d.get("policy") or d.get("policyid"),
    }
    return {k: str(v) for k, v in out.items() if v not in (None, "", [], {})}


def zen_describe(z: dict[str, str]) -> str:
    """'app Steam (Games) · web category Games · policy 3'"""
    parts = []
    if z.get("app"):
        parts.append(f"app {z['app']}" + (f" ({z['app_category']})" if z.get("app_category") else ""))
    elif z.get("app_category"):
        parts.append(f"app category {z['app_category']}")
    if z.get("web_category") and z.get("web_category") != z.get("app_category"):
        parts.append(f"web category {z['web_category']}")
    if z.get("security"):
        parts.append(f"security {z['security']}")
    if z.get("policy"):
        parts.append(f"policy {z['policy']}")
    return " · ".join(parts)


def zenarmor_record(family: str, d: dict[str, Any], ts: datetime, host: str | None = None,
                    program: str = "zenarmor") -> dict[str, Any]:
    """Normalise one Zenarmor document (any family) into an event."""
    blocked = str(d.get("is_blocked", "")).lower() in ("1", "true")
    alert_info = d.get("alertinfo") if isinstance(d.get("alertinfo"), dict) else {}
    category = d.get("app_category") or d.get("category") or _flat(d.get("domain_categories")) or None
    security = d.get("alert_category") or _flat(alert_info.get("category")) or d.get("security_tags") or None
    device = d.get("device") if isinstance(d.get("device"), dict) else {}
    src_geo = d.get("src_geoip") if isinstance(d.get("src_geoip"), dict) else {}
    dst_geo = d.get("dst_geoip") if isinstance(d.get("dst_geoip"), dict) else {}

    if family == "dns":
        domain = d.get("query")
        summary = " ".join(x for x in ("DNS", str(d.get("qtype") or ""), str(domain or "")) if x) + (f" [{category}]" if category else "")
    elif family == "tls":
        domain = d.get("server_name")
        summary = f"TLS {domain}" + (f" [{category}]" if category else "")
    elif family == "http":
        domain = d.get("host")
        summary = f"HTTP {d.get('method', '')} {domain}{d.get('uri', '')}"
    elif family == "alert":
        domain = d.get("dst_hostname") or d.get("server_name") or d.get("query")
        summary = f"Threat alert: {security or alert_info or 'unknown'} {domain or ''}"
    else:
        domain = d.get("dst_hostname") or d.get("server_name")
        summary = f"{d.get('app_name') or d.get('app_proto') or 'flow'} -> {domain or d.get('ip_dst_saddr')}" + \
                  (f" [{category}]" if category else "")
    action = "block" if blocked else ("threat" if family == "alert" else family)
    z = zen_details(d)
    what = zen_describe(z)
    if what:  # e.g. "BLOCKED TLS store.steampowered.com - app Steam (Games) · policy 2"
        base = f"Threat alert: {domain or d.get('ip_dst_saddr') or ''}".strip() if family == "alert" else summary.split(" [")[0]
        summary = f"{base} - {what}"
    data = {k: v for k, v in d.items() if k not in ("src_geoip", "dst_geoip") and v not in (None, "", [], {})}
    if device:
        data["device"] = device
    return event(
        _zen_ts(d, ts), "zenarmor", host=host, program=program,
        severity=3 if family == "alert" else 4 if blocked else 6, action=action,
        src_ip=d.get("ip_src_saddr") or d.get("src_ip"), dst_ip=d.get("ip_dst_saddr") or d.get("dst_ip"),
        src_port=d.get("ip_src_port"), dst_port=d.get("ip_dst_port"),
        proto=str(d.get("transport_proto") or "").lower() or None,
        interface=d.get("interface"), direction=d.get("direction"),
        domain=str(domain).lower().rstrip(".") if domain else None,
        username=d.get("src_username") or None,
        src_country=src_geo.get("country_code2") or None, dst_country=dst_geo.get("country_code2") or None,
        message=(("BLOCKED " if blocked else "") + summary)[:4000],
        data={"family": family, "security": security, "category": category, **data, "zen": z},
    )


def parse_zenarmor(ts: datetime, host: str | None, program: str | None, message: str) -> dict[str, Any]:
    msg = message.strip()
    m = _ZEN_SYSLOG.search(msg)
    if m:
        try:
            d = json.loads(m["data"])
            if isinstance(d, dict):
                fam = ZEN_FAMILIES.get(m["fam"].lower(), m["fam"].lower())
                return zenarmor_record(fam, d, ts, host, program or "zenarmor")
        except ValueError:
            pass
    start = msg.find("{")
    if start >= 0:
        try:
            d = json.loads(msg[start:])
            if isinstance(d, dict):
                fam = "dns" if "query" in d else "alert" if ("alertinfo" in d or "alert_category" in d) else \
                      "http" if "uri" in d else "tls" if "server_name" in d else "conn"
                return zenarmor_record(fam, d, ts, host, program or "zenarmor")
        except ValueError:
            pass
    ips = find_ips(msg)
    return event(ts, "zenarmor", host=host, program=program, severity=6, src_ip=ips[0] if ips else None,
                 dst_ip=ips[1] if len(ips) > 1 else None, message=msg[:4000])


def is_zenarmor_line(message: str) -> bool:
    return "daemon=zenarmor" in message or ("index=" in message and "data={" in message and "ip_src_saddr" in message)


# ----------------------------------------------------- auth / vpn / dhcp ---
AUTH_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # (regex, action, source)
    # OPNsense AuthenticationFactory (program audit): "user root authenticated successfully for WebGui [using ...] at 1.2.3.4"
    (re.compile(r"user (?P<user>\S+) authenticated successfully for (?P<svc>\S+) .*?\bat (?P<ip>[0-9a-fA-F:.]+)", re.I), "login_success", "auth"),
    (re.compile(r"user (?P<user>\S+) could not authenticate for (?P<svc>\S+?)\.? .*?\bat (?P<ip>[0-9a-fA-F:.]+)", re.I), "login_failed", "auth"),
    # OpenVPN daemon: "1.2.3.4:51820 TLS: Username/Password authentication succeeded for username 'bob'"
    (re.compile(r"(?:(?P<ip>[0-9a-fA-F:.]+):\d+ )?TLS: Username/Password authentication succeeded for username '(?P<user>[^']+)'", re.I), "login_success", "vpn"),
    (re.compile(r"(?:(?P<user>[^/\s]+)/)?(?P<ip>[0-9a-fA-F:.]+):\d+ \[[^\]]*\] Peer Connection Initiated", re.I), "vpn_connect", "vpn"),
    # OPNsense OpenVPN user_pass_verify.php: "user 'bob' authenticated using 'Local Database'"
    (re.compile(r"user '(?P<user>[^']+)' authenticated using", re.I), "login_success", "vpn"),
    # IPsec (charon): "IKE_SA con1[3] established between 192.0.2.1[fw]...198.51.100.7[peer]"
    (re.compile(r"IKE_SA (?P<user>[^\[\s]+)\[\d+\] established between \S+\.\.\.(?P<ip>[0-9a-fA-F:.]+)\[", re.I), "vpn_connect", "vpn"),
    # OPNsense API key failures (program api)
    (re.compile(r"uri \S+ authentication failed for api key (?P<user>\S+)", re.I), "login_failed", "auth"),
    (re.compile(r"Web GUI authentication error for '?(?P<user>[^' ]*)'? from (?P<ip>[0-9a-fA-F:.]+)", re.I), "login_failed", "auth"),
    (re.compile(r"Successful login for user '?(?P<user>[^' ]*)'? from:? (?P<ip>[0-9a-fA-F:.]+)", re.I), "login_success", "auth"),
    # Unraid web GUI (emhttp .login.php): "Successful login user root from 192.168.1.5",
    # "Unsuccessful login user root from 192.168.1.5. Ignoring login attempts for 900 seconds."
    (re.compile(r"^Successful login user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)"), "login_success", "auth"),
    (re.compile(r"^Unsuccessful login user (?P<user>\S*) from (?P<ip>\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)"), "login_failed", "auth"),
    (re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"), "login_failed", "auth"),
    (re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)"), "login_failed", "auth"),
    (re.compile(r"(?:error: )?maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)", re.I), "login_failed", "auth"),
    (re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"), "login_success", "auth"),
    (re.compile(r"Connection closed by (?:authenticating|invalid) user (?P<user>\S+) (?P<ip>[0-9a-fA-F:.]+)"), "login_failed", "auth"),
    (re.compile(r"Did not receive identification string from (?P<ip>[0-9a-fA-F:.]+)"), "probe", "auth"),
    (re.compile(r"authentication (?:error|failure).*?(?:user[= ]'?(?P<user>[^' ]+)'?)?.*?(?:from|rhost=) ?(?P<ip>[0-9a-fA-F:.]+)", re.I), "login_failed", "auth"),
    # OpenVPN
    (re.compile(r"(?P<ip>[0-9a-fA-F:.]+):\d+ (?:TLS Auth Error|TLS Error: TLS handshake failed|.*AUTH_FAILED|.*Authentication failed)", re.I), "login_failed", "vpn"),
    (re.compile(r"user '(?P<user>[^']+)' could not authenticate", re.I), "login_failed", "vpn"),
    (re.compile(r"(?P<user>[^/\s]+)/(?P<ip>[0-9a-fA-F:.]+):\d+ MULTI_sva: pool returned", re.I), "vpn_connect", "vpn"),
    # IPsec (charon)
    (re.compile(r"(?:authentication of '[^']*' with .* failed|no shared key found|AUTH_FAILED).*?(?P<ip>\d+\.\d+\.\d+\.\d+)?", re.I), "login_failed", "vpn"),
]
_DHCP_ACK = re.compile(r"DHCPACK (?:on|to) (?P<ip>[0-9.]+) (?:to|\() ?(?P<mac>[0-9a-f:]{17})\)? ?(?:\((?P<host>[^)]*)\))?", re.I)
_KEA_LEASE = re.compile(r"DHCP4_LEASE_ALLOC.*?hwtype=\d+ (?P<mac>[0-9a-f:]{17}).*?lease (?P<ip>[0-9.]+)", re.I)
_DNSMASQ = re.compile(r"DHCPACK\((?P<iface>[^)]+)\) (?P<ip>[0-9.]+) (?P<mac>[0-9a-f:]{17})(?: (?P<host>\S+))?", re.I)
_CONFIG_CHANGE = re.compile(r"(?:config(?:uration)? (?:change|changed)|user .* changed configuration|/conf/config\.xml)", re.I)
# OPNsense audit line written on every config save (Core/Config.php):
# "user root@192.168.1.10 changed configuration to /conf/backup/config-1700000000.1234.xml in /api/nginx/settings/set ..."
_CONFIG_AUDIT = re.compile(r"user (?P<user>\S+?)(?:@(?P<ip>[0-9A-Fa-f.:]+))?(?: \((?P<by>[^)]*)\))? changed configuration to \S+ in (?P<uri>\S+)")
# readable names of the most common OPNsense parts (API module or legacy page prefix)
CONFIG_AREAS = {
    "firewall": "Firewall", "filter": "Firewall", "nginx": "Nginx", "unbound": "Unbound DNS", "ids": "Intrusion detection",
    "interfaces": "Interfaces", "routes": "Routes", "routing": "Gateways", "core": "System", "system": "System",
    "wireguard": "WireGuard", "openvpn": "OpenVPN", "ipsec": "IPsec", "kea": "Kea DHCP", "dhcpv4": "DHCP", "dhcpv6": "DHCPv6",
    "services_dhcp": "DHCP", "dnsmasq": "Dnsmasq", "cron": "Cron", "zenarmor": "Zenarmor", "crowdsec": "CrowdSec",
    "haproxy": "HAProxy", "acmeclient": "ACME", "monit": "Monit", "syslog": "Logging", "diagnostics": "Diagnostics",
    "trust": "Certificates", "auth": "Users & groups", "system_usermanager": "Users & groups", "captiveportal": "Captive portal",
    "trafficshaper": "Traffic shaper", "dyndns": "Dynamic DNS", "vlan": "VLANs", "ntpd": "NTP", "unboundplus": "Unbound DNS",
}


def config_change(msg: str) -> dict[str, Any] | None:
    """Who changed what: user, client IP, the changed part (API module / page) and the request path."""
    m = _CONFIG_AUDIT.search(msg)
    if not m:
        return None
    uri = m["uri"].split("?")[0]
    parts = [p for p in uri.split("/") if p]
    if len(parts) >= 2 and parts[0] == "api":  # /api/<module>/<controller>/<action>
        area, detail = parts[1].lower(), parts[2] if len(parts) > 2 else ""
    else:  # legacy page (/firewall_rules_edit.php) or a script run from the console
        area = re.sub(r"(_edit|_manager)?\.(php|py|sh|inc)$", "", parts[-1] if parts else uri).lower()
        detail = ""
    label = CONFIG_AREAS.get(area) or area.replace("_", " ")  # legacy pages: "firewall_rules" -> "firewall rules"
    user = m["user"]
    return {"user": None if user in ("(system)", "(root)") else user, "ip": m["ip"], "by": m["by"],
            "area": area, "label": label, "detail": detail, "path": uri}

VPN_PROGRAMS = ("openvpn", "charon", "ipsec", "wireguard", "wg", "strongswan")  # incl. openvpn_server1, openvpn_client2
AUTH_PROGRAMS = ("sshd", "sshd-session", "audit", "login", "su", "sudo", "lighttpd", "php-cgi", "php", "webgui", "configd.py", "api")
DHCP_PROGRAMS = ("dhcpd", "dhcpd6", "kea-dhcp4", "kea-dhcp6", "dnsmasq", "dnsmasq-dhcp", "dhcp6c", "dhclient")


# FreeBSD kernel: "arp: 192.168.1.5 moved from aa:.. to bb:.. on igb1" / "arp: aa:.. is using my IP address 192.168.1.1 on igb1!"
_ARP_MOVE = re.compile(r"arp: (?P<ip>[0-9.]+) moved from (?P<old>[0-9a-f:]{17}) to (?P<new>[0-9a-f:]{17}) on (?P<intf>\S+)", re.I)
_ARP_MINE = re.compile(r"arp: (?P<mac>[0-9a-f:]{17}) is using my IP address (?P<ip>[0-9.]+)(?: on (?P<intf>[^!\s]+))?", re.I)


def parse_generic(ts: datetime, host: str | None, program: str | None, severity: int, message: str) -> dict[str, Any]:
    msg = message.strip()
    prog = (program or "").lower()
    if "arp: " in msg:
        if m := _ARP_MOVE.search(msg):
            return event(ts, "arp", host=host, program=program, severity=4, action="arp_move", src_ip=m["ip"],
                         message=msg[:4000], data={"from": m["old"].lower(), "to": m["new"].lower(), "interface": m["intf"]})
        if m := _ARP_MINE.search(msg):
            return event(ts, "arp", host=host, program=program, severity=2, action="arp_conflict", src_ip=m["ip"],
                         message=msg[:4000], data={"mac": m["mac"].lower(), "interface": m["intf"]})
    for rx, action, source in AUTH_PATTERNS:
        m = rx.search(msg)
        if m:
            gd = m.groupdict()
            if source == "vpn" and not (prog.startswith(VPN_PROGRAMS) or action == "vpn_connect"):
                continue
            if source == "auth" and action == "login_failed" and rx.pattern.startswith("authentication (") and prog.startswith(VPN_PROGRAMS):
                source = "vpn"
            return event(ts, source, host=host, program=program, severity=4 if action == "login_failed" else 5,
                         action=action, src_ip=gd.get("ip"), username=gd.get("user"), message=msg[:4000])
    if prog.startswith(DHCP_PROGRAMS) or "DHCPACK" in msg or "DHCP4_LEASE_ALLOC" in msg:
        m = _DHCP_ACK.search(msg) or _KEA_LEASE.search(msg) or _DNSMASQ.search(msg)
        if m:
            gd = m.groupdict()
            return event(ts, "dhcp", host=host, program=program, severity=6, action="lease", dst_ip=gd.get("ip"),
                         message=msg[:4000], data={"mac": gd["mac"].lower(), "hostname": gd.get("host")})
        return event(ts, "dhcp", host=host, program=program, severity=severity, message=msg[:4000])
    if prog.startswith(VPN_PROGRAMS):
        ips = find_ips(msg)
        return event(ts, "vpn", host=host, program=program, severity=severity, src_ip=ips[0] if ips else None, message=msg[:4000])
    cfg = config_change(msg)
    if cfg:
        return event(ts, "auth" if prog.startswith(AUTH_PROGRAMS) else "system", host=host, program=program, severity=severity,
                     action="config_change", src_ip=cfg["ip"], username=cfg["user"], message=msg[:4000], data={"config": cfg})
    if prog.startswith(AUTH_PROGRAMS):
        action = "config_change" if _CONFIG_CHANGE.search(msg) else None
        ips = find_ips(msg)
        return event(ts, "auth", host=host, program=program, severity=severity, action=action,
                     src_ip=ips[0] if ips else None, message=msg[:4000])
    action = "config_change" if _CONFIG_CHANGE.search(msg) else None
    return event(ts, "system", host=host, program=program, severity=severity, action=action, message=msg[:4000])
