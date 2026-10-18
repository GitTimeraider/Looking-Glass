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


def unbound_from_api(row: dict[str, Any]) -> dict[str, Any] | None:
    """Entry from ``/api/unbound/overview/searchQueries`` (Unbound reporting database)."""
    t = row.get("time")
    try:
        ts = datetime.fromtimestamp(float(t), tz=timezone.utc)
    except (TypeError, ValueError):
        return None
    action = str(row.get("action") or "Pass").lower()
    rcode = row.get("rcode") or ""
    domain = (row.get("domain") or "").rstrip(".").lower()
    return event(
        ts, "unbound", program="unbound", severity=5 if action in ("block", "drop") or rcode not in ("", "NOERROR") else 6,
        action="query" if action == "pass" else action, src_ip=row.get("client"), domain=domain, proto="dns", dst_port=53,
        message=f'{row.get("type", "")} {domain} {rcode} {row.get("source", "")}'.strip(),
        data={k: row.get(k) for k in ("type", "rcode", "source", "blocklist", "resolve_time_ms", "ttl", "category", "policy", "dnssec_status", "family")
              if row.get(k) not in (None, "")},
        uid=f'dns:{t}:{row.get("client")}:{domain}:{row.get("type")}',
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


def crowdsec_alert_from_api(row: dict[str, Any]) -> dict[str, Any] | None:
    """Row of ``/api/crowdsec/alerts/search``."""
    ts = parse_iso(str(row.get("created_at") or row.get("start_at") or "")) or datetime.now(timezone.utc)
    src = row.get("source") or {}
    ip = src.get("ip") if isinstance(src, dict) else None
    if not ip:
        value = row.get("value") or row.get("source_value") or ""
        ip = value.split(":")[-1] if value else None
    scenario = row.get("scenario") or row.get("reason")
    return event(ts, "crowdsec", program="crowdsec", severity=4, action="alert", src_ip=ip,
                 message=f'{scenario} from {ip} ({row.get("events_count", "?")} events) decisions: {row.get("decisions", "")}',
                 src_country=(src.get("cn") if isinstance(src, dict) else None) or row.get("country"),
                 data={k: row.get(k) for k in ("id", "scenario", "events_count", "decisions", "as", "country", "message", "machine_id") if row.get(k) not in (None, "")},
                 uid=f'cs-alert:{row.get("id")}:{ts.isoformat()}')


def crowdsec_decision_from_api(row: dict[str, Any]) -> dict[str, Any] | None:
    """Row of ``/api/crowdsec/decisions/search``."""
    ts = parse_iso(str(row.get("created_at") or row.get("created") or "")) or datetime.now(timezone.utc)
    value = str(row.get("value") or row.get("source") or "")
    return event(ts, "crowdsec", program="crowdsec", severity=4, action=str(row.get("type") or "ban").lower(),
                 src_ip=ip_or_none(value.split("/")[0]) if value else None,
                 message=f'decision {row.get("type", "ban")} on {row.get("scope", "Ip")} {value} ({row.get("reason") or row.get("scenario", "")}), '
                         f'origin {row.get("origin", "")}, expires {row.get("expiration") or row.get("duration", "")}',
                 data={k: row.get(k) for k in ("id", "scope", "value", "reason", "scenario", "origin", "duration", "expiration", "country", "as")
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
_ZEN_KEYS = {
    "src_ip": ("ip_src_saddr", "src_ip", "src_addr", "srcip", "client_ip", "src"),
    "dst_ip": ("ip_dst_saddr", "dst_ip", "dst_addr", "dstip", "server_ip", "dst"),
    "src_port": ("ip_src_port", "src_port", "srcport", "sport"),
    "dst_port": ("ip_dst_port", "dst_port", "dstport", "dport"),
    "proto": ("transport_proto", "proto", "ip_proto", "protocol"),
    "domain": ("dst_hostname", "domain", "query", "hostname", "host", "sni", "server_name"),
    "username": ("src_username", "username", "user"),
    "interface": ("interface", "iface", "interface_name"),
}


def _first(d: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", []):
            return v
    return None


def parse_zenarmor(ts: datetime, host: str | None, program: str | None, message: str) -> dict[str, Any]:
    msg = message.strip()
    start = msg.find("{")
    d: dict[str, Any] | None = None
    if start >= 0:
        try:
            d = json.loads(msg[start:])
        except ValueError:
            d = None
    if not isinstance(d, dict):
        # key=value fallback
        d = {k: v.strip('"') for k, v in _LOGFMT.findall(msg)}
        if not d:
            ips = find_ips(msg)
            return event(ts, "zenarmor", host=host, program=program, severity=6, src_ip=ips[0] if ips else None,
                         dst_ip=ips[1] if len(ips) > 1 else None, message=msg[:4000])
    kind = str(d.get("type") or d.get("log_type") or d.get("event_type") or d.get("category_type") or "conn").lower()
    blocked = str(d.get("is_blocked", d.get("blocked", d.get("action", "")))).lower() in ("1", "true", "block", "blocked", "drop")
    security = d.get("security_tags") or d.get("threat") or d.get("security_category")
    category = d.get("app_category") or d.get("category") or d.get("web_category")
    action = "block" if blocked else ("threat" if security else kind)
    domain = _first(d, _ZEN_KEYS["domain"])
    t = ts
    for k in ("start_time", "timestamp", "time", "@timestamp"):
        v = d.get(k)
        if isinstance(v, (int, float)):
            t = datetime.fromtimestamp(v / 1000 if v > 1e11 else v, tz=timezone.utc)
            break
        if isinstance(v, str) and parse_iso(v):
            t = parse_iso(v)
            break
    summary = " ".join(str(x) for x in (kind, action if action != kind else "", d.get("app_name") or "", domain or "", category or "",
                                        f"security={security}" if security else "") if x)
    return event(t, "zenarmor", host=host, program=program or "zenarmor", severity=4 if (blocked or security) else 6,
                 action=action, src_ip=_first(d, _ZEN_KEYS["src_ip"]), dst_ip=_first(d, _ZEN_KEYS["dst_ip"]),
                 src_port=_first(d, _ZEN_KEYS["src_port"]), dst_port=_first(d, _ZEN_KEYS["dst_port"]),
                 proto=str(_first(d, _ZEN_KEYS["proto"]) or "").lower() or None, domain=str(domain).lower() if domain else None,
                 username=_first(d, _ZEN_KEYS["username"]), interface=_first(d, _ZEN_KEYS["interface"]),
                 message=summary[:4000], data={k: d[k] for k in list(d)[:60]})


# ----------------------------------------------------- auth / vpn / dhcp ---
AUTH_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # (regex, action, source)
    (re.compile(r"Web GUI authentication error for '?(?P<user>[^' ]*)'? from (?P<ip>[0-9a-fA-F:.]+)", re.I), "login_failed", "auth"),
    (re.compile(r"Successful login for user '?(?P<user>[^' ]*)'? from:? (?P<ip>[0-9a-fA-F:.]+)", re.I), "login_success", "auth"),
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

VPN_PROGRAMS = ("openvpn", "charon", "ipsec", "wireguard", "wg", "strongswan")
AUTH_PROGRAMS = ("sshd", "sshd-session", "audit", "login", "su", "sudo", "lighttpd", "php-cgi", "php", "webgui", "configd.py")
DHCP_PROGRAMS = ("dhcpd", "dhcpd6", "kea-dhcp4", "kea-dhcp6", "dnsmasq", "dnsmasq-dhcp", "dhcp6c", "dhclient")


def parse_generic(ts: datetime, host: str | None, program: str | None, severity: int, message: str) -> dict[str, Any]:
    msg = message.strip()
    prog = (program or "").lower()
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
    if prog.startswith(AUTH_PROGRAMS):
        action = "config_change" if _CONFIG_CHANGE.search(msg) else None
        ips = find_ips(msg)
        return event(ts, "auth", host=host, program=program, severity=severity, action=action,
                     src_ip=ips[0] if ips else None, message=msg[:4000])
    action = "config_change" if _CONFIG_CHANGE.search(msg) else None
    return event(ts, "system", host=host, program=program, severity=severity, action=action, message=msg[:4000])
