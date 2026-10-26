"""Detection engine: periodic SQL/heuristic rules that turn events into alerts."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from . import alert_filters, db, event_filter
from .parsers.common import real_name
from .config import Settings
from .ingest import STATS
from .parsers.common import is_internal_ip, parse_networks
from .parsers.security import zen_describe

log = logging.getLogger(__name__)

SEVERITIES = ["info", "low", "medium", "high", "critical"]
# OPNsense services whose outage removes protection or visibility
SECURITY_SERVICES = ("suricata", "crowdsec", "zenarmor", "sensei", "unbound", "dnscrypt", "syslog", "openvpn", "wireguard",
                     "strongswan", "ipsec", "pf", "configd", "qfeeds")

SUSPICIOUS_OUT_PORTS = {
    23: "telnet", 445: "SMB", 135: "MS-RPC", 139: "NetBIOS", 3389: "RDP", 4444: "Metasploit default",
    5555: "ADB", 6667: "IRC", 6697: "IRC/TLS", 1337: "leet/backdoor", 31337: "back orifice", 9001: "Tor OR",
    9030: "Tor dir", 5900: "VNC", 1080: "SOCKS", 3128: "proxy", 8333: "Bitcoin", 3333: "mining pool",
    4242: "mining pool", 14444: "Monero pool", 25: "SMTP (spam?)",
}


# Was a connection ALLOWED? The firewall's own verdict wins. Zenarmor also logs connection ATTEMPTS ("conn" records -
# it sees the packets on the LAN side before the firewall rules act), so a Zenarmor record only counts as allowed when
# the destination answered (packets / bytes came back) - a connection a firewall rule blocked gets no answer.
ZEN_ANSWERED = ("(source = 'zenarmor' AND action = 'conn' AND (coalesce(data->>'dst_npackets', '') ~ '^[1-9]' "
                "OR coalesce(data->>'dst_nbytes', '') ~ '^[1-9]' OR coalesce(data->>'dst_pbytes', '') ~ '^[1-9]'))")
ALLOWED_ROW = (f"((source = 'firewall' AND action = 'pass') OR {ZEN_ANSWERED} "
               "OR (source NOT IN ('firewall', 'zenarmor') AND action IN ('pass', 'allow')))")
# per group of events (src, dst, ...): allowed unless only Zenarmor says so and the firewall blocked it
ALLOWED_AGG = (f"(bool_or(source = 'firewall' AND action = 'pass') OR bool_or(source NOT IN ('firewall', 'zenarmor') "
               f"AND action IN ('pass', 'allow')) OR (bool_or({ZEN_ANSWERED}) AND NOT bool_or(source = 'firewall' "
               "AND action IN ('block', 'drop'))))")
FW_BLOCKED_AGG = "count(*) FILTER (WHERE source = 'firewall' AND action IN ('block', 'drop'))"
FW_RULE_AGG = "max(data->>'label') FILTER (WHERE source = 'firewall' AND action IN ('block', 'drop'))"


def verdict(passed: bool, fw_blocked: int = 0, rule: str | None = None) -> str:
    """'ALLOWED' / 'blocked by the OPNsense firewall (rule "x", 12×)' / 'blocked' - for alert texts."""
    if passed:
        return "ALLOWED"
    if fw_blocked:
        return f"blocked by the OPNsense firewall ({f'rule “{rule}”, ' if rule else ''}{fw_blocked}×)"
    return "blocked"


# remote admin / file sharing: what ransomware and worms use to spread inside a network (MITRE T1021)
LATERAL_PORTS = {22: "SSH", 23: "telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB", 3389: "RDP", 5900: "VNC",
                 5985: "WinRM", 5986: "WinRM", 2375: "Docker API", 2376: "Docker API"}

# attack stages for attack_chains (rule names per stage, in order)
EXTERNAL_CHAIN = [("Recon", {"port_scan", "host_sweep", "web_scanner", "threat_intel_inbound"}),
                  ("Attack", {"web_attack", "ids", "crowdsec", "brute_force", "password_spray", "distributed_brute_force"}),
                  ("Access", {"success_after_failures", "admin_login", "login_new_location"})]
INTERNAL_CHAIN = [("Threat sign", {"threat_intel_outbound", "zenarmor_threat", "dns_malicious_blocked", "dns_dga", "ids",
                                   "threat_feed", "malicious_tls", "young_domain", "crypto_mining", "new_behavior",
                                   "ml_anomaly"}),
                  ("Command & control", {"beaconing", "suspicious_outbound_port", "dns_tunnel", "dns_bypass",
                                         "internal_blocked_outbound", "tor"}),
                  ("Spreading / theft", {"port_scan", "host_sweep", "lateral_movement", "password_spray", "brute_force",
                                         "large_upload", "canary", "arp_spoofing", "volume_spike"})]

# a name from a better source replaces one from a worse source, never the other way round
NAME_RANK = {"manual": 100, "opnsense": 90, "unifi-alias": 70, "dnsmasq-static": 60, "unifi": 45, "dhcp": 50, "dns": 30, "zenarmor": 25, "arp": 20}


def name_rank(source: str) -> int:
    return NAME_RANK.get(source, NAME_RANK["dhcp"] if source.startswith("dhcp") else 10)


async def device_info(ip: str | None) -> dict[str, Any] | None:
    """Name / MAC / vendor of a local device from the device list, for alert context."""
    if not ip:
        return None
    try:
        row = await db.pool().fetchrow(
            "SELECT mac, hostname, vendor, notes, conn_type, conn_where, conn_signal FROM devices WHERE ip = $1::inet "
            "ORDER BY last_seen DESC LIMIT 1", ip)
    except Exception:  # noqa: BLE001 - invalid ip text etc.
        return None
    if not row:
        return None
    return {k: row[k] for k in ("mac", "hostname", "vendor", "notes", "conn_type", "conn_where", "conn_signal") if row[k]}


def who(ip: str | None, dev: dict[str, Any] | None = None) -> str:
    if not ip:
        return "an unknown client"
    name = (dev or {}).get("hostname")
    return f"{name} ({ip})" if name else ip


# ------------------------------------------------------------------ severity ---
# One policy for every rule (README "How severity is decided"):
#   what got through  - blocked internet traffic is background noise; allowed / successful traffic matters
#   where it comes from - inside the network is worse than the internet
#   corroboration       - other sources saying the same about the same IP push it up
#   confidence          - the size of a scan (number of ports, hits) is not a severity by itself
def bump(severity: str, steps: int) -> str:
    return SEVERITIES[max(0, min(len(SEVERITIES) - 1, SEVERITIES.index(severity) + steps))]


class Rating:
    """A severity plus the plain-language reasons for it (shown with the alert)."""

    def __init__(self, base: str, why: str, sticky: bool = False) -> None:
        # sticky: rules that look at each new batch of events only - keep the highest level seen
        self.severity, self.why, self.sticky = base, [why], sticky

    def up(self, reason: str, steps: int = 1) -> "Rating":
        self.severity = bump(self.severity, steps)
        self.why.append(f"↑ {reason}")
        return self

    def down(self, reason: str, steps: int = 1) -> "Rating":
        self.severity = bump(self.severity, -steps)
        self.why.append(f"↓ {reason}")
        return self

    def cap(self, level: str, reason: str) -> "Rating":
        """At most ``level`` - e.g. traffic that was blocked is never critical, however much else points at the device."""
        if SEVERITIES.index(self.severity) > SEVERITIES.index(level):
            self.severity = level
            self.why.append(f"≤ {level}: {reason}")
        return self

    def note(self, reason: str) -> "Rating":
        """Context that does not change the level."""
        self.why.append(reason)
        return self

    def text(self) -> str:
        return f"Severity {self.severity}: " + "; ".join(self.why) + "."


# Zenarmor verdicts / categories that mean the device itself is probably infected - whole words, so an ordinary
# "Cryptocurrency" category block or the app "Amazon EC2" do not count
ZEN_BAD = re.compile(r"\b(malware|botnets?|phishing|ransom\w*|command\s*(and|&)\s*control|c2|c&c|"
                     r"crypto[\s-]?min\w*|cryptojack\w*|coin[\s-]?min\w*)\b", re.I)

# blocked threat traffic from one device in 24h that no longer looks like a stray ad / link: malware calling home.
# Counted in separate 10-minute periods and different sites (registered domains): one page load fires many DNS /
# QUIC / TLS retries to several subdomains (file1., file2. …) within seconds - that is one visit, not persistence.
REPEAT_PERIODS, REPEAT_TARGETS = 6, 5

# alerts built from the same events must not confirm each other
RULE_FAMILIES = [{"brute_force", "success_after_failures", "admin_login", "password_spray", "distributed_brute_force",
                  "login_new_location"},
                 {"port_scan", "host_sweep", "internal_blocked_outbound"}]


async def evidence(ip: str | None, rule: str, hours: int = 24) -> dict[str, Any]:
    """What else is known about one IP in the last ``hours``: traffic that got through and other threat signals."""
    if not ip:
        return {}
    pool = db.pool()
    try:
        row = await pool.fetchrow(
            "SELECT count(*) FILTER (WHERE source = 'firewall' AND action = 'pass' AND direction = 'in') AS fw_pass, "
            "count(*) FILTER (WHERE source = 'nginx' AND action ~ '^http_[23]') AS web_ok, "
            "count(*) FILTER (WHERE action = 'login_success') AS login_ok, "
            "count(*) FILTER (WHERE source = 'suricata') AS ids, "
            "count(*) FILTER (WHERE source = 'qfeeds') AS qfeeds, "
            "count(*) FILTER (WHERE source = 'crowdsec') AS crowdsec, "
            "count(*) FILTER (WHERE source = 'zenarmor' AND coalesce(data->>'security', data->>'security_tags', '') <> '') AS zen "
            "FROM events WHERE src_ip = $1::inet AND ts > now() - make_interval(hours => $2)", ip, hours)
        others = await pool.fetch(
            "SELECT DISTINCT rule FROM alerts WHERE (src_ip = $1::inet OR dst_ip = $1::inet) AND status <> 'closed' "
            "AND NOT (rule = ANY($2::text[])) AND last_seen > now() - make_interval(hours => $3) "
            "AND rule NOT IN ('new_device', 'admin_login', 'config_change', 'port_scan', 'host_sweep', 'attack_chain', 'risk_score')",
            ip, sorted(next((f for f in RULE_FAMILIES if rule in f), {rule})), hours)
    except Exception:  # noqa: BLE001 - invalid IP text etc.
        return {}
    out = dict(row) if row else {}
    out["other_alerts"] = sorted(r["rule"] for r in others)
    return out


def threat_signals(ev: dict[str, Any]) -> list[str]:
    """Independent signs that a host is compromised / malicious (for corroboration)."""
    sig = [f"{ev[k]} {label}" for k, label in (("ids", "Suricata alert(s)"), ("qfeeds", "threat-intel hit(s)"),
                                                 ("zen", "Zenarmor threat event(s)")) if ev.get(k)]
    if ev.get("other_alerts"):
        sig.append("open alerts: " + ", ".join(ev["other_alerts"][:5]))
    return sig


def corroborate(r: Rating, ev: dict[str, Any], max_steps: int = 2) -> Rating:
    sig = threat_signals(ev)
    if sig:
        r.up("also seen by other sources in the last 24h (" + "; ".join(sig) + ")", min(len(sig), max_steps))
    return r


async def blocked_threat_history(src: str, source: str) -> tuple[int, int, int]:
    """(attempts, distinct 10-minute periods, distinct targets) of threat traffic from one device that Zenarmor /
    Q-Feeds blocked in the last 24h; targets are sites (registered domains) or addresses."""
    pool = db.pool()
    if source == "qfeeds":
        r = await pool.fetchrow("SELECT count(*) n, count(DISTINCT date_bin('10 minutes', ts, 'epoch')) p, "
                                "count(DISTINCT dst_ip) t FROM events WHERE source = 'qfeeds' "
                                "AND src_ip = $1::inet AND ts > now() - interval '24 hours'", src)
        return r["n"], r["p"], r["t"]
    rows = await pool.fetch(
        "SELECT domain, host(dst_ip) AS ip, date_bin('10 minutes', ts, 'epoch') AS period, count(*) AS n, "
        "concat_ws(' ', data->>'security', data->>'security_tags', data->'zen'->>'app_category', "
        "data->'zen'->>'web_category') AS cats FROM events "
        "WHERE source = 'zenarmor' AND action = 'block' AND src_ip = $1::inet AND ts > now() - interval '24 hours' "
        "GROUP BY 1, 2, 3, 5", src)
    bad = [r for r in rows if ZEN_BAD.search(r["cats"] or "")]
    return (sum(r["n"] for r in bad), len({r["period"] for r in bad}),
            len({registered_domain(r["domain"]) if r["domain"] else r["ip"] for r in bad}))


def repeated(r: Rating, hits: int, periods: int, targets: int) -> Rating:
    """One step up when a device keeps coming back to blocked threat sites - one visit is usually an ad or a stray link,
    however many retries and subdomains it fires."""
    if periods >= REPEAT_PERIODS or targets >= REPEAT_TARGETS:
        why = f"in {periods} separate 10-minute periods" if periods >= REPEAT_PERIODS else f"to {targets} different sites"
        r.up(f"repeated: blocked threat traffic {why} in the last 24h ({hits} attempt(s), {targets} site(s)) - "
             "can be malware calling home; check which program on the device does it")
    return r


async def alert_ports(filters: dict[str, Any] | None, since: datetime) -> dict[str, Any] | None:
    """The most frequent source / destination ports of the events behind an alert (the same filters and time span its
    Events button uses), for the alert list. Only for alerts tied to an address - the IP index keeps it cheap."""
    if not filters or not any(filters.get(k) for k in ("ip", "src", "dst")):
        return None
    try:
        where, args = event_filter.build({**filters, "start": since.isoformat()})
    except ValueError:
        return None
    r = await db.pool().fetchrow(
        f"WITH ev AS (SELECT src_port, dst_port FROM events WHERE {' AND '.join(where)} ORDER BY ts DESC LIMIT 5000) "
        "SELECT (SELECT array_agg(p ORDER BY n DESC, p) FROM (SELECT src_port p, count(*) n FROM ev WHERE src_port IS NOT NULL "
        "GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 5) a) src, (SELECT count(DISTINCT src_port) FROM ev) src_n, "
        "(SELECT array_agg(p ORDER BY n DESC, p) FROM (SELECT dst_port p, count(*) n FROM ev WHERE dst_port IS NOT NULL "
        "GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 5) b) dst, (SELECT count(DISTINCT dst_port) FROM ev) dst_n", *args)
    if not r or not (r["src_n"] or r["dst_n"]):
        return None
    return {"src": list(r["src"] or []), "src_n": r["src_n"], "dst": list(r["dst"] or []), "dst_n": r["dst_n"],
            "at": datetime.now(timezone.utc).isoformat()}


async def raise_alert(rule: str, severity: str | Rating, title: str, fingerprint: str, description: str = "",
                      src_ip: str | None = None, dst_ip: str | None = None, data: dict | None = None,
                      count: int = 1, mode: str = "add", events: dict[str, Any] | None = None,
                      span: tuple[Any, Any] | None = None, blocked: bool | str = False) -> None:
    """Create an alert or update the matching open one (dedupe by fingerprint within 24h).

    ``severity``: a level, or a Rating whose reasons are added to the description. A Rating of a windowed rule is
    re-evaluated on every run (it covers the last 24 hours), so its level replaces the stored one; plain levels and
    sticky Ratings only raise it.
    ``events``: Event-search filters that show the events behind the alert (default: the source IP);
    the alerts page links to them for the alert's time span. The device name of ``src_ip`` is added.
    ``span``: (first, last) time of the events behind it, when they can lie outside the alert's own time span - events
    pulled from an API carry the time the tool saw them, which can be long before Looking Glass raised the alert.
    ``blocked``: the traffic behind it was blocked (True, or the reason: "Zenarmor blocked it") - never critical then,
    however much confirms it; only your own severity rules (Settings › Alert filters) can still set critical."""
    pool = db.pool()
    data = dict(data or {})
    if blocked:
        reason = blocked if isinstance(blocked, str) else "the traffic was blocked"
        data["blocked"] = True  # attack chains of blocked alerts only are capped too
        if isinstance(severity, Rating):
            severity.cap("high", reason)
        elif severity == "critical":
            severity = "high"
    rated = isinstance(severity, Rating)
    keep_max = not rated or severity.sticky
    if rated:
        data["severity_why"] = severity.why
        description = (description + "\n\n" if description else "") + severity.text()
        severity = severity.severity
    if events is None and (src_ip or dst_ip):
        events = {"ip": src_ip or dst_ip}
    if events:
        data["events"] = {k: v for k, v in events.items() if v not in (None, "")}
    dev = await device_info(src_ip)
    if dev:
        data["device"] = dev
        name = dev.get("hostname")
        if name and name not in title:  # "192.168.1.20" -> "laptop (192.168.1.20)"
            title = re.sub(rf"(?<![\d.:]){re.escape(src_ip)}(?![\d.:])", f"{name} ({src_ip})", title, count=1)
        if dev.get("conn_where") and "Connected to:" not in description:
            # UniFi knows where the device is: say so, and how to cut it off right there
            signal = f", signal {dev['conn_signal']} dBm" if dev.get("conn_signal") else ""
            description = (description + "\n\n" if description else "") + (
                f"Connected to: {dev['conn_where']}{signal} (UniFi). To cut it off quickly: UniFi Network › Client Devices › "
                f"{name or dev.get('mac')} › Block, or an OPNsense firewall rule for {src_ip}.")
    row = await pool.fetchrow(
        "SELECT id, severity, status, data ? 'filter' OR data ? 'auto_closed' AS by_filter, "
        "data->>'events_from' AS ev_from, data->>'events_to' AS ev_to, data->'ports' AS ports, created_at "
        "FROM alerts WHERE fingerprint = $1 "
        "AND last_seen > now() - interval '24 hours' ORDER BY id DESC LIMIT 1", fingerprint)
    if span and all(span):
        # widened over every sighting: the update below replaces data
        # UTC with milliseconds ("...T13:10:34.123Z"): every browser parses it, and it sorts as text
        first, last = (t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"
                       if hasattr(t, "astimezone") else str(t) for t in span)
        data["events_from"] = min(first, row["ev_from"]) if row and row["ev_from"] else first
        data["events_to"] = max(last, row["ev_to"]) if row and row["ev_to"] else last
    # ports of its events (refreshed at most every 10 minutes - the update below replaces data); filters can match them
    old_ports = row["ports"] if row else None
    if old_ports and old_ports.get("at", "") > (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat():
        data["ports"] = old_ports
    else:
        since = min(t for t in (row["created_at"] if row else datetime.now(timezone.utc),
                                datetime.fromisoformat(data["events_from"].replace("Z", "+00:00")) if data.get("events_from") else None)
                    if t is not None) - timedelta(minutes=15)
        if ports := await alert_ports(data.get("events"), since):
            data["ports"] = ports
        elif old_ports:
            data["ports"] = old_ports
    # your own severity rules (Settings › Alert filters › "Change the severity") come first; mute filters see the result
    if ov := await alert_filters.check(rule, severity, title, description, src_ip, dst_ip, kind="severity",
                                    ports=data.get("ports")):
        if ov["set_severity"] != severity:
            label = ov.get("name") or f"filter #{ov['id']}"
            data["severity_override"] = {"from": severity, "to": ov["set_severity"], "filter": {"id": ov["id"], "name": ov.get("name")}}
            data["severity_why"] = list(data.get("severity_why") or []) + [f"→ set to {ov['set_severity']} by your rule “{label}” (was {severity})"]
            description += f"\n\nSeverity set to {ov['set_severity']} by your alert rule “{label}” (was {severity})."
            severity = ov["set_severity"]
            keep_max = False  # your choice replaces the stored level, also downwards
    status = "open"
    if flt := await alert_filters.check(rule, severity, title, description, src_ip, dst_ip, ports=data.get("ports")):
        if flt["action"] == "suppress":
            log.debug("alert '%s' stopped by filter %s", title, flt["id"])
            return
        status = "closed"  # "create as closed": kept for reference, never shown as open
        data["filter"] = {"id": flt["id"], "name": flt.get("name")}
    if row and row["status"] == "closed" and status != "closed":
        # You closed it: it stays closed while it keeps happening (it only collects the new sightings), unless it gets
        # WORSE than when you closed it. After 24 quiet hours it can come back as a new alert. A mute filter that closed
        # it and has since been removed / paused, or closed automatically because the problem went away: back to open.
        worse = SEVERITIES.index(severity) > SEVERITIES.index(row["severity"])
        if not (worse or row["by_filter"]):
            count_sql = "count + $2" if mode == "add" else "GREATEST(count, $2)"
            await pool.execute(f"UPDATE alerts SET last_seen = now(), count = {count_sql} WHERE id = $1", row["id"], count)
            return
        if worse:
            description += (f"\n\nRe-opened: the severity rose from {row['severity']} to {severity} after it was closed.")
        await pool.execute("UPDATE alerts SET status = 'open', close_reason = NULL, data = data - 'filter' - 'auto_closed' WHERE id = $1", row["id"])
        log.info("ALERT re-opened [%s] %s", severity, title)
    if row:
        sev = max(row["severity"], severity, key=SEVERITIES.index) if keep_max else severity
        if blocked and sev == "critical" and "severity_override" not in data:  # stored before the cap existed
            sev = "high"
        count_sql = "count + $2" if mode == "add" else "GREATEST(count, $2)"
        await pool.execute(
            # the title too: it can say what changed ("Zenarmor blocked: …" once the block record arrived)
            f"UPDATE alerts SET last_seen = now(), count = {count_sql}, severity = $3, description = $4, data = $5, "
            f"status = CASE WHEN $6 = 'closed' THEN 'closed' ELSE status END, title = $7 WHERE id = $1",
            row["id"], count, sev, description, data, status, title)
        return
    await pool.execute(
        "INSERT INTO alerts (rule, severity, title, description, src_ip, dst_ip, count, fingerprint, data, status) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        rule, severity, title, description, src_ip, dst_ip, count, fingerprint, data, status)
    log.info("ALERT [%s] %s", severity, title)


def login_target(source: str, host: str | None, programs: Any = None) -> str:
    """Which system a login went to, for titles: "Tower (webGUI)", "UniFi controller", "OPNsense (sshd)"."""
    prog = next((p for p in programs or [] if p), None)
    if source == "unifi":
        return "UniFi controller"
    if source == "vpn":
        return f"VPN ({prog})" if prog else "VPN"
    name = host or "OPNsense"
    return f"{name} ({prog})" if prog and prog != name else name


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def ignored_domain(domain: str, ignore: list[str]) -> bool:
    """``domain`` is one of the ``ignore`` domains or a subdomain of one."""
    d = domain.lower().rstrip(".")
    return any(d == i or d.endswith("." + i) for i in ignore)


def ignore_list(csv: str) -> list[str]:
    return [p.strip().lower().strip(".").removeprefix("*.") for p in (csv or "").replace(";", ",").split(",") if p.strip()]


def dga_like(domain: str) -> bool:
    """<random>.<tld>: a long, high-entropy first label. With hyphens, the longest part counts (echo-prod-3f9a1c.example
    is a named service with an id, not a generated name). Deeper names are covered by the tunneling check."""
    label = domain.split(".")[0]
    if domain.count(".") > 2 or label.startswith("xn--"):
        return False
    part = max(label.split("-"), key=len)
    return len(part) >= 16 and entropy(part) >= 3.6


def registered_domain(domain: str) -> str:
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 3 and len(parts[-2]) <= 3 and len(parts[-1]) == 2:  # co.uk, com.au, ...
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def ipless_key(ip: Any) -> str:
    """Device key for a client without a MAC address (WireGuard peer, a routed network behind another router)."""
    return f"ip:{ip}"


async def track_devices(devices: list[dict[str, Any]], origin: str, mark_online: bool = False) -> None:
    """Upsert devices (from ARP, DHCP leases or DHCP logs) and alert on MAC addresses never seen before.

    ``mark_online``: the list is a complete snapshot of present devices (ARP table) -> others become offline; devices
    without a MAC (``ip:`` keys) are never in the ARP table and keep their state.
    """
    pool = db.pool()
    if mark_online:
        await pool.execute("UPDATE devices SET online = false WHERE online AND NOT (mac = ANY($1::text[])) "
                           "AND mac NOT LIKE 'ip:%'",
                           [d["mac"] for d in devices])
    if not devices:
        return
    first_run = not await pool.fetchval("SELECT EXISTS (SELECT 1 FROM devices)")
    for d in devices:
        d["hostname"] = real_name(d.get("hostname"))
        source = (d.get("name_source") or origin) if d["hostname"] else None
        new = await pool.fetchval(
            "INSERT INTO devices (mac, ip, hostname, vendor, interface, sources, lease_type, lease_expires, online, "
            "name_source, name_rank, conn_type, conn_where, conn_signal, conn_seen) "
            "VALUES ($1, $2, $3, $4, $5, ARRAY[$6::text], $7, $8, $9, $10, $11, $12, $13, $14, "
            "CASE WHEN $12::text IS NOT NULL THEN now() END) "
            "ON CONFLICT (mac) DO UPDATE SET ip = COALESCE(EXCLUDED.ip, devices.ip), "
            "hostname = CASE WHEN EXCLUDED.hostname IS NOT NULL AND EXCLUDED.name_rank >= devices.name_rank "
            "THEN EXCLUDED.hostname ELSE devices.hostname END, "
            "name_source = CASE WHEN EXCLUDED.hostname IS NOT NULL AND EXCLUDED.name_rank >= devices.name_rank "
            "THEN EXCLUDED.name_source ELSE devices.name_source END, "
            "name_rank = GREATEST(devices.name_rank, CASE WHEN EXCLUDED.hostname IS NOT NULL THEN EXCLUDED.name_rank ELSE 0 END), "
            "vendor = COALESCE(EXCLUDED.vendor, devices.vendor), "
            "interface = COALESCE(EXCLUDED.interface, devices.interface), "
            "sources = (SELECT array_agg(DISTINCT s) FROM unnest(devices.sources || EXCLUDED.sources) s), "
            "lease_type = COALESCE(EXCLUDED.lease_type, devices.lease_type), "
            "lease_expires = COALESCE(EXCLUDED.lease_expires, devices.lease_expires), "
            "conn_type = COALESCE(EXCLUDED.conn_type, devices.conn_type), "
            "conn_where = COALESCE(EXCLUDED.conn_where, devices.conn_where), "
            "conn_signal = CASE WHEN EXCLUDED.conn_type IS NOT NULL THEN EXCLUDED.conn_signal ELSE devices.conn_signal END, "
            "conn_seen = COALESCE(EXCLUDED.conn_seen, devices.conn_seen), "
            "online = devices.online OR EXCLUDED.online, last_seen = now() "
            "RETURNING (xmax = 0)", d["mac"], d.get("ip"), d.get("hostname") or None, d.get("vendor") or None,
            d.get("interface") or None, origin, d.get("lease_type"), d.get("lease_expires"), bool(d.get("online")),
            source, name_rank(source) if source else 0, d.get("conn_type"), d.get("conn_where"), d.get("conn_signal"))
        if new and not first_run:
            ipless = d["mac"].startswith("ip:")
            await raise_alert(
                "new_device", Rating("low", ("a client without a MAC address (VPN / WireGuard peer or a routed network) "
                                             "appeared on a new IP" if ipless else
                                             "an unknown MAC address appeared - usually a new phone, guest or randomised "
                                             "Wi-Fi address") + "; mark it trusted on the Devices page when you know it",
                                     sticky=True),
                f"New device on network: {d['mac']} ({d.get('hostname') or d.get('ip') or '?'})",
                f"new_device:{d['mac']}",
                description=f"{'A client without a MAC address' if ipless else 'A MAC address'} never seen before appeared via {origin}: "
                            f"ip={d.get('ip')} hostname={d.get('hostname')} vendor={d.get('vendor')} interface={d.get('interface')}. "
                            "Verify it is a known device (intruder / rogue device check) and mark it trusted on the Devices page.",
                src_ip=d.get("ip"), data={k: v for k, v in d.items() if v is not None})


_zen_seen: dict[str, tuple[float, bool]] = {}  # MAC -> (when, had a name)


def zen_device_name(d: dict[str, Any], ip: Any) -> str | None:
    """The name Zenarmor knows for a client: the host name it learned (DHCP / DNS), else the name of its device entry
    (Zenarmor › Devices). Not an IP address, nor a bare fingerprint label that only repeats the OS / vendor / type."""
    dev = d.get("device") if isinstance(d.get("device"), dict) else {}
    generic = {str(dev.get(k) or "").strip().lower() for k in ("os", "vendor", "category")} - {""}
    for name in (d.get("src_hostname"), dev.get("name")):
        name = real_name(name)
        if not name or name == str(ip or "") or name.lower() in generic:
            continue
        try:
            ipaddress.ip_address(name)
            continue
        except ValueError:
            return name
    return None


def real_mac(value: Any) -> str | None:
    """A device's MAC address ("AA-BB-.." -> "aa:bb:.."), or None for a missing one and the placeholders a tunnel
    client (WireGuard) gets instead: 00:00:00:00:00:00, ff:ff:ff:ff:ff:ff, a multicast address, "-", "unknown"."""
    mac = str(value or "").strip().lower().replace("-", ":")
    if not re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", mac) or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") \
            or int(mac[:2], 16) & 1:
        return None
    return mac


async def zenarmor_device_listener(events: list[dict[str, Any]]) -> None:
    """Zenarmor records carry the client MAC, hostname and a device fingerprint (name/vendor/OS). A MAC is looked at
    again after 10 minutes - right away while no record of it carried a name yet. A client without a MAC (WireGuard
    peer, routed network) is kept under its IP (``ip:`` key), unless a device with a MAC already has that IP."""
    now = time.time()
    found: dict[str, dict[str, Any]] = {}
    for e in events:
        d = e.get("data") if e.get("source") == "zenarmor" else None
        if not isinstance(d, dict):
            continue
        # a tunnel interface (WireGuard wg0, OpenVPN ovpns1 / tun0) carries no client MAC, whatever the record says
        tunnel = re.match(r"(wg|tun|ovpn|ipsec|enc)\d", str(d.get("interface") or "").lower())
        mac = None if tunnel else real_mac(d.get("src_hwaddr"))
        if not mac:
            if not e.get("src_ip") or not is_internal_ip(e["src_ip"]):
                continue
            mac = ipless_key(e["src_ip"])
        if mac in found and found[mac]["hostname"]:
            continue
        name = zen_device_name(d, e.get("src_ip"))
        when, named = _zen_seen.get(mac, (0, False))
        if now - when < 600 and (named or not name):
            continue
        dev = d.get("device") if isinstance(d.get("device"), dict) else {}
        vendor = " / ".join(x for x in (dev.get("vendor"), dev.get("os")) if x) or None
        found[mac] = {"mac": mac, "ip": e.get("src_ip"), "hostname": name, "vendor": vendor,
                      "interface": d.get("interface"), "online": True}
    ipless = [str(dev["ip"]) for key, dev in found.items() if key.startswith("ip:")]
    if ipless:
        taken = {r["ip"] for r in await db.pool().fetch(
            # a device with a MAC known from ARP / DHCP / UniFi; one only Zenarmor reported may be a tunnel client
            # merged under a bogus MAC by an older version
            "SELECT DISTINCT host(ip) ip FROM devices WHERE ip = ANY($1::inet[]) AND mac NOT LIKE 'ip:%' "
            "AND NOT (sources <@ ARRAY['zenarmor'])", ipless)}
        found = {k: v for k, v in found.items() if not (k.startswith("ip:") and str(v["ip"]) in taken)}
    for mac, dev in found.items():
        _zen_seen[mac] = (now, bool(dev["hostname"]))
    await track_devices(list(found.values()), origin="zenarmor")


async def dhcp_listener(events: list[dict[str, Any]]) -> None:
    devices = [{"mac": e["data"]["mac"], "ip": e.get("dst_ip"), "hostname": e["data"].get("hostname")}
               for e in events if e.get("source") == "dhcp" and isinstance(e.get("data"), dict) and e["data"].get("mac")]
    await track_devices(devices, origin="dhcp")


class DetectionEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._last_events_at = time.time()
        self._ran: dict[str, float] = {}
        from .behavior import Behavior  # local imports: those modules use the helpers of this one
        from .intel import Intel
        self.behavior = Behavior(settings, self.internal)
        self.intel = Intel(settings)

    async def run(self) -> None:
        await asyncio.sleep(20)
        while True:
            started = time.monotonic()
            for rule in (self.port_scan, self.host_sweep, self.brute_force, self.success_after_failures,
                         self.external_admin_login, self.web_attacks, self.web_scanner, self.ids_alerts,
                         self.crowdsec_alerts, self.qfeeds_hits, self.zenarmor_threats, self.dns_anomalies,
                         self.internal_blocked_outbound, self.suspicious_outbound_ports, self.config_changes,
                         self.password_spray, self.distributed_brute_force, self.login_location, self.dns_bypass,
                         self.beaconing, self.lateral_movement, self.large_upload,
                         self.threat_intel, self.canary, self.arp_spoofing, self.young_domains,
                         self.behavior_profiles, self.behavior_hourly, self.behavior_cleanup,
                         self.system_health, self.log_silence, self.attack_chains, self.risk_scores):
                try:
                    await rule()
                except Exception:  # noqa: BLE001
                    log.exception("detection rule %s failed", rule.__name__)
            elapsed = time.monotonic() - started
            await asyncio.sleep(max(5, self.settings.detection_interval - elapsed))  # live setting

    # -------------------------------------------------------- helpers ---
    async def _watermark(self, rule: str) -> tuple[int, int]:
        """Return (last processed event id, current max id) for incremental rules."""
        pool = db.pool()
        current = await pool.fetchval("SELECT COALESCE(max(id), 0) FROM events")
        last = await db.kv_get(f"wm:{rule}")
        if last is None:
            last = await pool.fetchval("SELECT COALESCE(min(id), 1) - 1 FROM events WHERE ts > now() - interval '1 hour'") or 0
            last = min(last, current)
        return int(last), int(current)

    async def _commit(self, rule: str, current: int) -> None:
        await db.kv_set(f"wm:{rule}", current)

    def internal(self, ip: Any) -> bool:
        return is_internal_ip(ip, parse_networks(self.settings.internal_networks))

    # ----------------------------------------------------- network rules ---
    async def port_scan(self) -> None:
        rows = await db.pool().fetch(
            "SELECT src_ip, count(DISTINCT dst_port) AS ports, count(DISTINCT dst_ip) AS hosts, count(*) AS hits, "
            "array_agg(DISTINCT dst_port ORDER BY dst_port) FILTER (WHERE dst_port IS NOT NULL) AS port_list "
            "FROM events WHERE source = 'firewall' AND action = 'block' AND ts > now() - interval '10 minutes' "
            "AND src_ip IS NOT NULL GROUP BY src_ip HAVING count(DISTINCT dst_port) >= 15")
        for r in rows:
            ip = str(r["src_ip"])
            internal = self.internal(ip)
            if not (sev := await self.rate_scan(ip, internal, "port_scan")):
                continue
            await raise_alert(
                "port_scan", sev, f"{'Internal' if internal else 'External'} port scan from {ip} ({r['ports']} ports)",
                f"port_scan:{ip}", src_ip=ip, events={"source": "firewall", "ip": ip, "action": "block"}, count=r["hits"], mode="max",
                blocked="the firewall blocked the scanned ports",
                description=f"{ip} hit {r['ports']} distinct blocked ports on {r['hosts']} host(s) in 10 minutes "
                            f"({r['hits']} packets). Sample ports: {list(r['port_list'] or [])[:30]}."
                            + (" Source is INTERNAL - possible compromised host / lateral movement." if internal else ""),
                data={"ports": r["ports"], "hosts": r["hosts"], "hits": r["hits"]})

    async def host_sweep(self) -> None:
        rows = await db.pool().fetch(
            "SELECT src_ip, dst_port, count(DISTINCT dst_ip) AS hosts, count(*) AS hits FROM events "
            "WHERE source = 'firewall' AND action = 'block' AND ts > now() - interval '10 minutes' AND src_ip IS NOT NULL "
            "GROUP BY src_ip, dst_port HAVING count(DISTINCT dst_ip) >= 10")
        for r in rows:
            ip = str(r["src_ip"])
            if not (sev := await self.rate_scan(ip, self.internal(ip), "host_sweep")):
                continue
            await raise_alert(
                "host_sweep", sev,
                f"Host sweep from {ip} on port {r['dst_port']} ({r['hosts']} hosts)", f"host_sweep:{ip}:{r['dst_port']}", events={"source": "firewall", "ip": ip, "port": r["dst_port"]},
                src_ip=ip, count=r["hits"], mode="max", blocked="the firewall blocked the sweep",
                description=f"{ip} tried port {r['dst_port']} on {r['hosts']} different hosts within 10 minutes.")

    async def rate_scan(self, ip: str, internal: bool, rule: str) -> Rating | None:
        """Scans and sweeps: the number of ports / hosts does not matter, what got through and who scans does.
        None = no alert: a blocked scan from the internet is background noise every public IP gets, unless the scanner
        also logged in or got successful answers from an attack on your web server."""
        ev = await evidence(ip, rule)
        if internal:
            # a device inside scanning the network: compromised host, malware spreading, or an admin tool / NAS scanner
            return corroborate(Rating("medium", "scan from INSIDE the network (compromised device, or a scanner tool)"), ev)
        r = Rating("low", "scan from the internet - background noise every public IP gets")
        if ev.get("fw_pass"):
            # an open port (port forward / hosted service) lets every scanner in - that alone is not an escalation
            r.note(f"{ev['fw_pass']} connection(s) from this IP reached an open port in the last 24h (normal for a hosted "
                   "service)")
        if ev.get("login_ok"):
            r.up("and it LOGGED IN successfully", 2)
        elif "web_attack" in ev.get("other_alerts", []) and ev.get("web_ok"):
            r.up("and it also attacked your web server and got successful responses")
        else:
            return None
        return r

    async def internal_blocked_outbound(self) -> None:
        rows = await db.pool().fetch(
            "SELECT src_ip, count(*) AS hits, count(DISTINCT dst_ip) AS dsts, "
            "array_agg(DISTINCT dst_port) FILTER (WHERE dst_port IS NOT NULL) AS ports FROM events "
            "WHERE source = 'firewall' AND action = 'block' AND ts > now() - interval '10 minutes' "
            "AND src_ip IS NOT NULL AND dst_ip IS NOT NULL GROUP BY src_ip HAVING count(DISTINCT dst_ip) >= 25")
        for r in rows:
            ip = str(r["src_ip"])
            if not self.internal(ip):
                continue
            rating = corroborate(Rating("low", "outbound traffic that the firewall blocked - often a policy or a "
                                                "misconfigured device, sometimes malware beaconing"), await evidence(ip, "internal_blocked_outbound"))
            await raise_alert(
                "internal_blocked_outbound", rating, f"Internal host {ip} blocked towards {r['dsts']} destinations",
                f"int_blocked:{ip}", src_ip=ip, events={"source": "firewall", "ip": ip, "action": "block"}, count=r["hits"], mode="max",
                blocked="the firewall blocked it", description=f"Internal host {ip} was blocked {r['hits']} times towards {r['dsts']} destinations in 10 "
                            f"minutes (ports {list(r['ports'] or [])[:20]}). Could be malware beaconing, a misconfigured "
                            "device or a blocked policy.")

    async def suspicious_outbound_ports(self) -> None:
        last, current = await self._watermark("susp_ports")
        rows = await db.pool().fetch(
            f"SELECT src_ip, dst_ip, dst_port, count(*) AS hits, {ALLOWED_AGG} AS passed, {FW_BLOCKED_AGG} AS fw_blocked, "
            f"{FW_RULE_AGG} AS fw_rule FROM events WHERE id > $1 AND id <= $2 "
            "AND source IN ('firewall', 'zenarmor') AND dst_port = ANY($3::int[]) AND src_ip IS NOT NULL "
            "GROUP BY src_ip, dst_ip, dst_port", last, current, list(SUSPICIOUS_OUT_PORTS))
        for r in rows:
            src, dst = str(r["src_ip"]), str(r["dst_ip"])
            if not self.internal(src) or self.internal(dst):
                continue
            passed = r["passed"]
            how = verdict(passed, r["fw_blocked"], r["fw_rule"])
            rating = Rating("medium", "the connection was ALLOWED out") if passed else \
                Rating("low", f"the connection was {how}")
            rating.sticky = True
            corroborate(rating, await evidence(src, "suspicious_outbound_port"))
            await raise_alert(
                "suspicious_outbound_port", rating,
                f"{src} → {dst}:{r['dst_port']} ({SUSPICIOUS_OUT_PORTS[r['dst_port']]}) {'ALLOWED' if passed else 'blocked'}",
                f"susp_port:{src}:{r['dst_port']}", src_ip=src, events={"source": "firewall", "ip": src, "port": r["dst_port"]}, dst_ip=dst, count=r["hits"],
                blocked=not passed and f"the connection was {how}",
                description=f"Internal host {src} connected to external {dst} on port {r['dst_port']} "
                            f"({SUSPICIOUS_OUT_PORTS[r['dst_port']]}): {how}.")
        await self._commit("susp_ports", current)

    # -------------------------------------------------------- auth rules ---
    async def brute_force(self) -> None:
        rows = await db.pool().fetch(
            "SELECT src_ip, source, coalesce(host, '') AS host, count(*) AS hits, "
            "array_agg(DISTINCT username) FILTER (WHERE username IS NOT NULL) AS users, "
            "array_agg(DISTINCT program) FILTER (WHERE program IS NOT NULL) AS programs "
            "FROM events WHERE action = 'login_failed' AND ts > now() - interval '15 minutes' AND src_ip IS NOT NULL "
            "GROUP BY src_ip, source, coalesce(host, '') HAVING count(*) >= 5")
        for r in rows:
            ip = str(r["src_ip"])
            if self.internal(ip):
                rating = corroborate(Rating("high", "password guessing from INSIDE the network"), await evidence(ip, "brute_force"), 1)
            else:
                # failed attempts from the internet: annoying but harmless - unless one succeeds (separate critical alert)
                rating = Rating("medium", "failed password guessing from the internet - nothing got in, but the service is "
                                          "reachable from outside")
            target = login_target(r["source"], r["host"], r["programs"])
            await raise_alert(
                "brute_force", rating, f"Brute force against {target} from {ip} ({r['hits']} failures)",
                f"brute_force:{r['source']}:{r['host']}:{ip}", src_ip=ip, events={"source": r["source"], "ip": ip, "action": "login_failed"}, count=r["hits"], mode="max",
                description=f"{r['hits']} failed logins from {ip} in 15 minutes. Usernames tried: {list(r['users'] or [])[:20]}.")

    async def success_after_failures(self) -> None:
        rows = await db.pool().fetch(
            "SELECT s.src_ip, s.username, s.source, s.host, s.program, max(s.ts) AS ts, (SELECT count(*) FROM events f "
            "WHERE f.action = 'login_failed' AND f.src_ip = s.src_ip AND f.ts BETWEEN s.ts - interval '1 hour' AND s.ts) AS failures "
            "FROM events s WHERE s.action = 'login_success' AND s.ts > now() - interval '10 minutes' AND s.src_ip IS NOT NULL "
            "GROUP BY s.src_ip, s.username, s.source, s.host, s.program, s.ts")
        for r in rows:
            if r["failures"] >= 3:
                ip = str(r["src_ip"])
                if not self.internal(ip):
                    rating = Rating("critical", "a login from the INTERNET succeeded after failed attempts - possible "
                                                "guessed password")
                elif r["failures"] >= 5:
                    rating = Rating("high", f"{r['failures']} failures before success from inside - more than typos")
                else:
                    rating = Rating("medium", "from inside the network with few failures - often just mistyped passwords")
                rating.sticky = True
                await raise_alert(
                    "success_after_failures", rating,
                    f"Successful login to {login_target(r['source'], r['host'], [r['program']])} for '{r['username']}' "
                    f"from {ip} after {r['failures']} failures",
                    f"succ_after_fail:{ip}:{r['username']}", src_ip=ip, events={"ip": ip, "action": "login_failed,login_success"}, mode="max",
                    description="A login succeeded right after a series of failures - possible password guessing success. "
                                "Verify this login was legitimate.")

    async def external_admin_login(self) -> None:
        last, current = await self._watermark("ext_login")
        rows = await db.pool().fetch(
            "SELECT src_ip, username, source, program, host, count(*) AS n FROM events WHERE id > $1 AND id <= $2 "
            "AND action = 'login_success' AND src_ip IS NOT NULL GROUP BY 1, 2, 3, 4, 5", last, current)
        for r in rows:
            ip = str(r["src_ip"])
            internal = self.internal(ip)
            vpn = r["source"] == "vpn"
            if internal:
                rating = Rating("info", "login from inside the network")
            elif vpn:
                rating = Rating("low", "VPN users log in from the internet by design")
            else:
                rating = Rating("high", "an admin interface (web GUI / SSH / API) accepted a login from the INTERNET - it "
                                        "should normally only be reachable from inside or through the VPN")
            rating.sticky = True
            target = login_target(r["source"], r["host"], [r["program"]])
            await raise_alert(
                "admin_login", rating,
                f"{'Login' if internal or vpn else 'Login from EXTERNAL address'} to {target}: '{r['username']}' from {ip}",
                f"login:{r['host'] or r['source']}:{ip}:{r['username']}", src_ip=ip, events={"ip": ip, "action": "login_success"},
                count=r["n"], description=("VPN login." if vpn else f"Administrative login to {target}.") +
                                          ("" if internal else " The source is a public IP address."))
        await self._commit("ext_login", current)

    async def config_changes(self) -> None:
        last, current = await self._watermark("config")
        rows = await db.pool().fetch(
            "SELECT host, program, message, ts, username, host(src_ip) ip, data->'config' cfg FROM events "
            "WHERE id > $1 AND id <= $2 AND action = 'config_change' LIMIT 50", last, current)
        for r in rows:
            cfg = r["cfg"] or {}
            where = r["host"] or "firewall"
            if not cfg:  # a log line without the OPNsense audit details
                configd = (r["program"] or "").lower().startswith("configd")
                # every OPNsense save also makes configd log "[uuid] trigger config changed event" - nothing in it says
                # what or who; the audit line of the same save does, and makes its own alert
                if configd and await db.pool().fetchval(
                        "SELECT 1 FROM events WHERE action = 'config_change' AND data ? 'config' AND host IS NOT DISTINCT "
                        "FROM $1 AND ts BETWEEN $2::timestamptz - interval '2 minutes' "
                        "AND $2::timestamptz + interval '2 minutes' LIMIT 1",
                        r["host"], r["ts"]):
                    continue
                hint = ("\n\nThis line from OPNsense's configd does not say what was changed or by whom - that is in "
                        "OPNsense's audit log line of the same save, which did not arrive. OPNsense › System › Settings › "
                        "Logging › Remote: edit the Looking Glass destination and leave Applications empty (or include "
                        "'audit'). Until then: System › Configuration › History shows the change.") if configd else ""
                await raise_alert("config_change", "info", f"Configuration change on {where}", f"config:{r['host']}",
                                  events={"action": "config_change", "host": r["host"]},
                                  description=r["message"][:1000] + hint)
                continue
            # what was changed and by whom go in the title, so an alert filter can match them ("Nginx", "admin", …)
            who = (f" by {r['username']}" if r["username"] else "") + (f" (as {cfg['by']})" if cfg.get("by") else "") + \
                  (f" from {r['ip']}" if r["ip"] else "")
            part = cfg.get("label") or cfg.get("area") or "?"
            await raise_alert(
                "config_change", "info", f"Configuration change on {where}: {part}{who}",
                f"config:{r['host']}:{cfg.get('area')}:{r['username']}", src_ip=r["ip"],
                events={"action": "config_change", "host": r["host"], **({"user": r["username"]} if r["username"] else {})},
                data={"config": cfg},
                description=f"Changed: {part}{' › ' + cfg['detail'] if cfg.get('detail') else ''} (via {cfg.get('path')}). "
                            f"Changed by: {r['username'] or 'the system (no user)'}{' from ' + r['ip'] if r['ip'] else ''}. "
                            f"Each save is a backup in System › Configuration › History, where you can compare it with the "
                            f"previous version. Log line: {r['message'][:600]}")
        await self._commit("config", current)

    # --------------------------------------------------------- web rules ---
    async def web_attacks(self) -> None:
        last, current = await self._watermark("web_attacks")
        rows = await db.pool().fetch(
            "SELECT src_ip, tag, count(*) AS hits, array_agg(DISTINCT message) AS samples, "
            "count(*) FILTER (WHERE action ~ '^http_[23]') AS ok_hits FROM ("
            "  SELECT src_ip, message, action, jsonb_array_elements_text(data->'tags') AS tag FROM events "
            "  WHERE id > $1 AND id <= $2 AND source = 'nginx' AND jsonb_typeof(data->'tags') = 'array' "
            "  AND jsonb_array_length(data->'tags') > 0) t GROUP BY src_ip, tag", last, current)
        for r in rows:
            ip = str(r["src_ip"]) if r["src_ip"] else "unknown"
            if r["tag"] in ("rce", "sqli"):
                rating = Rating("medium", f"{r['tag']} attempt")
            elif r["tag"] in ("path_traversal", "sensitive_file", "xss"):
                rating = Rating("low", f"{r['tag'].replace('_', ' ')} probe")
            else:
                rating = Rating("info", f"{r['tag'].replace('_', ' ')} - typical internet scanner traffic")
            rating.sticky = True
            if r["ok_hits"]:
                rating.up(f"{r['ok_hits']} of these requests got a SUCCESSFUL response (2xx/3xx) - check whether it worked")
            elif rating.severity != "info":
                rating.why.append("every request failed (4xx/5xx)")
            if r["src_ip"] and self.internal(ip):
                rating.up("the attacker is INSIDE the network")
            await raise_alert(
                "web_attack", rating, f"Web attack ({r['tag']}) from {ip} on nginx", f"web:{ip}:{r['tag']}", src_ip=r["src_ip"] and ip, events={"source": "nginx", "ip": r["src_ip"] and ip},
                count=r["hits"], description=f"{r['hits']} request(s) matching '{r['tag']}'. Samples: {list(r['samples'])[:5]}")
        await self._commit("web_attacks", current)

    async def web_scanner(self) -> None:
        rows = await db.pool().fetch(
            "SELECT src_ip, count(*) AS hits, count(DISTINCT data->>'path') AS paths FROM events "
            "WHERE source = 'nginx' AND ts > now() - interval '10 minutes' AND action ~ '^http_4' AND src_ip IS NOT NULL "
            "GROUP BY src_ip HAVING count(*) >= 50")
        for r in rows:
            ip = str(r["src_ip"])
            rating = Rating("medium", "web scanning from INSIDE the network") if self.internal(ip) else \
                Rating("low", "directory / vulnerability scanning from the internet that only got errors - background noise")
            await raise_alert("web_scanner", rating, f"Web scanning from {ip} ({r['hits']} 4xx responses)",
                              f"web_scan:{ip}", src_ip=ip, events={"source": "nginx", "ip": ip, "action": "http_4*"}, count=r["hits"], mode="max",
                              description=f"{ip} produced {r['hits']} client errors over {r['paths']} distinct paths in 10 minutes "
                                          "(directory brute forcing / vulnerability scanning).")

    # -------------------------------------------------- 3rd party sources ---
    async def ids_alerts(self) -> None:
        last, current = await self._watermark("ids")
        rows = await db.pool().fetch(
            "SELECT src_ip, dst_ip, message, min(severity) AS sev, count(*) AS hits, max(data->>'classification') AS cls, "
            "min(ts) AS first, max(ts) AS last, "
            "bool_and(action IN ('drop', 'blocked')) AS all_blocked "
            "FROM events WHERE id > $1 AND id <= $2 AND source = 'suricata' AND action IS NOT NULL "
            "GROUP BY src_ip, dst_ip, message", last, current)
        for r in rows:
            base = {0: "critical", 1: "critical", 2: "high", 3: "medium", 4: "low"}.get(r["sev"], "low")
            rating = Rating(base, f"Suricata rates this signature {'priority 1' if base == 'critical' else base}", sticky=True)
            src = str(r["src_ip"]) if r["src_ip"] else None
            if r["all_blocked"]:
                rating.down("Suricata (IPS mode) dropped it")
            if src and self.internal(src) and not (r["dst_ip"] and self.internal(str(r["dst_ip"]))):
                ev = await evidence(src, "ids")
                ev["ids"] = 0  # that is this alert
                corroborate(rating, ev, 1)
            await raise_alert("ids", rating, f"Suricata: {r['message']}", f"ids:{r['src_ip']}:{r['message']}",
                              events={"source": "suricata", "ip": str(r["src_ip"]) if r["src_ip"] else None, "q": r["message"][:80]},
                              src_ip=str(r["src_ip"]) if r["src_ip"] else None, dst_ip=str(r["dst_ip"]) if r["dst_ip"] else None,
                              count=r["hits"], span=(r["first"], r["last"]), blocked=r["all_blocked"] and "Suricata dropped it",
                              description=f"Suricata signature '{r['message']}' ({r['cls'] or 'n/a'}) "
                                                           f"{r['src_ip']} -> {r['dst_ip']}, {r['hits']} hit(s).")
        await self._commit("ids", current)

    async def crowdsec_alerts(self) -> None:
        last, current = await self._watermark("crowdsec")
        rows = await db.pool().fetch(
            "SELECT src_ip, coalesce(data->>'scenario', data->>'reason', 'unknown') AS scenario, count(*) AS hits, "
            "min(ts) AS first, max(ts) AS last "
            "FROM events WHERE id > $1 AND id <= $2 AND source = 'crowdsec' AND action IN ('alert', 'ban', 'captcha') "
            "GROUP BY 1, 2", last, current)
        for r in rows:
            ip = str(r["src_ip"]) if r["src_ip"] else None
            internal = self.internal(ip) if ip else False
            rating = Rating("high", "behaviour detected from INSIDE the network", sticky=True) if internal else \
                Rating("low", "CrowdSec detected it and handles it (ban / captcha) - working as intended", sticky=True)
            await raise_alert("crowdsec", rating,
                              f"CrowdSec: {r['scenario']} from {ip}{' (INTERNAL)' if internal else ''}",
                              f"crowdsec:{ip}:{r['scenario']}", src_ip=ip, events={"source": "crowdsec", "ip": ip}, count=r["hits"],
                              span=(r["first"], r["last"]),
                              description=f"CrowdSec detected behaviour '{r['scenario']}' from {ip}.")
        await self._commit("crowdsec", current)

    async def qfeeds_hits(self) -> None:
        last, current = await self._watermark("qfeeds")
        rows = await db.pool().fetch(
            "SELECT src_ip, dst_ip, dst_port, count(*) AS hits, min(ts) AS first, max(ts) AS last FROM events "
            "WHERE id > $1 AND id <= $2 AND source = 'qfeeds' "
            "GROUP BY 1, 2, 3", last, current)
        inbound: dict[str, int] = defaultdict(int)
        spans: dict[str, tuple[Any, Any]] = {}
        for r in rows:
            src, dst = (str(r["src_ip"]) if r["src_ip"] else None), (str(r["dst_ip"]) if r["dst_ip"] else None)
            if src and self.internal(src):
                # blocked: Q-Feeds did its job - only repeated attempts or other signs make the device suspicious
                rating = Rating("low", "a device inside contacted a known malicious address, blocked by Q-Feeds - "
                                       "working as intended", sticky=True)
                ev = await evidence(src, "threat_intel_outbound")
                ev["qfeeds"] = 0  # that is this alert
                corroborate(rating, ev, 2)
                repeated(rating, *await blocked_threat_history(src, "qfeeds"))
                await raise_alert(
                    "threat_intel_outbound", rating, f"Internal host {src} contacted threat-intel listed IP {dst}",
                    f"qf_out:{src}:{dst}", src_ip=src, events={"source": "qfeeds", "ip": src}, dst_ip=dst, count=r["hits"],
                    span=(r["first"], r["last"]), blocked="Q-Feeds blocked it",
                    description=f"Q-Feeds blocked traffic from internal {src} to known malicious {dst}:{r['dst_port']}. "
                                "A single attempt is usually a web page or ad; repeated attempts or other alerts for "
                                "this device point to malware (C2 beacon) - then investigate it.")
            elif src:
                inbound[src] += r["hits"]
                f, t = spans.get(src, (r["first"], r["last"]))
                spans[src] = (min(f, r["first"]), max(t, r["last"]))
        for src, hits in inbound.items():
            if hits >= 20:
                await raise_alert("threat_intel_inbound", Rating("info", "known-bad internet address probing you, already "
                                                                         "blocked by Q-Feeds", sticky=True),
                                  f"Threat-intel listed IP {src} is probing you",
                                  f"qf_in:{src}", src_ip=src, events={"source": "qfeeds", "ip": src}, count=hits,
                                  span=spans.get(src), blocked="Q-Feeds blocked it", description=f"{hits} connection attempts from {src} (Q-Feeds listed) were blocked.")
        await self._commit("qfeeds", current)

    async def zenarmor_threats(self) -> None:
        last, current = await self._watermark("zenarmor")
        mode = self.settings.zenarmor_blocked_alerts  # Settings › Zenarmor
        rows = await db.pool().fetch(
            "SELECT src_ip, coalesce(domain, host(dst_ip)) AS target, coalesce(data->>'security', data->>'security_tags', '') AS threat, "
            "bool_or(action = 'block') AS blocked, count(*) AS hits, max(data->'zen'->>'app') app, "
            "max(data->'zen'->>'app_category') app_category, max(data->'zen'->>'web_category') web_category, "
            "max(data->'zen'->>'policy') policy "
            "FROM events WHERE id > $1 AND id <= $2 AND source = 'zenarmor' "
            "AND (data->>'family' = 'alert' OR coalesce(data->>'security', data->>'security_tags', '') <> '' "
            "     OR action = 'block') "  # blocked by category / policy: judged below (setting)
            "GROUP BY 1, 2, 3", last, current)
        for r in rows:
            what = zen_describe({k: r[k] for k in ("app", "app_category", "web_category", "policy") if r[k]})
            threat = r["threat"] or r["app_category"] or r["web_category"] or r["app"] or "threat alert"
            src = str(r["src_ip"]) if r["src_ip"] else None
            fingerprint = f"zen:{src}:{r['target']}"
            # Zenarmor writes a threat as an "alert" record (without the blocked flag) and the blocked DNS / TLS / flow
            # record, which can arrive in different batches: judge "blocked" on all records of this device and target in
            # the last 24h. NOT blocked = no block at all, or flagged DNS / TLS / flow records that got through.
            seen = await db.pool().fetchrow(
                "SELECT bool_or(action = 'block') AS blocked, bool_or(action <> 'block' AND coalesce(data->>'family', '') <> 'alert' "
                "AND coalesce(data->>'security', data->>'security_tags', '') <> '') AS passed FROM events "
                "WHERE source = 'zenarmor' AND src_ip IS NOT DISTINCT FROM $1::inet AND coalesce(domain, host(dst_ip)) = $2 "
                "AND ts > now() - interval '24 hours'", src, r["target"])
            blocked = bool(r["blocked"] or seen["blocked"]) and not seen["passed"]
            partly = bool(r["blocked"] or seen["blocked"]) and bool(seen["passed"])
            # only Zenarmor's own verdict / categories, never the app name ("Amazon EC2" is no C2 server)
            bad = bool(ZEN_BAD.search(" ".join(x for x in (r["threat"], r["app_category"], r["web_category"]) if x)))
            if blocked and (mode == "never" or (mode == "threats" and not bad)) and not await db.pool().fetchval(
                    "SELECT 1 FROM alerts WHERE fingerprint = $1 AND status <> 'closed' "
                    "AND last_seen > now() - interval '24 hours'", fingerprint):
                continue  # blocked by policy (or all blocks, if chosen): Zenarmor did its job, nothing to look into
            # not sticky: re-rated from the 24h verdict, so an alert raised before the block record arrived drops back
            got = "some of it was NOT blocked" if partly else "was NOT blocked"
            if bad:
                # blocked: Zenarmor did its job - only repeated attempts or other signs make the device suspicious
                rating = Rating("low", f"'{threat[:40]}' traffic from this device, blocked by Zenarmor - working as "
                                       "intended") if blocked else \
                    Rating("critical", f"'{threat[:40]}' traffic from this device {got}")
            else:
                rating = Rating("low", "flagged and blocked by Zenarmor") if blocked else \
                    Rating("medium", f"flagged by Zenarmor, {got}")
            if src and self.internal(src):
                ev = await evidence(src, "zenarmor_threat")
                ev["zen"] = 0  # that is this alert
                corroborate(rating, ev, 2 if bad and blocked else 1)
                if bad and blocked:
                    repeated(rating, *await blocked_threat_history(src, "zenarmor"))
            label = threat if not r["app"] or r["app"] in threat else f"{r['app']}, {threat}"
            state = "blocked" if blocked else "partly blocked" if partly else "NOT blocked"
            await raise_alert("zenarmor_threat", rating,
                              f"Zenarmor{' blocked' if blocked else ''}: {src} → {r['target']} ({label[:60]})",
                              fingerprint, src_ip=src, events={"source": "zenarmor", "ip": src}, count=r["hits"],
                              blocked=blocked and "Zenarmor blocked it",
                              data={k: r[k] for k in ("app", "app_category", "web_category", "policy") if r[k]},
                              description=f"Zenarmor flagged traffic from {src} to {r['target']} as '{threat}' ({state})."
                                          + (f" Details: {what}." if what else "")
                                          + (f" Blocked by Zenarmor policy {r['policy']} (Zenarmor › Policies) - change the "
                                             "policy there if this traffic should be allowed." if blocked and r["policy"] else ""))
        await self._commit("zenarmor", current)

    # --------------------------------------------------------- DNS rules ---
    async def dns_anomalies(self) -> None:
        rows = await db.pool().fetch(
            "SELECT src_ip, domain, action, data->>'rcode' AS rcode, coalesce(data->>'blocklist', '') || ' ' || coalesce(data->>'category', '') AS bl "
            "FROM events WHERE source = 'unbound' AND ts > now() - interval '10 minutes' AND domain IS NOT NULL LIMIT 200000")
        per_client_sub: dict[tuple[str, str], set[str]] = defaultdict(set)
        dga: dict[str, set[str]] = defaultdict(set)
        nx: Counter = Counter()
        nx_domains: dict[str, Counter] = defaultdict(Counter)
        bad_block: dict[str, set[str]] = defaultdict(set)
        ignore = ignore_list(self.settings.dns_ignore_domains)  # Settings › Data & detection
        for r in rows:
            client = str(r["src_ip"]) if r["src_ip"] else "?"
            domain = r["domain"]
            if ignore and ignored_domain(domain, ignore):
                continue
            reg = registered_domain(domain)
            sub = domain[: -len(reg)].rstrip(".") if domain.endswith(reg) else ""
            if sub:
                per_client_sub[(client, reg)].add(sub)
            if dga_like(domain):
                dga[client].add(domain)
            if (r["rcode"] or "").upper() == "NXDOMAIN" or r["action"] == "nxdomain":
                nx[client] += 1
                nx_domains[client][domain] += 1
            if r["action"] in ("block", "drop") and any(w in (r["bl"] or "").lower() for w in ("malware", "phish", "threat", "crypto", "ransom", "botnet", "c2", "abuse", "qfeed", "q-feed")):
                bad_block[client].add(domain)
        no_client = ("The DNS log lines carry no client IP, so the device can't be named. Unbound query logging via "
                     "Reporting › Settings › Unbound DNS statistics (API) or Services › Unbound DNS › Advanced › "
                     "Log queries (syslog) includes it.")

        async def name(client: str) -> tuple[str | None, str]:
            ip = client if client != "?" else None
            return ip, who(ip, await device_info(ip))

        for (client, reg), subs in per_client_sub.items():
            long_subs = [s for s in subs if len(s) > 30]
            if len(subs) >= 150 and len(long_subs) >= 50:
                ip, label = await name(client)
                rating = corroborate(Rating("high", "data hidden in DNS names (tunneling / exfiltration) - few legitimate apps do this"),
                                     await evidence(ip, "dns_tunnel"), 1)
                await raise_alert("dns_tunnel", rating, f"Possible DNS tunneling: {label} → *.{reg} ({len(subs)} unique subdomains)",
                                  f"dns_tunnel:{client}:{reg}", src_ip=ip, count=len(subs), mode="max",
                                  events={"source": "unbound", "ip": ip, "q": reg},
                                  description=f"{label} queried {len(subs)} unique subdomains of {reg} in 10 minutes, "
                                              f"{len(long_subs)} longer than 30 chars. Samples: {', '.join(long_subs[:5])}"
                                              + ("" if ip else f" {no_client}"))
        for client, domains in dga.items():
            if len(domains) >= 8:
                ip, label = await name(client)
                rating = corroborate(Rating("medium", "random-looking domain names are typical for malware (DGA), but CDNs "
                                                      "and some apps produce them too"), await evidence(ip, "dns_dga"), 1)
                await raise_alert("dns_dga", rating, f"Possible DGA/malware DNS from {label} ({len(domains)} random-looking domains)",
                                  f"dns_dga:{client}", src_ip=ip, count=len(domains), mode="max",
                                  events={"source": "unbound", "ip": ip},
                                  description=f"High-entropy domain names queried by {label}: {', '.join(sorted(domains)[:10])}"
                                              + ("" if ip else f" {no_client}") + " A known service with random names? Add it "
                                              "under Settings › Data & detection › DNS: domains to ignore.")
        for client, n in nx.items():
            if n >= 150:
                ip, label = await name(client)
                top = ", ".join(f"{d} ({c}×)" for d, c in nx_domains[client].most_common(8))
                rating = corroborate(Rating("low", "lots of failing lookups - usually a misconfigured device or a removed "
                                                   "service, sometimes DGA malware"), await evidence(ip, "dns_nxdomain"))
                await raise_alert("dns_nxdomain", rating, f"{label} produced {n} NXDOMAIN answers in 10 minutes",
                                  f"dns_nx:{client}", src_ip=ip, count=n, mode="max",
                                  events={"source": "unbound", "ip": ip, "d_rcode": "NXDOMAIN"},
                                  data={"top_domains": nx_domains[client].most_common(25)},
                                  description=f"Most looked-up non-existent names: {top}. Many failing lookups are typical for "
                                              f"DGA malware, a misconfigured device or a removed service." + ("" if ip else f" {no_client}"))
        for client, domains in bad_block.items():
            ip, label = await name(client)
            rating = Rating("high", f"{len(domains)} different malicious domains looked up - the device may be infected") \
                if len(domains) >= 3 else Rating("medium", "a malicious domain was looked up (blocked) - can be a single bad "
                                                           "link or ad, or malware")
            corroborate(rating, await evidence(ip, "dns_malicious_blocked"), 1)
            await raise_alert("dns_malicious_blocked", rating, f"{label} tried to resolve {len(domains)} malicious domain(s)",
                              f"dns_bad:{client}", src_ip=ip, count=len(domains), mode="max", blocked="the lookups were blocked",
                              events={"source": "unbound", "ip": ip, "action": "block,drop"},
                              description=f"Blocked by a security blocklist: {', '.join(sorted(domains)[:15])}"
                                          + ("" if ip else f" {no_client}"))

    # ------------------------------------------------------ system rules ---
    # ------------------------------------------------- correlation rules ---
    # Ideas from network threat hunting (RITA / Zeek beacon scoring, Sigma password-spray rules, MITRE ATT&CK
    # T1110.003 password spraying, T1071.004 DNS C2, T1021 remote services, T1048 exfiltration, T1572 DNS bypass).
    def _due(self, name: str, seconds: int) -> bool:
        """Expensive rules run less often than the detection interval."""
        now = time.monotonic()
        last = self._ran.get(name)
        if last is not None and now - last < seconds:
            return False
        self._ran[name] = now
        return True

    # behaviour & ML, threat intel and traps live in behavior.py / intel.py
    async def behavior_profiles(self) -> None:
        if self._due("profiles", 120):
            await self.behavior.update_profiles()

    async def behavior_hourly(self) -> None:
        if self._due("hourly", 300):
            await self.behavior.hourly()

    async def behavior_cleanup(self) -> None:
        if self._due("behavior_cleanup", 86400):
            await self.behavior.cleanup()

    async def risk_scores(self) -> None:
        await self.behavior.risk()
        if self._due("feedback", 600):
            await self.behavior.feedback()

    async def threat_intel(self) -> None:
        await self.intel.match(self.internal, self._watermark, self._commit)

    async def canary(self) -> None:
        await self.intel.canary(self.internal, self._watermark, self._commit)

    async def arp_spoofing(self) -> None:
        await self.intel.arp(self.internal)

    async def young_domains(self) -> None:
        if self._due("rdap", 60):
            await self.intel.rdap(self.internal)

    async def password_spray(self) -> None:
        """One address trying MANY different usernames: a list-based attack, not a forgotten password."""
        rows = await db.pool().fetch(
            "SELECT src_ip, count(DISTINCT username) AS users, count(*) AS hits, "
            "(array_agg(DISTINCT username))[1:15] AS names, array_agg(DISTINCT coalesce(host, source)) AS targets "
            "FROM events WHERE action = 'login_failed' AND ts > now() - interval '1 hour' AND src_ip IS NOT NULL "
            "AND username IS NOT NULL AND username <> '' GROUP BY src_ip HAVING count(DISTINCT username) >= 5")
        for r in rows:
            ip = str(r["src_ip"])
            if self.internal(ip):
                rating = corroborate(Rating("high", "a device INSIDE the network tries many accounts - malware or an "
                                                    "intruder looking for a weak password"), await evidence(ip, "password_spray"), 1)
            else:
                rating = Rating("medium", "many usernames from one internet address - an automated attack with a "
                                          "username list; nothing got in unless a login alert follows")
            await raise_alert(
                "password_spray", rating, f"Password spraying from {ip}: {r['users']} usernames tried",
                f"spray:{ip}", src_ip=ip, events={"ip": ip, "action": "login_failed"}, count=r["hits"], mode="max",
                description=f"{r['hits']} failed logins for {r['users']} different usernames in 1 hour against "
                            f"{', '.join(sorted(r['targets'] or []))}. Usernames: {', '.join(r['names'] or [])}.")

    async def distributed_brute_force(self) -> None:
        """One username attacked from MANY addresses (botnet): every single address stays under the brute force limit."""
        rows = await db.pool().fetch(
            "SELECT username, count(DISTINCT src_ip) AS ips, count(*) AS hits, (array_agg(DISTINCT host(src_ip)))[1:10] AS sample, "
            "array_agg(DISTINCT src_ip) AS all_ips FROM events WHERE action = 'login_failed' AND ts > now() - interval '1 hour' "
            "AND src_ip IS NOT NULL AND username IS NOT NULL AND username <> '' GROUP BY username HAVING count(DISTINCT src_ip) >= 10")
        for r in rows:
            ok = await db.pool().fetchrow(
                "SELECT host(src_ip) ip, coalesce(host, source) target FROM events WHERE action = 'login_success' "
                "AND username = $1 AND src_ip = ANY($2::inet[]) AND ts > now() - interval '1 hour' LIMIT 1",
                r["username"], r["all_ips"])
            if ok:
                rating = Rating("critical", f"one of the attacking addresses ({ok['ip']}) then LOGGED IN as this user "
                                            f"on {ok['target']}", sticky=True)
            else:
                rating = Rating("medium", "a coordinated attack on one account from many addresses (botnet) - no "
                                          "successful login from them")
            await raise_alert(
                "distributed_brute_force", rating,
                f"Distributed brute force on user '{r['username']}' from {r['ips']} addresses",
                f"dist_bf:{r['username']}", src_ip=ok["ip"] if ok else None,
                events={"action": "login_failed", "user": r["username"]}, count=r["hits"], mode="max",
                description=f"{r['hits']} failed logins for '{r['username']}' from {r['ips']} different addresses in 1 hour "
                            f"(e.g. {', '.join(r['sample'] or [])}). Use a long unique password / key, MFA, and don't "
                            "expose the login to the internet.")

    async def login_location(self) -> None:
        """A successful login from a country never seen for that user, or from two countries too fast to travel."""
        last, current = await self._watermark("login_geo")
        rows = await db.pool().fetch(
            "SELECT id, ts, src_ip, username, source, host, program, src_country FROM events WHERE id > $1 AND id <= $2 "
            "AND action = 'login_success' AND src_ip IS NOT NULL AND username IS NOT NULL AND src_country IS NOT NULL",
            last, current)
        for r in rows:
            ip = str(r["src_ip"])
            if self.internal(ip):
                continue
            prev = await db.pool().fetch(
                "SELECT src_country, max(ts) AS last FROM events WHERE action = 'login_success' AND username = $1 "
                "AND src_country IS NOT NULL AND id < $2 AND ts > now() - interval '90 days' GROUP BY 1",
                r["username"], r["id"])
            if not prev:
                continue  # first login we know of: nothing to compare with
            countries = {p["src_country"]: p["last"] for p in prev}
            if r["src_country"] in countries:
                continue
            target = login_target(r["source"], r["host"], [r["program"]])
            recent = [(c, t) for c, t in countries.items() if t and (r["ts"] - t).total_seconds() < 2 * 3600]
            if recent:
                c, t = max(recent, key=lambda x: x[1])
                rating = Rating("high", f"logged in from {c} {int((r['ts'] - t).total_seconds() // 60)} min earlier - "
                                        "too fast to travel (stolen password, or a VPN / proxy)", sticky=True)
                title = f"Impossible travel: '{r['username']}' logged in from {c} and {r['src_country']}"
            else:
                rating = Rating("medium", f"this user only logged in from {', '.join(sorted(countries))} before",
                                sticky=True)
                title = f"Login to {target} for '{r['username']}' from a new country: {r['src_country']}"
            await raise_alert(
                "login_new_location", corroborate(rating, await evidence(ip, "login_new_location"), 1), title,
                f"geo:{r['username']}:{r['src_country']}", src_ip=ip, events={"ip": ip, "action": "login_success"},
                description=f"Successful login to {target} as '{r['username']}' from {ip} ({r['src_country']}). "
                            "If that wasn't you: change the password, end the sessions and check what was done.")
        await self._commit("login_geo", current)

    async def dns_bypass(self) -> None:
        """Devices that talk to DNS servers on the internet directly, past your own resolver and its blocklists."""
        from .intel import dns_redirects  # local import: intel imports this module
        last, current = await self._watermark("dns_bypass")
        rows = await db.pool().fetch(
            "SELECT src_ip, dst_port, count(*) AS hits, (array_agg(DISTINCT host(dst_ip)))[1:8] AS dsts, "
            "bool_or(source = 'firewall' AND direction = 'out') AS left_wan FROM events "
            "WHERE id > $1 AND id <= $2 AND source IN ('firewall', 'zenarmor') AND dst_port IN (53, 853) "
            f"AND {ALLOWED_ROW} AND src_ip IS NOT NULL AND dst_ip IS NOT NULL "
            "GROUP BY src_ip, dst_port", last, current)
        # A NAT port forward that sends port 53 to Unbound catches these queries, but Zenarmor (it sees the packets
        # before NAT) and the firewall's pass log still show the original destination (8.8.8.8). Only a pass OUT
        # (on the way to the internet, after NAT) proves the query really left. Known redirect: the configured port
        # forwards (OPNsense API) or the redirect's own log lines ('rdr', NAT rule with logging on).
        redirects = dns_redirects(await db.get_snapshot("nat_rules"))
        rdr_seen = {str(x["src_ip"]) for x in await db.pool().fetch(
            "SELECT DISTINCT src_ip FROM events WHERE source = 'firewall' AND action = 'rdr' AND dst_port = 53 "
            "AND src_ip IS NOT NULL AND ts > now() - interval '1 hour'")} if rows else set()
        for r in rows:
            src = str(r["src_ip"])
            dsts = [d for d in r["dsts"] or [] if not self.internal(d)]
            if not self.internal(src) or not dsts:
                continue
            if r["dst_port"] == 53 and (redirects or src in rdr_seen) and not r["left_wan"]:
                continue  # caught by the DNS redirect: answered by your own resolver
            kind = "DNS-over-TLS (853)" if r["dst_port"] == 853 else "plain DNS (53)"
            rating = corroborate(Rating("low", "bypasses your DNS server and its blocklists - common for Chromecast / "
                                               "some IoT with hard-coded DNS, but also used by malware to avoid "
                                               "filtering", sticky=True), await evidence(src, "dns_bypass"))
            if r["dst_port"] == 53 and redirects:
                fix = (f"The firewall logged it leaving towards the internet although a DNS redirect exists "
                       f"({redirects[0]}): check that the redirect's interface / source covers {src}.")
            elif r["dst_port"] == 53:
                fix = ("To force all devices through it: OPNsense › Firewall › NAT › Port Forward: redirect LAN TCP/UDP "
                       "53 to 127.0.0.1 (Unbound). Already have that redirect? Then give Looking Glass's API user the "
                       "'Firewall: NAT: Port Forward' privilege (or tick 'Log' on the NAT rule) so it knows.")
            else:
                fix = "DNS-over-TLS can't be redirected: block it with a LAN rule for TCP 853 to the internet."
            await raise_alert(
                "dns_bypass", rating, f"{src} uses external DNS servers directly ({kind})", f"dns_bypass:{src}:{r['dst_port']}",
                src_ip=src, events={"ip": src, "port": r["dst_port"]}, count=r["hits"],
                description=f"{src} sent {kind} queries to {', '.join(dsts)} instead of your own resolver. {fix}")
        await self._commit("dns_bypass", current)

    async def beaconing(self) -> None:
        """Malware 'phones home' at a fixed rhythm. Regular intervals to a rarely used domain / address over hours are
        a classic command-and-control sign (RITA-style beacon scoring)."""
        if not self._due("beaconing", 900):
            return
        ignore = ignore_list(self.settings.dns_ignore_domains)
        queries = {
            "dns": ("SELECT src_ip, domain AS dst, ts FROM events WHERE source = 'unbound' AND ts > now() - interval '6 hours' "
                    "AND src_ip IS NOT NULL AND domain IS NOT NULL",
                    "SELECT domain AS dst FROM events WHERE source = 'unbound' AND ts > now() - interval '7 days' "
                    "AND domain = ANY($1::text[]) GROUP BY domain HAVING count(DISTINCT src_ip) > 2"),
            "conn": ("SELECT src_ip, host(dst_ip) AS dst, ts FROM events WHERE source IN ('zenarmor', 'firewall') "
                     # every attempt counts, blocked ones too: malware keeps retrying at its rhythm
                     "AND action IN ('pass', 'allow', 'conn', 'block', 'drop') AND ts > now() - interval '6 hours' "
                     "AND src_ip IS NOT NULL "
                     "AND dst_ip IS NOT NULL",
                     "SELECT host(dst_ip) AS dst FROM events WHERE source IN ('zenarmor', 'firewall') "
                     "AND ts > now() - interval '7 days' AND host(dst_ip) = ANY($1::text[]) GROUP BY dst_ip "
                     "HAVING count(DISTINCT src_ip) > 2"),
        }
        for kind, (base, popular) in queries.items():
            rows = await db.pool().fetch(
                f"WITH t AS (SELECT DISTINCT src_ip, dst, date_trunc('second', ts) AS ts FROM ({base} LIMIT 2000000) x), "
                "d AS (SELECT src_ip, dst, extract(epoch FROM ts - lag(ts) OVER (PARTITION BY src_ip, dst ORDER BY ts)) AS gap FROM t) "
                "SELECT src_ip, dst, count(*) + 1 AS n, avg(gap) AS mean, stddev_pop(gap) AS sd FROM d WHERE gap IS NOT NULL "
                "GROUP BY src_ip, dst HAVING count(*) >= 30 AND avg(gap) BETWEEN 60 AND 3600 "
                "AND stddev_pop(gap) < 0.1 * avg(gap) LIMIT 200")
            rows = [r for r in rows if self.internal(str(r["src_ip"]))
                    and (kind == "conn" and not self.internal(r["dst"]) or kind == "dns" and not ignored_domain(r["dst"], ignore))]
            if not rows:
                continue
            common = {p["dst"] for p in await db.pool().fetch(popular, list({r["dst"] for r in rows}))}
            for r in rows:
                if r["dst"] in common:
                    continue  # several devices talk to it: a normal service (updates, time, cloud)
                src = str(r["src_ip"])
                every = f"{round(r['mean'] / 60)} min" if r["mean"] >= 90 else f"{round(r['mean'])} s"
                rating = corroborate(Rating("low", f"contacted at a near-constant rhythm (every {every}, ±{round(r['sd'])} s) "
                                                   "and no other device uses it - typical for malware check-ins, also for "
                                                   "some IoT clouds and update checkers"), await evidence(src, "beaconing"))
                if kind == "dns":
                    seen = await db.pool().fetchval("SELECT first_seen FROM seen_domains WHERE domain = $1",
                                                    registered_domain(r["dst"]))
                    if seen and (time.time() - seen.timestamp()) < 3 * 86400 and await db.kv_get("nod:since") and \
                            time.time() - await db.kv_get("nod:since") > 3 * 86400:
                        rating.up("and the domain was first seen on your network less than 3 days ago")
                what = r["dst"] if kind == "dns" else f"address {r['dst']}"
                how = ""
                if kind == "conn":
                    v = await db.pool().fetchrow(
                        f"SELECT {ALLOWED_AGG} passed, {FW_BLOCKED_AGG} fw_blocked, {FW_RULE_AGG} fw_rule FROM events "
                        "WHERE src_ip = $1::inet AND dst_ip = $2::inet AND ts > now() - interval '6 hours' "
                        "AND source IN ('firewall', 'zenarmor')", src, r["dst"])
                    how = verdict(v["passed"], v["fw_blocked"], v["fw_rule"])
                    if not v["passed"]:
                        rating.note(f"{how} - the firewall stops it, but the device keeps trying (malware retries like this)")
                await raise_alert(
                    "beaconing", rating, f"Possible beaconing: {src} → {what} every {every}", f"beacon:{src}:{r['dst']}",
                    src_ip=src, dst_ip=r["dst"] if kind == "conn" else None, count=r["n"], mode="max",
                    blocked=kind == "conn" and not v["passed"] and "every attempt was blocked",
                    # an address: only the traffic to it, so the alert's ports (and port filters) are those of this flow
                    events={"ip": src, "q": r["dst"]} if kind == "dns" else {"src": src, "dst": r["dst"]},
                    description=f"{src} contacted {what} {r['n']} times in 6 hours at very regular intervals (every {every})"
                                + (f"; {how}" if how else "") + ". "
                                "Check which program on the device does this; if it is a known service, "
                                + ("add it to Settings › Data & detection › DNS: domains to ignore or mute it."
                                   if kind == "dns" else
                                   "mute it in Settings › Alert filters (rule Beaconing, this device's IP and the "
                                   "destination ports, e.g. 19294-19344 for Discord voice). A long UDP session (voice, "
                                   "game) also looks regular: the firewall logs an open flow about every 60 s."))

    async def lateral_movement(self) -> None:
        """One device reaching admin / file-sharing services on many other internal devices: how ransomware and worms
        spread (and what management or backup tools do on purpose)."""
        rows = await db.pool().fetch(
            "SELECT src_ip, array_agg(DISTINCT host(dst_ip)) AS dsts, count(*) AS hits, array_agg(DISTINCT dst_port) AS ports, "
            f"count(*) FILTER (WHERE {ALLOWED_ROW}) AS passed FROM events "
            "WHERE source IN ('firewall', 'zenarmor') AND ts > now() - interval '15 minutes' AND dst_port = ANY($1::int[]) "
            "AND src_ip IS NOT NULL AND dst_ip IS NOT NULL AND src_ip <> dst_ip GROUP BY src_ip HAVING count(DISTINCT dst_ip) >= 5",
            list(LATERAL_PORTS))
        for r in rows:
            src = str(r["src_ip"])
            if not self.internal(src):
                continue
            internal_dsts = sum(1 for d in r["dsts"] if self.internal(d))
            if internal_dsts < 5:
                continue
            services = ", ".join(sorted({LATERAL_PORTS[p] for p in r["ports"] if p in LATERAL_PORTS}))
            rating = Rating("medium", "one device opening admin / file-sharing services on many internal devices - "
                                      "how ransomware and worms spread; also normal for backup or management tools")
            if r["passed"]:
                rating.up("some connections were ALLOWED")
            corroborate(rating, await evidence(src, "lateral_movement"), 1)
            await raise_alert(
                "lateral_movement", rating, f"Possible lateral movement: {src} → {internal_dsts} internal hosts ({services})",
                f"lateral:{src}", src_ip=src, events={"ip": src}, count=r["hits"], mode="max",
                blocked=not r["passed"] and "every connection was blocked",
                description=f"{src} contacted {services} on {internal_dsts} internal hosts within 15 minutes "
                            f"({r['passed']} allowed). Is this a backup / management tool? Otherwise isolate the device.")

    async def large_upload(self) -> None:
        """Much more data sent to the internet than the device normally sends: possible exfiltration."""
        if not self._due("large_upload", 900):
            return
        up = ("greatest(coalesce((data->>'src_nbytes')::numeric, 0), coalesce((data->>'src_pbytes')::numeric, 0))")
        rows = await db.pool().fetch(
            f"SELECT src_ip, sum({up}) FILTER (WHERE ts > now() - interval '1 hour') AS last_hour, "
            f"sum({up}) FILTER (WHERE ts <= now() - interval '1 hour') / 167.0 AS per_hour, "
            f"(array_agg(DISTINCT host(dst_ip)) FILTER (WHERE ts > now() - interval '1 hour'))[1:5] AS dsts "
            "FROM events WHERE source = 'zenarmor' AND data->>'family' = 'conn' AND ts > now() - interval '7 days' "
            "AND src_ip IS NOT NULL GROUP BY src_ip")
        for r in rows:
            src, hour, base = str(r["src_ip"]), float(r["last_hour"] or 0), float(r["per_hour"] or 0)
            if not self.internal(src) or hour < 1024 ** 3 or hour < 5 * max(base, 50 * 1024 ** 2):
                continue
            rating = corroborate(Rating("low", f"{hour / 1024 ** 3:.1f} GB sent in the last hour, normally "
                                               f"{base / 1024 ** 2:.0f} MB per hour - a cloud backup or upload, or data "
                                               "being stolen"), await evidence(src, "large_upload"))
            await raise_alert(
                "large_upload", rating, f"Unusual upload: {src} sent {hour / 1024 ** 3:.1f} GB in 1 hour",
                f"upload:{src}", src_ip=src, events={"source": "zenarmor", "ip": src}, mode="max",
                description=f"{src} uploaded {hour / 1024 ** 3:.1f} GB in the last hour (7-day average {base / 1024 ** 2:.0f} "
                            f"MB per hour), to e.g. {', '.join(r['dsts'] or [])}.")

    async def attack_chains(self) -> None:
        """Connect the dots: separate alerts about one address that together tell a story (MITRE ATT&CK stages).
        Outside → in: reconnaissance, then an attack, then access. Inside: a threat sign, then command & control or
        spreading - a compromised device."""
        rows = await db.pool().fetch(
            "SELECT host(coalesce(src_ip, dst_ip)) AS ip, array_agg(DISTINCT rule) AS rules, min(created_at) AS first, "
            "array_agg(id ORDER BY id) AS ids, bool_and(coalesce((data->>'blocked')::boolean, false)) AS all_blocked "
            "FROM alerts WHERE status <> 'closed' AND last_seen > now() - interval '24 hours' "
            "AND coalesce(src_ip, dst_ip) IS NOT NULL AND rule <> 'attack_chain' GROUP BY 1")
        for r in rows:
            ip, rules = r["ip"], set(r["rules"])
            internal = self.internal(ip)
            chain = INTERNAL_CHAIN if internal else EXTERNAL_CHAIN
            stages = [name for name, members in chain if rules & members]
            if not internal and "Access" not in stages:
                continue  # scans and attacks from the internet that got nowhere: background noise
            if len(stages) < 2:
                continue  # one kind of signal is what the alert of that rule already says
            sev = "critical" if len(stages) >= 3 else "high"
            if internal and await db.pool().fetchval(
                    "SELECT 1 FROM devices WHERE ip = $1::inet AND first_seen > now() - interval '48 hours' AND NOT trusted "
                    "LIMIT 1", ip):
                stages.insert(0, "New device")  # an unknown (untrusted) device that misbehaves right away: worse
                sev = "critical"
            story = " → ".join(f"{s} ({', '.join(sorted(rules & dict(chain).get(s, set())) or ['first seen < 48 h'])})"
                               for s in stages)
            why = ("an outside address went from probing to getting in" if not internal else
                   "several independent signs of a compromised device")
            await raise_alert(
                "attack_chain", Rating(sev, why, sticky=True),
                f"{'Attack chain from' if not internal else 'Possibly compromised device'} {ip}: {' → '.join(stages)}",
                f"chain:{ip}", src_ip=ip, events={"ip": ip}, data={"alerts": r["ids"], "stages": stages},
                blocked=r["all_blocked"] and "every step of it was blocked",
                description=f"Related open alerts in the last 24 hours: {story}. Look at them together (Alerts page, filter "
                            f"on {ip}); " + ("block the address and check the accessed account / service." if not internal
                                             else "isolate the device (UniFi › Block, or an OPNsense rule) and check it."))

    async def system_health(self) -> None:
        gws = await db.get_snapshot("gateways") or []
        for gw in gws:
            status = str(gw.get("status", "")).lower()
            if status in ("down", "force_down") or str(gw.get("status_translated", "")).lower() == "offline":
                await raise_alert("gateway_down", Rating("high", "a gateway that is down usually means no internet (or a "
                                                                 "failover is active)"), f"Gateway {gw.get('name')} is DOWN",
                                  f"gw:{gw.get('name')}", description=str(gw))
            elif status in ("loss", "delay", "delay+loss"):
                await raise_alert("gateway_degraded", "low", f"Gateway {gw.get('name')} degraded ({status})",
                                  f"gwdeg:{gw.get('name')}", description=str(gw))
        rows = await db.pool().fetch(
            "SELECT DISTINCT ON (name, labels) name, labels, value FROM metrics WHERE ts > now() - interval '10 minutes' "
            "AND name IN ('disk_used_pct', 'memory_used_pct', 'pf_states_pct') ORDER BY name, labels, ts DESC")
        limits = {"disk_used_pct": 90, "memory_used_pct": 95, "pf_states_pct": 80}
        for r in rows:
            if r["value"] >= limits[r["name"]]:
                await raise_alert("resource", "medium", f"{r['name'].replace('_', ' ')} {r['labels']} at {r['value']:.0f}%",
                                  f"res:{r['name']}:{r['labels']}", description="Resource usage over threshold.")
        services = await db.get_snapshot("services") or []
        for svc in services if isinstance(services, list) else []:
            if str(svc.get("running")) == "0" and not str(svc.get("locked", "0")) == "1":
                name = str(svc.get("name") or "").lower()
                security = any(w in name for w in SECURITY_SERVICES)
                rating = Rating("medium", "a security service is down, so its protection and logging are missing") if security \
                    else Rating("low", "a service is not running")
                await raise_alert("service_stopped", rating, f"Service '{svc.get('name')}' is not running",
                                  f"svc:{svc.get('name')}", description=str(svc.get("description", "")))
        fw = await db.get_snapshot("firmware") or {}
        if isinstance(fw, dict) and fw.get("status") in ("update", "upgrade"):
            await raise_alert("firmware", Rating("low", "updates often contain security fixes - install them in a quiet "
                                                        "moment (System › Firmware › Updates)"),
                              "OPNsense firmware updates available", "firmware",
                              description=str(fw.get("status_msg", "")))

    async def log_silence(self) -> None:
        if STATS.received:
            self._last_events_at = max(self._last_events_at, max(STATS.senders.values(), default=0))
        if STATS.received and time.time() - self._last_events_at > 900:
            await raise_alert("log_silence", Rating("medium", "without logs nothing can be detected; could be a reboot or an "
                                                              "outage, rarely tampering"),
                              "No syslog received from OPNsense for 15+ minutes", "log_silence",
                              description="Log forwarding stopped. Could be an outage, a reboot, a network problem or log tampering.")
