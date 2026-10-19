"""Detection engine: periodic SQL/heuristic rules that turn events into alerts."""
from __future__ import annotations

import asyncio
import logging
import math
import re
import time
from collections import Counter, defaultdict
from typing import Any

from . import alert_filters, db
from .parsers.common import real_name
from .config import Settings
from .ingest import STATS
from .parsers.common import is_internal_ip, parse_networks

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


# a name from a better source replaces one from a worse source, never the other way round
NAME_RANK = {"manual": 100, "unifi-alias": 70, "dnsmasq-static": 60, "unifi": 45, "dhcp": 50, "dns": 30, "zenarmor": 25, "arp": 20}


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

    def note(self, reason: str) -> "Rating":
        """Context that does not change the level."""
        self.why.append(reason)
        return self

    def text(self) -> str:
        return f"Severity {self.severity}: " + "; ".join(self.why) + "."


# alerts built from the same events must not confirm each other
RULE_FAMILIES = [{"brute_force", "success_after_failures", "admin_login"},
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
            "AND rule NOT IN ('new_device', 'admin_login', 'config_change', 'port_scan', 'host_sweep')",
            ip, sorted(next((f for f in RULE_FAMILIES if rule in f), {rule})), hours)
    except Exception:  # noqa: BLE001 - invalid IP text etc.
        return {}
    out = dict(row) if row else {}
    out["other_alerts"] = sorted(r["rule"] for r in others)
    return out


def threat_signals(ev: dict[str, Any]) -> list[str]:
    """Independent signs that a host is compromised / malicious (for corroboration)."""
    sig = [f"{ev[k]} {label}" for k, label in (("ids", "IDS alert(s)"), ("qfeeds", "threat-intel hit(s)"),
                                                 ("zen", "Zenarmor threat event(s)")) if ev.get(k)]
    if ev.get("other_alerts"):
        sig.append("open alerts: " + ", ".join(ev["other_alerts"][:5]))
    return sig


def corroborate(r: Rating, ev: dict[str, Any], max_steps: int = 2) -> Rating:
    sig = threat_signals(ev)
    if sig:
        r.up("also seen by other sources in the last 24h (" + "; ".join(sig) + ")", min(len(sig), max_steps))
    return r


async def raise_alert(rule: str, severity: str | Rating, title: str, fingerprint: str, description: str = "",
                      src_ip: str | None = None, dst_ip: str | None = None, data: dict | None = None,
                      count: int = 1, mode: str = "add", events: dict[str, Any] | None = None) -> None:
    """Create an alert or update the matching open one (dedupe by fingerprint within 24h).

    ``severity``: a level, or a Rating whose reasons are added to the description. A Rating of a windowed rule is
    re-evaluated on every run (it covers the last 24 hours), so its level replaces the stored one; plain levels and
    sticky Ratings only raise it.
    ``events``: Event-search filters that show the events behind the alert (default: the source IP);
    the alerts page links to them for the alert's time span. The device name of ``src_ip`` is added."""
    pool = db.pool()
    data = dict(data or {})
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
    # your own severity rules (Settings › Alert filters › "Change the severity") come first; mute filters see the result
    if ov := await alert_filters.check(rule, severity, title, description, src_ip, dst_ip, kind="severity"):
        if ov["set_severity"] != severity:
            label = ov.get("name") or f"filter #{ov['id']}"
            data["severity_override"] = {"from": severity, "to": ov["set_severity"], "filter": {"id": ov["id"], "name": ov.get("name")}}
            data["severity_why"] = list(data.get("severity_why") or []) + [f"→ set to {ov['set_severity']} by your rule “{label}” (was {severity})"]
            description += f"\n\nSeverity set to {ov['set_severity']} by your alert rule “{label}” (was {severity})."
            severity = ov["set_severity"]
            keep_max = False  # your choice replaces the stored level, also downwards
    status = "open"
    if flt := await alert_filters.check(rule, severity, title, description, src_ip, dst_ip):
        if flt["action"] == "suppress":
            log.debug("alert '%s' stopped by filter %s", title, flt["id"])
            return
        status = "closed"  # "create as closed": kept for reference, never shown as open
        data["filter"] = {"id": flt["id"], "name": flt.get("name")}
    row = await pool.fetchrow(
        "SELECT id, severity FROM alerts WHERE fingerprint = $1 AND status <> 'closed' "
        "AND last_seen > now() - interval '24 hours' ORDER BY id DESC LIMIT 1", fingerprint)
    if row:
        sev = max(row["severity"], severity, key=SEVERITIES.index) if keep_max else severity
        count_sql = "count + $2" if mode == "add" else "GREATEST(count, $2)"
        await pool.execute(
            f"UPDATE alerts SET last_seen = now(), count = {count_sql}, severity = $3, description = $4, data = $5, "
            f"status = CASE WHEN $6 = 'closed' THEN 'closed' ELSE status END WHERE id = $1",
            row["id"], count, sev, description, data, status)
        return
    await pool.execute(
        "INSERT INTO alerts (rule, severity, title, description, src_ip, dst_ip, count, fingerprint, data, status) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        rule, severity, title, description, src_ip, dst_ip, count, fingerprint, data, status)
    log.info("ALERT [%s] %s", severity, title)


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


async def track_devices(devices: list[dict[str, Any]], origin: str, mark_online: bool = False) -> None:
    """Upsert devices (from ARP, DHCP leases or DHCP logs) and alert on MAC addresses never seen before.

    ``mark_online``: the list is a complete snapshot of present devices (ARP table) -> others become offline.
    """
    pool = db.pool()
    if mark_online:
        await pool.execute("UPDATE devices SET online = false WHERE online AND NOT (mac = ANY($1::text[]))",
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
            await raise_alert(
                "new_device", Rating("low", "an unknown MAC address appeared - usually a new phone, guest or randomised "
                                            "Wi-Fi address; mark it trusted on the Devices page when you know it", sticky=True),
                f"New device on network: {d['mac']} ({d.get('hostname') or d.get('ip') or '?'})",
                f"new_device:{d['mac']}",
                description=f"A MAC address never seen before appeared via {origin}: "
                            f"ip={d.get('ip')} hostname={d.get('hostname')} vendor={d.get('vendor')} interface={d.get('interface')}. "
                            "Verify it is a known device (intruder / rogue device check) and mark it trusted on the Devices page.",
                src_ip=d.get("ip"), data={k: v for k, v in d.items() if v is not None})


_zen_seen: dict[str, float] = {}


async def zenarmor_device_listener(events: list[dict[str, Any]]) -> None:
    """Zenarmor records carry the client MAC, hostname and a device fingerprint (name/vendor/OS)."""
    now = time.time()
    found: dict[str, dict[str, Any]] = {}
    for e in events:
        d = e.get("data") if e.get("source") == "zenarmor" else None
        if not isinstance(d, dict):
            continue
        mac = str(d.get("src_hwaddr") or "").lower()
        if len(mac) != 17 or mac in found or now - _zen_seen.get(mac, 0) < 600:
            continue
        dev = d.get("device") if isinstance(d.get("device"), dict) else {}
        vendor = " / ".join(x for x in (dev.get("vendor"), dev.get("os")) if x) or None
        found[mac] = {"mac": mac, "ip": e.get("src_ip"), "hostname": dev.get("name") or d.get("src_hostname"),
                      "vendor": vendor, "interface": d.get("interface"), "online": True}
    for mac in found:
        _zen_seen[mac] = now
    await track_devices(list(found.values()), origin="zenarmor")


async def dhcp_listener(events: list[dict[str, Any]]) -> None:
    devices = [{"mac": e["data"]["mac"], "ip": e.get("dst_ip"), "hostname": e["data"].get("hostname")}
               for e in events if e.get("source") == "dhcp" and isinstance(e.get("data"), dict) and e["data"].get("mac")]
    await track_devices(devices, origin="dhcp")


class DetectionEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._last_events_at = time.time()

    async def run(self) -> None:
        await asyncio.sleep(20)
        while True:
            started = time.monotonic()
            for rule in (self.port_scan, self.host_sweep, self.brute_force, self.success_after_failures,
                         self.external_admin_login, self.web_attacks, self.web_scanner, self.ids_alerts,
                         self.crowdsec_alerts, self.qfeeds_hits, self.zenarmor_threats, self.dns_anomalies,
                         self.internal_blocked_outbound, self.suspicious_outbound_ports, self.config_changes,
                         self.system_health, self.log_silence):
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
            sev = await self.rate_scan(ip, internal, "port_scan")
            await raise_alert(
                "port_scan", sev, f"{'Internal' if internal else 'External'} port scan from {ip} ({r['ports']} ports)",
                f"port_scan:{ip}", src_ip=ip, events={"source": "firewall", "ip": ip, "action": "block"}, count=r["hits"], mode="max",
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
            await raise_alert(
                "host_sweep", await self.rate_scan(ip, self.internal(ip), "host_sweep"),
                f"Host sweep from {ip} on port {r['dst_port']} ({r['hosts']} hosts)", f"host_sweep:{ip}:{r['dst_port']}", events={"source": "firewall", "ip": ip, "port": r["dst_port"]},
                src_ip=ip, count=r["hits"], mode="max",
                description=f"{ip} tried port {r['dst_port']} on {r['hosts']} different hosts within 10 minutes.")

    async def rate_scan(self, ip: str, internal: bool, rule: str) -> Rating:
        """Scans and sweeps: the number of ports / hosts does not matter, what got through and who scans does."""
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
                description=f"Internal host {ip} was blocked {r['hits']} times towards {r['dsts']} destinations in 10 "
                            f"minutes (ports {list(r['ports'] or [])[:20]}). Could be malware beaconing, a misconfigured "
                            "device or a blocked policy.")

    async def suspicious_outbound_ports(self) -> None:
        last, current = await self._watermark("susp_ports")
        rows = await db.pool().fetch(
            "SELECT src_ip, dst_ip, dst_port, action, count(*) AS hits FROM events WHERE id > $1 AND id <= $2 "
            "AND source IN ('firewall', 'zenarmor') AND dst_port = ANY($3::int[]) AND src_ip IS NOT NULL "
            "GROUP BY src_ip, dst_ip, dst_port, action", last, current, list(SUSPICIOUS_OUT_PORTS))
        for r in rows:
            src, dst = str(r["src_ip"]), str(r["dst_ip"])
            if not self.internal(src) or self.internal(dst):
                continue
            passed = r["action"] in ("pass", "conn", "allow")
            rating = Rating("medium", "the connection was ALLOWED out") if passed else \
                Rating("low", "the connection was blocked")
            rating.sticky = True
            corroborate(rating, await evidence(src, "suspicious_outbound_port"))
            await raise_alert(
                "suspicious_outbound_port", rating,
                f"{src} → {dst}:{r['dst_port']} ({SUSPICIOUS_OUT_PORTS[r['dst_port']]}) {'ALLOWED' if passed else r['action']}",
                f"susp_port:{src}:{r['dst_port']}", src_ip=src, events={"source": "firewall", "ip": src, "port": r["dst_port"]}, dst_ip=dst, count=r["hits"],
                description=f"Internal host {src} connected to external {dst} on port {r['dst_port']} "
                            f"({SUSPICIOUS_OUT_PORTS[r['dst_port']]}); action={r['action']}.")
        await self._commit("susp_ports", current)

    # -------------------------------------------------------- auth rules ---
    async def brute_force(self) -> None:
        rows = await db.pool().fetch(
            "SELECT src_ip, source, count(*) AS hits, array_agg(DISTINCT username) FILTER (WHERE username IS NOT NULL) AS users "
            "FROM events WHERE action = 'login_failed' AND ts > now() - interval '15 minutes' AND src_ip IS NOT NULL "
            "GROUP BY src_ip, source HAVING count(*) >= 5")
        for r in rows:
            ip = str(r["src_ip"])
            if self.internal(ip):
                rating = corroborate(Rating("high", "password guessing from INSIDE the network"), await evidence(ip, "brute_force"), 1)
            else:
                # failed attempts from the internet: annoying but harmless - unless one succeeds (separate critical alert)
                rating = Rating("medium", "failed password guessing from the internet - nothing got in, but the service is "
                                          "reachable from outside")
            await raise_alert(
                "brute_force", rating, f"Brute force against {r['source'].upper()} from {ip} ({r['hits']} failures)",
                f"brute_force:{r['source']}:{ip}", src_ip=ip, events={"source": r["source"], "ip": ip, "action": "login_failed"}, count=r["hits"], mode="max",
                description=f"{r['hits']} failed logins from {ip} in 15 minutes. Usernames tried: {list(r['users'] or [])[:20]}.")

    async def success_after_failures(self) -> None:
        rows = await db.pool().fetch(
            "SELECT s.src_ip, s.username, s.source, max(s.ts) AS ts, (SELECT count(*) FROM events f WHERE f.action = 'login_failed' "
            "AND f.src_ip = s.src_ip AND f.ts BETWEEN s.ts - interval '1 hour' AND s.ts) AS failures "
            "FROM events s WHERE s.action = 'login_success' AND s.ts > now() - interval '10 minutes' AND s.src_ip IS NOT NULL "
            "GROUP BY s.src_ip, s.username, s.source, s.ts")
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
                    f"Successful {r['source']} login for '{r['username']}' from {ip} after {r['failures']} failures",
                    f"succ_after_fail:{ip}:{r['username']}", src_ip=ip, events={"ip": ip, "action": "login_failed,login_success"}, mode="max",
                    description="A login succeeded right after a series of failures - possible password guessing success. "
                                "Verify this login was legitimate.")

    async def external_admin_login(self) -> None:
        last, current = await self._watermark("ext_login")
        rows = await db.pool().fetch(
            "SELECT src_ip, username, source, program, count(*) AS n FROM events WHERE id > $1 AND id <= $2 "
            "AND action = 'login_success' AND src_ip IS NOT NULL GROUP BY 1, 2, 3, 4", last, current)
        for r in rows:
            ip = str(r["src_ip"])
            internal = self.internal(ip)
            vpn = r["source"] == "vpn"
            if internal:
                rating = Rating("info", "login from inside the network")
            elif vpn:
                rating = Rating("low", "VPN users log in from the internet by design")
            else:
                rating = Rating("high", "the firewall's admin interface (web GUI / SSH / API) accepted a login from the "
                                        "INTERNET - it should normally only be reachable from inside or through the VPN")
            rating.sticky = True
            await raise_alert(
                "admin_login", rating,
                f"{'Login' if internal or vpn else 'Login from EXTERNAL address'}: '{r['username']}' via {r['program'] or r['source']} from {ip}",
                f"login:{ip}:{r['username']}", src_ip=ip, events={"ip": ip, "action": "login_success"}, count=r["n"],
                description=("VPN login." if vpn else "Administrative login to the firewall.") +
                            ("" if internal else " The source is a public IP address."))
        await self._commit("ext_login", current)

    async def config_changes(self) -> None:
        last, current = await self._watermark("config")
        rows = await db.pool().fetch(
            "SELECT host, program, message, ts FROM events WHERE id > $1 AND id <= $2 AND action = 'config_change' LIMIT 50", last, current)
        for r in rows:
            await raise_alert("config_change", "info", f"Configuration change on {r['host'] or 'firewall'}",
                              f"config:{r['host']}", events={"action": "config_change", "host": r["host"]}, description=r["message"][:1000])
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
            await raise_alert("ids", rating, f"IDS: {r['message']}", f"ids:{r['src_ip']}:{r['message']}",
                              events={"source": "suricata", "ip": str(r["src_ip"]) if r["src_ip"] else None, "q": r["message"][:80]},
                              src_ip=str(r["src_ip"]) if r["src_ip"] else None, dst_ip=str(r["dst_ip"]) if r["dst_ip"] else None,
                              count=r["hits"], description=f"Suricata signature '{r['message']}' ({r['cls'] or 'n/a'}) "
                                                           f"{r['src_ip']} -> {r['dst_ip']}, {r['hits']} hit(s).")
        await self._commit("ids", current)

    async def crowdsec_alerts(self) -> None:
        last, current = await self._watermark("crowdsec")
        rows = await db.pool().fetch(
            "SELECT src_ip, coalesce(data->>'scenario', data->>'reason', 'unknown') AS scenario, count(*) AS hits "
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
                              description=f"CrowdSec detected behaviour '{r['scenario']}' from {ip}.")
        await self._commit("crowdsec", current)

    async def qfeeds_hits(self) -> None:
        last, current = await self._watermark("qfeeds")
        rows = await db.pool().fetch(
            "SELECT src_ip, dst_ip, dst_port, count(*) AS hits FROM events WHERE id > $1 AND id <= $2 AND source = 'qfeeds' "
            "GROUP BY 1, 2, 3", last, current)
        inbound: dict[str, int] = defaultdict(int)
        for r in rows:
            src, dst = (str(r["src_ip"]) if r["src_ip"] else None), (str(r["dst_ip"]) if r["dst_ip"] else None)
            if src and self.internal(src):
                rating = Rating("high", "a device inside contacted a known malicious address (blocked by Q-Feeds) - "
                                        "the device itself may be infected", sticky=True)
                ev = await evidence(src, "threat_intel_outbound")
                ev["qfeeds"] = 0  # that is this alert
                corroborate(rating, ev, 1)
                await raise_alert(
                    "threat_intel_outbound", rating, f"Internal host {src} contacted threat-intel listed IP {dst}",
                    f"qf_out:{src}:{dst}", src_ip=src, events={"source": "qfeeds", "ip": src}, dst_ip=dst, count=r["hits"],
                    description=f"Q-Feeds blocked traffic from internal {src} to known malicious {dst}:{r['dst_port']}. "
                                "The internal host may be compromised (C2 / malware beacon). Investigate it.")
            elif src:
                inbound[src] += r["hits"]
        for src, hits in inbound.items():
            if hits >= 20:
                await raise_alert("threat_intel_inbound", Rating("info", "known-bad internet address probing you, already "
                                                                         "blocked by Q-Feeds", sticky=True),
                                  f"Threat-intel listed IP {src} is probing you",
                                  f"qf_in:{src}", src_ip=src, events={"source": "qfeeds", "ip": src}, count=hits,
                                  description=f"{hits} connection attempts from {src} (Q-Feeds listed) were blocked.")
        await self._commit("qfeeds", current)

    async def zenarmor_threats(self) -> None:
        last, current = await self._watermark("zenarmor")
        rows = await db.pool().fetch(
            "SELECT src_ip, coalesce(domain, host(dst_ip)) AS target, coalesce(data->>'security', data->>'security_tags', '') AS threat, "
            "bool_or(action = 'block') AS blocked, count(*) AS hits "
            "FROM events WHERE id > $1 AND id <= $2 AND source = 'zenarmor' "
            "AND (data->>'family' = 'alert' OR coalesce(data->>'security', data->>'security_tags', '') <> '') "
            "GROUP BY 1, 2, 3", last, current)
        for r in rows:
            threat = r["threat"] or "threat alert"
            src = str(r["src_ip"]) if r["src_ip"] else None
            bad = any(w in threat.lower() for w in ("malware", "botnet", "phishing", "command", "c2", "ransom", "crypto"))
            if bad:
                rating = Rating("high", f"'{threat[:40]}' traffic from this device (blocked)", sticky=True) if r["blocked"] else \
                    Rating("critical", f"'{threat[:40]}' traffic from this device was NOT blocked", sticky=True)
            else:
                rating = Rating("low", "flagged and blocked by Zenarmor", sticky=True) if r["blocked"] else \
                    Rating("medium", "flagged by Zenarmor but NOT blocked", sticky=True)
            if src and self.internal(src):
                ev = await evidence(src, "zenarmor_threat")
                ev["zen"] = 0  # that is this alert
                corroborate(rating, ev, 1)
            await raise_alert("zenarmor_threat", rating, f"Zenarmor: {src} → {r['target']} ({threat[:60]})",
                              f"zen:{src}:{r['target']}", src_ip=src, events={"source": "zenarmor", "ip": src}, count=r["hits"],
                              description=f"Zenarmor flagged traffic from {src} to {r['target']} as '{threat}' "
                                          f"({'blocked' if r['blocked'] else 'NOT blocked'}).")
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
                              f"dns_bad:{client}", src_ip=ip, count=len(domains), mode="max",
                              events={"source": "unbound", "ip": ip, "action": "block,drop"},
                              description=f"Blocked by a security blocklist: {', '.join(sorted(domains)[:15])}"
                                          + ("" if ip else f" {no_client}"))

    # ------------------------------------------------------ system rules ---
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
