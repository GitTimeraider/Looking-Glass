"""Detection engine: periodic SQL/heuristic rules that turn events into alerts."""
from __future__ import annotations

import asyncio
import logging
import math
import time
from collections import Counter, defaultdict
from typing import Any

from . import db
from .config import Settings
from .ingest import STATS
from .parsers.common import is_internal_ip, parse_networks

log = logging.getLogger(__name__)

SEVERITIES = ["info", "low", "medium", "high", "critical"]

SUSPICIOUS_OUT_PORTS = {
    23: "telnet", 445: "SMB", 135: "MS-RPC", 139: "NetBIOS", 3389: "RDP", 4444: "Metasploit default",
    5555: "ADB", 6667: "IRC", 6697: "IRC/TLS", 1337: "leet/backdoor", 31337: "back orifice", 9001: "Tor OR",
    9030: "Tor dir", 5900: "VNC", 1080: "SOCKS", 3128: "proxy", 8333: "Bitcoin", 3333: "mining pool",
    4242: "mining pool", 14444: "Monero pool", 25: "SMTP (spam?)",
}


async def raise_alert(rule: str, severity: str, title: str, fingerprint: str, description: str = "",
                      src_ip: str | None = None, dst_ip: str | None = None, data: dict | None = None,
                      count: int = 1, mode: str = "add") -> None:
    """Create an alert or update the matching open one (dedupe by fingerprint within 24h)."""
    pool = db.pool()
    row = await pool.fetchrow(
        "SELECT id, severity FROM alerts WHERE fingerprint = $1 AND status <> 'closed' "
        "AND last_seen > now() - interval '24 hours' ORDER BY id DESC LIMIT 1", fingerprint)
    if row:
        sev = max(row["severity"], severity, key=SEVERITIES.index)
        count_sql = "count + $2" if mode == "add" else "GREATEST(count, $2)"
        await pool.execute(
            f"UPDATE alerts SET last_seen = now(), count = {count_sql}, severity = $3, description = $4, data = $5 WHERE id = $1",
            row["id"], count, sev, description, data)
        return
    await pool.execute(
        "INSERT INTO alerts (rule, severity, title, description, src_ip, dst_ip, count, fingerprint, data) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        rule, severity, title, description, src_ip, dst_ip, count, fingerprint, data)
    log.info("ALERT [%s] %s", severity, title)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


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
        new = await pool.fetchval(
            "INSERT INTO devices (mac, ip, hostname, vendor, interface, sources, lease_type, lease_expires, online) "
            "VALUES ($1, $2, $3, $4, $5, ARRAY[$6::text], $7, $8, $9) "
            "ON CONFLICT (mac) DO UPDATE SET ip = COALESCE(EXCLUDED.ip, devices.ip), "
            "hostname = COALESCE(EXCLUDED.hostname, devices.hostname), vendor = COALESCE(EXCLUDED.vendor, devices.vendor), "
            "interface = COALESCE(EXCLUDED.interface, devices.interface), "
            "sources = (SELECT array_agg(DISTINCT s) FROM unnest(devices.sources || EXCLUDED.sources) s), "
            "lease_type = COALESCE(EXCLUDED.lease_type, devices.lease_type), "
            "lease_expires = COALESCE(EXCLUDED.lease_expires, devices.lease_expires), "
            "online = devices.online OR EXCLUDED.online, last_seen = now() "
            "RETURNING (xmax = 0)", d["mac"], d.get("ip"), d.get("hostname") or None, d.get("vendor") or None,
            d.get("interface") or None, origin, d.get("lease_type"), d.get("lease_expires"), bool(d.get("online")))
        if new and not first_run:
            await raise_alert(
                "new_device", "low", f"New device on network: {d['mac']} ({d.get('hostname') or d.get('ip') or '?'})",
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
            sev = "high" if internal or r["ports"] >= 100 else "medium"
            await raise_alert(
                "port_scan", sev, f"{'Internal' if internal else 'External'} port scan from {ip} ({r['ports']} ports)",
                f"port_scan:{ip}", src_ip=ip, count=r["hits"], mode="max",
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
                "host_sweep", "high" if self.internal(ip) else "medium",
                f"Host sweep from {ip} on port {r['dst_port']} ({r['hosts']} hosts)", f"host_sweep:{ip}:{r['dst_port']}",
                src_ip=ip, count=r["hits"], mode="max",
                description=f"{ip} tried port {r['dst_port']} on {r['hosts']} different hosts within 10 minutes.")

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
            await raise_alert(
                "internal_blocked_outbound", "medium", f"Internal host {ip} blocked towards {r['dsts']} destinations",
                f"int_blocked:{ip}", src_ip=ip, count=r["hits"], mode="max",
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
            await raise_alert(
                "suspicious_outbound_port", "medium" if passed else "low",
                f"{src} → {dst}:{r['dst_port']} ({SUSPICIOUS_OUT_PORTS[r['dst_port']]}) {'ALLOWED' if passed else r['action']}",
                f"susp_port:{src}:{r['dst_port']}", src_ip=src, dst_ip=dst, count=r["hits"],
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
            await raise_alert(
                "brute_force", "high", f"Brute force against {r['source'].upper()} from {ip} ({r['hits']} failures)",
                f"brute_force:{r['source']}:{ip}", src_ip=ip, count=r["hits"], mode="max",
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
                await raise_alert(
                    "success_after_failures", "critical",
                    f"Successful {r['source']} login for '{r['username']}' from {ip} after {r['failures']} failures",
                    f"succ_after_fail:{ip}:{r['username']}", src_ip=ip, mode="max",
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
            await raise_alert(
                "admin_login", "info" if internal else "high",
                f"{'Login' if internal else 'Login from EXTERNAL address'}: '{r['username']}' via {r['program'] or r['source']} from {ip}",
                f"login:{ip}:{r['username']}", src_ip=ip, count=r["n"],
                description="Administrative login to the firewall." + ("" if internal else " The source is a public IP address."))
        await self._commit("ext_login", current)

    async def config_changes(self) -> None:
        last, current = await self._watermark("config")
        rows = await db.pool().fetch(
            "SELECT host, program, message, ts FROM events WHERE id > $1 AND id <= $2 AND action = 'config_change' LIMIT 50", last, current)
        for r in rows:
            await raise_alert("config_change", "info", f"Configuration change on {r['host'] or 'firewall'}",
                              f"config:{r['host']}", description=r["message"][:1000])
        await self._commit("config", current)

    # --------------------------------------------------------- web rules ---
    async def web_attacks(self) -> None:
        last, current = await self._watermark("web_attacks")
        rows = await db.pool().fetch(
            "SELECT src_ip, tag, count(*) AS hits, array_agg(DISTINCT message) AS samples FROM ("
            "  SELECT src_ip, message, jsonb_array_elements_text(data->'tags') AS tag FROM events "
            "  WHERE id > $1 AND id <= $2 AND source = 'nginx' AND jsonb_typeof(data->'tags') = 'array' "
            "  AND jsonb_array_length(data->'tags') > 0) t GROUP BY src_ip, tag", last, current)
        for r in rows:
            ip = str(r["src_ip"]) if r["src_ip"] else "unknown"
            sev = "high" if r["tag"] in ("rce", "sqli") else "medium" if r["tag"] in ("path_traversal", "sensitive_file", "xss") else "low"
            await raise_alert(
                "web_attack", sev, f"Web attack ({r['tag']}) from {ip} on nginx", f"web:{ip}:{r['tag']}", src_ip=r["src_ip"] and ip,
                count=r["hits"], description=f"{r['hits']} request(s) matching '{r['tag']}'. Samples: {list(r['samples'])[:5]}")
        await self._commit("web_attacks", current)

    async def web_scanner(self) -> None:
        rows = await db.pool().fetch(
            "SELECT src_ip, count(*) AS hits, count(DISTINCT data->>'path') AS paths FROM events "
            "WHERE source = 'nginx' AND ts > now() - interval '10 minutes' AND action ~ '^http_4' AND src_ip IS NOT NULL "
            "GROUP BY src_ip HAVING count(*) >= 50")
        for r in rows:
            ip = str(r["src_ip"])
            await raise_alert("web_scanner", "medium", f"Web scanning from {ip} ({r['hits']} 4xx responses)",
                              f"web_scan:{ip}", src_ip=ip, count=r["hits"], mode="max",
                              description=f"{ip} produced {r['hits']} client errors over {r['paths']} distinct paths in 10 minutes "
                                          "(directory brute forcing / vulnerability scanning).")

    # -------------------------------------------------- 3rd party sources ---
    async def ids_alerts(self) -> None:
        last, current = await self._watermark("ids")
        rows = await db.pool().fetch(
            "SELECT src_ip, dst_ip, message, min(severity) AS sev, count(*) AS hits, max(data->>'classification') AS cls "
            "FROM events WHERE id > $1 AND id <= $2 AND source = 'suricata' AND action IS NOT NULL "
            "GROUP BY src_ip, dst_ip, message", last, current)
        for r in rows:
            sev = {0: "critical", 1: "critical", 2: "high", 3: "medium", 4: "low"}.get(r["sev"], "low")
            await raise_alert("ids", sev, f"IDS: {r['message']}", f"ids:{r['src_ip']}:{r['message']}",
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
            await raise_alert("crowdsec", "high" if internal else "medium",
                              f"CrowdSec: {r['scenario']} from {ip}{' (INTERNAL)' if internal else ''}",
                              f"crowdsec:{ip}:{r['scenario']}", src_ip=ip, count=r["hits"],
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
                await raise_alert(
                    "threat_intel_outbound", "high", f"Internal host {src} contacted threat-intel listed IP {dst}",
                    f"qf_out:{src}:{dst}", src_ip=src, dst_ip=dst, count=r["hits"],
                    description=f"Q-Feeds blocked traffic from internal {src} to known malicious {dst}:{r['dst_port']}. "
                                "The internal host may be compromised (C2 / malware beacon). Investigate it.")
            elif src:
                inbound[src] += r["hits"]
        for src, hits in inbound.items():
            if hits >= 20:
                await raise_alert("threat_intel_inbound", "low", f"Threat-intel listed IP {src} is probing you",
                                  f"qf_in:{src}", src_ip=src, count=hits,
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
            sev = "high" if any(w in threat.lower() for w in ("malware", "botnet", "phishing", "command", "c2", "ransom", "crypto")) else "medium"
            await raise_alert("zenarmor_threat", sev, f"Zenarmor: {src} → {r['target']} ({threat[:60]})",
                              f"zen:{src}:{r['target']}", src_ip=src, count=r["hits"],
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
        bad_block: dict[str, set[str]] = defaultdict(set)
        for r in rows:
            client = str(r["src_ip"]) if r["src_ip"] else "?"
            domain = r["domain"]
            reg = registered_domain(domain)
            sub = domain[: -len(reg)].rstrip(".") if domain.endswith(reg) else ""
            if sub:
                per_client_sub[(client, reg)].add(sub)
            label = domain.split(".")[0]
            # DGA domains look like <random>.<tld>; deeper names are covered by the tunneling check
            if domain.count(".") <= 2 and len(label) >= 16 and entropy(label) >= 3.6 and not label.startswith("xn--"):
                dga[client].add(domain)
            if (r["rcode"] or "").upper() == "NXDOMAIN" or r["action"] == "nxdomain":
                nx[client] += 1
            if r["action"] in ("block", "drop") and any(w in (r["bl"] or "").lower() for w in ("malware", "phish", "threat", "crypto", "ransom", "botnet", "c2", "abuse", "qfeed", "q-feed")):
                bad_block[client].add(domain)
        for (client, reg), subs in per_client_sub.items():
            long_subs = [s for s in subs if len(s) > 30]
            if len(subs) >= 150 and len(long_subs) >= 50:
                await raise_alert("dns_tunnel", "high", f"Possible DNS tunneling: {client} → *.{reg} ({len(subs)} unique subdomains)",
                                  f"dns_tunnel:{client}:{reg}", src_ip=client if client != "?" else None, count=len(subs), mode="max",
                                  description=f"{client} queried {len(subs)} unique subdomains of {reg} in 10 minutes, "
                                              f"{len(long_subs)} longer than 30 chars. Samples: {long_subs[:5]}")
        for client, domains in dga.items():
            if len(domains) >= 8:
                await raise_alert("dns_dga", "medium", f"Possible DGA/malware DNS from {client} ({len(domains)} random-looking domains)",
                                  f"dns_dga:{client}", src_ip=client if client != "?" else None, count=len(domains), mode="max",
                                  description=f"High-entropy domain names queried by {client}: {sorted(domains)[:10]}")
        for client, n in nx.items():
            if n >= 150:
                await raise_alert("dns_nxdomain", "medium", f"{client} produced {n} NXDOMAIN answers in 10 minutes",
                                  f"dns_nx:{client}", src_ip=client if client != "?" else None, count=n, mode="max",
                                  description="Large amounts of non-existent domain lookups are typical for DGA malware or misconfiguration.")
        for client, domains in bad_block.items():
            await raise_alert("dns_malicious_blocked", "high", f"{client} tried to resolve {len(domains)} malicious domain(s)",
                              f"dns_bad:{client}", src_ip=client if client != "?" else None, count=len(domains), mode="max",
                              description=f"Blocked by a security blocklist: {sorted(domains)[:15]}")

    # ------------------------------------------------------ system rules ---
    async def system_health(self) -> None:
        gws = await db.get_snapshot("gateways") or []
        for gw in gws:
            status = str(gw.get("status", "")).lower()
            if status in ("down", "force_down") or str(gw.get("status_translated", "")).lower() == "offline":
                await raise_alert("gateway_down", "medium", f"Gateway {gw.get('name')} is DOWN",
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
                await raise_alert("service_stopped", "low", f"Service '{svc.get('name')}' is not running",
                                  f"svc:{svc.get('name')}", description=str(svc.get("description", "")))
        fw = await db.get_snapshot("firmware") or {}
        if isinstance(fw, dict) and fw.get("status") in ("update", "upgrade"):
            await raise_alert("firmware", "low", "OPNsense firmware updates available", "firmware",
                              description=str(fw.get("status_msg", "")))

    async def log_silence(self) -> None:
        if STATS.received:
            self._last_events_at = max(self._last_events_at, max(STATS.senders.values(), default=0))
        if STATS.received and time.time() - self._last_events_at > 900:
            await raise_alert("log_silence", "medium", "No syslog received from OPNsense for 15+ minutes", "log_silence",
                              description="Log forwarding stopped. Could be an outage, a reboot, a network problem or log tampering.")
