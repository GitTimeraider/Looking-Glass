"""Alert filters: stop (or auto-close) alerts by severity, rule, text and IP / network.

Logic:
* inside one condition it is always OR: any ticked rule, any listed IP / network; the text condition has its own
  choice: any of the terms (OR) or all of them (AND);
* between the filled-in conditions of one filter: ALL (AND, default) or ANY (OR) - the filter's ``match_mode``;
* between filters: OR - an alert is stopped when any enabled filter matches, so "(A and B) or C" is two filters.
Empty conditions are ignored; a filter without any condition is refused. Filters are cached and re-read after every
change made in the web UI.
"""
from __future__ import annotations

import ipaddress
import time
from typing import Any

from . import db

SEVERITIES = ["info", "low", "medium", "high", "critical"]
ACTIONS = ("suppress", "close")
MODES = ("all", "any")

# every rule that can raise an alert, grouped for the settings page
RULES: dict[str, list[tuple[str, str]]] = {
    "OPNsense firewall": [("port_scan", "Port scan"), ("host_sweep", "Host sweep"),
                          ("internal_blocked_outbound", "Internal host blocked outbound"),
                          ("suspicious_outbound_port", "Suspicious outbound port (Tor, IRC, RDP …)")],
    "Logins & VPN": [("brute_force", "Brute force"), ("success_after_failures", "Login after failed attempts"),
                     ("admin_login", "Login (admin GUI / SSH / API / VPN)"), ("config_change", "Configuration change")],
    "Web server (nginx)": [("web_attack", "Web attack pattern"), ("web_scanner", "Web scanning (many 4xx)")],
    "IDS / CrowdSec / Q-Feeds / Zenarmor": [("ids", "Suricata IDS"), ("crowdsec", "CrowdSec"),
                                            ("threat_intel_outbound", "Device contacted a threat-intel address"),
                                            ("threat_intel_inbound", "Threat-intel address probing you"),
                                            ("zenarmor_threat", "Zenarmor threat")],
    "DNS": [("dns_tunnel", "DNS tunneling"), ("dns_dga", "DGA / random domains"), ("dns_nxdomain", "NXDOMAIN storm"),
            ("dns_malicious_blocked", "Malicious domain looked up")],
    "Devices": [("new_device", "New device")],
    "OPNsense system": [("gateway_down", "Gateway down"), ("gateway_degraded", "Gateway degraded"),
                        ("resource", "Resource usage high"), ("service_stopped", "Service stopped"),
                        ("firmware", "Firmware updates available"), ("log_silence", "Logs stopped arriving")],
    "UniFi": [("unifi_device_offline", "AP / switch offline"), ("unifi_evil_twin", "Foreign AP with your Wi-Fi name"),
              ("unifi_rogue_dhcp", "Rogue DHCP server"), ("unifi_unreachable", "Controller unreachable")],
    "Unraid": [("unraid_array", "Array problem"), ("unraid_disk", "Disk problem"), ("unraid_disk_errors", "Disk errors"),
               ("unraid_disk_temp", "Disk temperature"), ("unraid_smart", "SMART"), ("unraid_parity", "Parity check"),
               ("unraid_zfs", "ZFS problem"), ("unraid_temp", "Temperature"), ("unraid_ups", "UPS"),
               ("unraid_container_down", "Container stopped"), ("unraid_notification", "Unraid notification"),
               ("unraid_unreachable", "Server unreachable")],
}
RULE_NAMES = {r for group in RULES.values() for r, _ in group}

_cache: dict[str, Any] = {"at": 0.0, "filters": []}


def invalidate() -> None:
    _cache["at"] = 0.0


def clean(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate a filter coming from the web UI; raises ValueError with a readable message."""
    max_sev = payload.get("max_severity") or None
    if max_sev not in (None, *SEVERITIES):
        raise ValueError("unknown severity")
    rules = sorted({str(r) for r in payload.get("rules") or [] if str(r).strip()})
    if any(len(r) > 60 for r in rules):
        raise ValueError("rule name too long")
    contains = ", ".join(terms(payload.get("contains")))[:300] or None
    match_mode = payload.get("match_mode") or "all"
    text_mode = payload.get("text_mode") or "any"
    if match_mode not in MODES or text_mode not in MODES:
        raise ValueError("unknown match mode")
    nets = parse_nets(payload.get("networks"))
    action = payload.get("action") or "suppress"
    if action not in ACTIONS:
        raise ValueError("unknown action")
    if not (max_sev or rules or contains or nets):
        raise ValueError("Fill in at least one condition - an empty filter would stop every alert.")
    return {"name": str(payload.get("name") or "").strip()[:100] or None, "enabled": bool(payload.get("enabled", True)),
            "max_severity": max_sev, "rules": rules, "contains": contains,
            "networks": ", ".join(str(n) for n in nets) or None, "action": action, "match_mode": match_mode,
            "text_mode": text_mode}


def terms(value: Any) -> list[str]:
    """'wpad, crowdsecurity/http-probing' -> two terms (comma separated)."""
    return [t.strip() for t in str(value or "").split(",") if t.strip()]


def parse_nets(value: Any) -> list[ipaddress._BaseNetwork]:
    out = []
    for part in str(value or "").replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(ipaddress.ip_network(part, strict=False))
        except ValueError as exc:
            raise ValueError(f"'{part}' is not an IP address or network (e.g. 192.168.1.20 or 192.168.30.0/24)") from exc
    return out


def matches(f: dict[str, Any], rule: str, severity: str, title: str, description: str,
            src_ip: str | None, dst_ip: str | None) -> bool:
    results: list[bool] = []  # one per filled-in condition
    if f.get("max_severity"):
        results.append(SEVERITIES.index(severity) <= SEVERITIES.index(f["max_severity"]))
    if f.get("rules"):
        results.append(rule in f["rules"])
    if f.get("contains"):
        text = f"{title}\n{description}".lower()
        found = [t.lower() in text for t in terms(f["contains"])]
        results.append(all(found) if f.get("text_mode") == "all" else any(found))
    if f.get("networks"):
        nets = f.get("_nets") or parse_nets(f["networks"])
        ips = []
        for ip in (src_ip, dst_ip):
            try:
                ips.append(ipaddress.ip_address(str(ip))) if ip else None
            except ValueError:
                pass
        results.append(any(ip in n for ip in ips for n in nets if ip.version == n.version))
    if not results:
        return False
    return any(results) if f.get("match_mode") == "any" else all(results)


async def _filters() -> list[dict[str, Any]]:
    if time.monotonic() - _cache["at"] > 60:
        rows = await db.pool().fetch("SELECT * FROM alert_filters WHERE enabled ORDER BY id")
        filters = []
        for r in rows:
            f = dict(r)
            try:
                f["_nets"] = parse_nets(f.get("networks"))
            except ValueError:
                continue
            filters.append(f)
        _cache.update(at=time.monotonic(), filters=filters)
    return _cache["filters"]


async def check(rule: str, severity: str, title: str, description: str, src_ip: str | None,
                dst_ip: str | None) -> dict[str, Any] | None:
    """The first enabled filter matching this alert (its hit counter is updated), or None."""
    try:
        filters = await _filters()
    except Exception:  # noqa: BLE001 - table missing during an upgrade etc.: never lose alerts because of a filter
        return None
    for f in filters:
        if matches(f, rule, severity, title, description, src_ip, dst_ip):
            await db.pool().execute("UPDATE alert_filters SET hits = hits + 1, last_hit = now() WHERE id = $1", f["id"])
            return f
    return None
