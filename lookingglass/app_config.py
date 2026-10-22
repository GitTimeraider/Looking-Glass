"""Application settings managed in the web UI and stored in the database (secrets encrypted).

Values are applied onto the shared ``Settings`` object, so the rest of the code keeps reading
``settings.opnsense_url`` etc. ``VERSION`` increments on every change; long-running components compare
``signature(group)`` to restart themselves when their group changed.
"""
from __future__ import annotations

import ipaddress
import re
import logging
import os
from dataclasses import dataclass, field
from typing import Any
from zoneinfo import ZoneInfo

from . import crypto, db
from .config import Settings

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Field:
    key: str
    group: str
    label: str
    kind: str  # str | secret | bool | int | choice | text | list (one entry per line in the UI, stored ', ' separated)
    help: str = ""
    choices: tuple[str, ...] = ()
    min: int | None = None
    max: int | None = None
    placeholder: str = ""


GROUPS = {
    "opnsense": "OPNsense",
    "unifi": "UniFi",
    "email": "Email",
    "ai": "AI analyst",
    "zenarmor": "Zenarmor stream",
    "ingest": "Log ingestion & network",
    "data": "Data & detection",
    "display": "Display",
    "behavior": "Behaviour & ML",
    "intel": "Threat intel & traps",
}

FIELDS: list[Field] = [
    # OPNsense
    Field("opnsense_url", "opnsense", "OPNsense URL", "str", "Address of the OPNsense web GUI, add :port if not 443.",
          placeholder="https://192.168.1.1"),
    Field("opnsense_api_key", "opnsense", "API key", "secret", "System › Access › Users › (user) › API keys › + (the 'key' line)."),
    Field("opnsense_api_secret", "opnsense", "API secret", "secret", "The 'secret' line of the same downloaded file."),
    Field("opnsense_verify_ssl", "opnsense", "Verify TLS certificate", "bool",
          "Off accepts OPNsense's self-signed certificate. On requires a trusted certificate or the CA below."),
    Field("opnsense_ca_pem", "opnsense", "Custom CA certificate (PEM)", "text",
          "Optional: paste the CA that signed the OPNsense GUI certificate (System › Trust › Authorities › download)."),
    Field("poll_interval", "opnsense", "Poll interval (seconds)", "int", "How often system state and metrics are pulled from OPNsense and Unraid (logs, leases, firmware etc. have their own fixed intervals).", min=15, max=3600),
    Field("firewall_log_pull", "opnsense", "Pull firewall log via API", "choice",
          "auto = only when no filterlog arrives via syslog.", choices=("auto", "always", "never")),
    Field("unbound_query_pull", "opnsense", "Pull Unbound DNS queries", "bool", "Needs Reporting › Settings › Unbound DNS statistics."),
    Field("crowdsec_pull", "opnsense", "Pull CrowdSec alerts & decisions", "bool"),
    Field("qfeeds_pull", "opnsense", "Pull Q-Feeds events", "bool"),
    Field("ids_pull", "opnsense", "Pull Suricata IDS alerts", "bool"),
    Field("nginx_pull", "opnsense", "Pull nginx access / error logs", "bool",
          "nginx plugin: its access logs are never sent by OPNsense remote syslog, so they are read via the API."),
    Field("vpn_pull", "opnsense", "Pull VPN status (WireGuard, OpenVPN, IPsec)", "bool",
          "Peers, handshakes, sessions and traffic. WireGuard does not log connections, so this is the only source."),
    # UniFi
    Field("unifi_url", "unifi", "UniFi controller URL", "str",
          "UniFi OS console (UDM, UCG, Cloud Key Gen2+, UniFi OS Server): https://<ip>. "
          "Self-hosted Network Application: https://<ip>:8443.", placeholder="https://192.168.1.2"),
    Field("unifi_api_key", "unifi", "API key", "secret",
          "UniFi Network › Settings › Control Plane › Integrations › Create API key. Recommended (read-only use)."),
    Field("unifi_username", "unifi", "Username (instead of an API key)", "str",
          "Only when no API key is possible (older self-hosted versions): a local admin with a View Only role, no MFA."),
    Field("unifi_password", "unifi", "Password", "secret", "Password of that local account."),
    Field("unifi_site", "unifi", "Site", "str", "Site name as in the URL (…/manage/<site>/…), usually 'default'.",
          placeholder="default"),
    Field("unifi_verify_ssl", "unifi", "Verify TLS certificate", "bool", "Off accepts the controller's self-signed certificate."),
    Field("unifi_poll_interval", "unifi", "Poll interval (seconds)", "int",
          "Devices, clients and health. Events and rogue APs follow every 2 minutes.", min=30, max=3600),
    Field("unifi_events", "unifi", "Collect UniFi events", "bool",
          "Client connects / roams, AP / switch offline, rogue APs - shown in Event search and the UniFi dashboard."),
    # email
    Field("smtp_host", "email", "SMTP server", "str", "Mail server that sends the notifications, e.g. smtp.gmail.com, "
          "smtp.office365.com, your provider's server or a local relay.", placeholder="smtp.example.com"),
    Field("smtp_port", "email", "Port", "int", "587 with STARTTLS (most common), 465 with SSL/TLS, 25 without encryption.",
          min=1, max=65535),
    Field("smtp_security", "email", "Encryption", "choice", "starttls = upgrade to TLS on port 587; ssl = TLS from the start "
          "(port 465); none = only for a relay inside your network.", choices=("starttls", "ssl", "none")),
    Field("smtp_username", "email", "Username", "str", "Usually your full mail address; empty if the server needs no login."),
    Field("smtp_password", "email", "Password", "secret", "Gmail / Microsoft 365 with MFA: an app password."),
    Field("smtp_from", "email", "Sender address", "str", "From address of the notifications (many providers require your "
          "own address).", placeholder="looking-glass@example.com"),
    Field("mail_link_url", "email", "Looking Glass address for links", "str", "How you open Looking Glass in the browser - "
          "used for the links in mails.", placeholder="http://192.168.1.10:8080"),
    # AI
    Field("ai_base_url", "ai", "API base URL", "str",
          "Any OpenAI-compatible endpoint. Claude: https://api.anthropic.com/v1/ · OpenAI: https://api.openai.com/v1/ · "
          "Ollama: http://<host>:11434/v1/", placeholder="https://api.anthropic.com/v1/"),
    Field("ai_api_key", "ai", "API key", "secret", "Anthropic: console.anthropic.com › API keys."),
    Field("ai_model", "ai", "Model", "str", "e.g. claude-opus-5-5", placeholder="claude-opus-5-5"),
    Field("ai_max_tool_rounds", "ai", "Max tool rounds per question", "int", "", min=1, max=50),
    Field("ai_timeout", "ai", "Request timeout (seconds)", "int", "Per request to the model; also the longest "
          "pause allowed while an answer streams in.", min=10, max=1800),
    Field("ai_stream", "ai", "Stream answers", "bool", "Receive answers word by word. Keeps the connection busy, so "
          "gateways / proxies in front of the model (OpenRouter, LiteLLM, Cloudflare, nginx) don't cut long answers off "
          "with 504 Gateway Timeout. Switched off automatically if the endpoint can't stream."),
    Field("ai_daily_report", "ai", "Daily AI report", "bool", "Write an AI-analysed 24h report every morning (Reports page)."),
    Field("ai_daily_report_hour", "ai", "Daily report hour (local time)", "int", "", min=0, max=23),
    # Zenarmor
    Field("zenarmor_es_user", "zenarmor", "Stream username", "str", "Optional basic auth; must match Zenarmor's streaming username."),
    Field("zenarmor_es_password", "zenarmor", "Stream password", "secret", "Must match Zenarmor's streaming password."),
    Field("zenarmor_es_allowed", "zenarmor", "Allowed senders", "list",
          "IPs / CIDRs allowed to stream (empty = same as syslog allowed senders).", placeholder="192.168.1.1"),
    Field("zenarmor_blocked_alerts", "zenarmor", "Alert on traffic Zenarmor blocked", "choice",
          "threats = only when the blocked traffic was malware, botnet / command & control, phishing, ransomware or "
          "crypto mining (the device itself is probably infected); all = also policy / app category blocks (low); "
          "never = no alerts for blocked traffic at all, not even malware. Traffic Zenarmor flagged but did NOT block is "
          "always alerted.", choices=("threats", "all", "never")),
    # ingest
    Field("syslog_allowed_senders", "ingest", "Syslog allowed senders", "list",
          "IPs / CIDRs (your OPNsense). Empty accepts everyone - not recommended.", placeholder="192.168.1.1"),
    Field("internal_networks", "ingest", "Extra internal networks", "list",
          "CIDRs treated as internal besides RFC1918/CGNAT/ULA, e.g. public ranges you own.", placeholder="203.0.113.0/28"),
    Field("timezone", "ingest", "Time zone", "str", "IANA name; used for syslog timestamps without zone and daily reports.",
          placeholder="Europe/Amsterdam"),
    # behaviour & ML
    Field("behavior_enabled", "behavior", "Learn device behaviour", "bool", "Learn per device which countries, ports, "
          "domains, TLS programs and hours are normal, and alert on what is new or unusual."),
    Field("behavior_exclude", "behavior", "Never analyse these devices", "list", "IPs, CIDRs or MAC "
          "addresses skipped by ALL behaviour, anomaly and risk rules (e.g. a backup server, Looking Glass itself).",
          placeholder="192.168.1.10, 192.168.50.0/24, aa:bb:cc:dd:ee:ff"),
    Field("behavior_learn_days", "behavior", "Learning period (days)", "int", "How far back the normal behaviour of a "
          "device is taken from. Things not seen for longer count as new again.", min=3, max=90),
    Field("behavior_min_days", "behavior", "Quiet period for new devices (days)", "int", "A device is only judged after "
          "it has been seen for this many days - before that everything it does is new.", min=1, max=60),
    Field("behavior_stable_max", "behavior", "Predictable devices: max. new things per day", "int", "'New …' alerts "
          "only for devices that picked up at most this many new destinations per day while learning (cameras, TVs, "
          "plugs). PCs and phones that constantly reach new places are skipped. 0 = judge every device.", min=0, max=1000),
    Field("behavior_new_country", "behavior", "Alert: first contact with a new country", "bool"),
    Field("behavior_new_port", "behavior", "Alert: first use of a new port / protocol", "bool"),
    Field("behavior_new_domain", "behavior", "Alert: first lookup of a new domain", "bool"),
    Field("behavior_new_tls", "behavior", "Alert: new TLS program (JA3/JA4)", "bool", "Needs TLS records with JA3/JA4 "
          "from Suricata (eve) or Zenarmor."),
    Field("behavior_odd_hours", "behavior", "Alert: activity at hours the device is never active", "bool"),
    Field("behavior_peers", "behavior", "Compare with similar devices", "bool", "Devices of the same vendor form a "
          "group: something the others do too is not alerted; something none of them do weighs heavier."),
    Field("behavior_volume_factor", "behavior", "Alert: traffic N times the device's normal", "int", "Connections / "
          "data / DNS lookups in one hour compared to the device's median for that hour. 0 = off.", min=0, max=1000),
    Field("anomaly_ml_enabled", "behavior", "Machine learning (Isolation Forest)", "bool", "Scores every device-hour on "
          "8 features (connections, destinations, ports, countries, DNS, failed lookups, blocks, upload) against the "
          "device's own history and alerts on combinations that are rare. Runs locally, nothing leaves the server."),
    Field("anomaly_ml_sensitivity", "behavior", "Machine learning: sensitivity", "choice", "low = only hours rarer "
          "than 1 in 2000 normal hours with a feature 4+ deviations off; medium = 1 in 500, 3.5; high = 1 in 200, 3.",
          choices=("low", "medium", "high")),
    Field("seasonal_enabled", "behavior", "Unusual for this hour of the week", "bool", "Totals per hour (firewall "
          "blocks, failed logins, DNS, failed lookups, per log source) against the same hour in previous weeks."),
    Field("seasonal_sensitivity", "behavior", "Hour of the week: sensitivity", "int", "How many 'normal deviations' "
          "above usual before an alert (3 = sensitive, 10 = only big spikes).", min=2, max=30),
    Field("seasonal_ignore", "behavior", "Hour of the week: ignore metrics", "list", "Metric names from "
          "these alerts, e.g. blocks, dns, source:firewall.", placeholder="blocks, source:nginx"),
    Field("risk_enabled", "behavior", "Risk score per device / address", "bool", "Every alert adds points (info 1, low "
          "3, medium 8, high 20, critical 40; once per rule) that fade over time; one alert when the total is high."),
    Field("risk_threshold", "behavior", "Risk score: alert from", "int", "", min=10, max=1000),
    Field("risk_half_life", "behavior", "Risk score: half-life (hours)", "int", "After this many hours an alert counts "
          "half.", min=1, max=720),
    Field("risk_exclude", "behavior", "Risk score: skip these addresses", "list", "IPs / CIDRs."),
    Field("feedback_mode", "behavior", "Learn from 'false positive'", "choice", "suggest = show a suggestion on the "
          "Alerts page after repeated false positives; auto = also create a rule that lowers them to info (listed "
          "under Alert filters, undo there); off.", choices=("suggest", "auto", "off")),
    Field("feedback_min", "behavior", "False positives before learning", "int", "Same rule + same address closed as "
          "false positive this many times in 30 days.", min=2, max=50),
    # threat intel & traps
    Field("abusech_auth_key", "intel", "abuse.ch Auth-Key", "secret", "Free key for URLhaus, ThreatFox, Feodo Tracker "
          "and SSLBL: auth.abuse.ch › log in (e.g. with GitHub / Google) › Optional › Generate Auth-Key."),
    Field("intel_urlhaus", "intel", "URLhaus (malware download domains)", "bool"),
    Field("intel_threatfox", "intel", "ThreatFox (malware / C2 domains and IPs)", "bool"),
    Field("intel_feodo", "intel", "Feodo Tracker (botnet C2 servers)", "bool"),
    Field("intel_ja3", "intel", "SSLBL JA3 (malware TLS fingerprints)", "bool"),
    Field("intel_tor", "intel", "Tor detection", "choice", "outbound = devices connecting to the Tor network; both = "
          "also Tor exit nodes reaching your services; off.", choices=("outbound", "both", "off")),
    Field("intel_tor_allow", "intel", "Devices allowed to use Tor", "list", "IPs / CIDRs / MACs."),
    Field("intel_mining", "intel", "Crypto-mining pools", "bool", "Lookups of / connections to known mining pools."),
    Field("mining_domains", "intel", "Extra mining pool domains", "list", "Added to the built-in list."),
    Field("intel_allow", "intel", "Never flag these domains / IPs", "list", "Domains (incl. their subdomains) "
          "and IPs / CIDRs, for false positives in the feeds."),
    Field("nod_enabled", "intel", "Track newly seen domains", "bool", "Remembers the first time any device looks up a "
          "domain; beaconing and random-domain alerts to such a domain weigh heavier."),
    Field("nod_rdap", "intel", "Look up the registration date (RDAP)", "bool", "Asks the domain registries (rdap.org) "
          "when new domains were registered and alerts on lookups of very young domains. Sends those domain names to "
          "the registry."),
    Field("nod_young_days", "intel", "Young domain: registered less than (days)", "int", "", min=1, max=365),
    Field("nod_lookups_per_hour", "intel", "RDAP lookups per hour (max)", "int", "", min=1, max=1000),
    Field("canary_targets", "intel", "Canary addresses", "list", "IP, IP:port or "
          "CIDR that nothing should ever contact. The firewall must see (and log) that traffic: e.g. the firewall's own "
          "LAN address on unused ports (192.168.1.1:23) or an unused IP in ANOTHER VLAN - traffic inside one subnet "
          "never passes OPNsense.", placeholder="192.168.1.1:23\n192.168.1.1:445\n192.168.20.250"),
    Field("canary_exclude", "intel", "Canary: ignore these sources", "list", "e.g. your own network scanner."),
    Field("canary_internal_only", "intel", "Canary: only devices inside", "bool", "Off = also internet addresses "
          "(port forwards used as a honeypot)."),
    Field("exposure_watch", "intel", "Watch what is open to the internet", "bool", "Alerts on new / changed port "
          "forwards and firewall rules (OPNsense API; needs the 'Firewall: Rules' / 'NAT' read privileges)."),
    Field("arp_watch", "intel", "ARP spoofing detection", "bool", "OPNsense's ARP table and kernel messages: an IP "
          "flipping between devices, a device claiming the firewall's address, one device holding many IPs."),
    Field("arp_exclude", "intel", "ARP: ignore these IPs / MACs", "list", "e.g. failover (CARP / VRRP) addresses, "
          "Wi-Fi repeaters, VM hosts with bridged guests."),
    Field("arp_flips", "intel", "ARP: IP changes per hour before alerting", "int", "", min=2, max=100),
    # display
    Field("time_format", "display", "Time format", "choice", "24h = 14:05, 12h = 2:05 PM, browser = whatever your browser's "
          "language uses. Applies to the web UI, notification mails and the AI analyst's answers and reports (mails and "
          "AI use the Time zone under Ingestion & network; browser = 24h there).", choices=("24h", "12h", "browser")),
    Field("theme", "display", "Theme", "choice", "dark, light, or auto = follow the light / dark setting of the browser "
          "or operating system. Applies to everyone using this Looking Glass.", choices=("dark", "light", "auto")),
    Field("accent", "display", "Accent color", "choice", "Color of buttons, links and highlights; the background gets a "
          "light tint of it too (light + purple = lavender). The preview changes as you pick; Save to keep it.",
          choices=("blue", "indigo", "purple", "pink", "red", "orange", "green", "teal", "cyan", "gray")),
    # data
    Field("retention_days", "data", "Keep events (days)", "int", "", min=1, max=3650),
    Field("metrics_retention_days", "data", "Keep metrics (days)", "int", "", min=1, max=3650),
    Field("detection_interval", "data", "Detection interval (seconds)", "int", "", min=10, max=3600),
    Field("dns_ignore_domains", "data", "DNS: domains to ignore", "list",
          "Domains (subdomains included) the DNS checks - random-looking / DGA names, tunneling, NXDOMAIN "
          "storms - skip, e.g. CDNs or latency probes with random names. Logs and dashboards still show them.",
          placeholder="atoma.cloud, example-cdn.net"),
    Field("unraid_container_grace", "data", "Unraid: container alerts wait (minutes)", "int", "No 'container stopped' "
          "alert until the Unraid server has been up this long (after a reboot containers are still starting) and the "
          "container has been stopped this long. An open one closes by itself once the container has been running "
          "again this long.", min=1, max=240),
    Field("geoip_db", "data", "GeoIP database path", "str", "MaxMind GeoLite2-City or -Country .mmdb inside the data volume.",
          placeholder="/data/GeoLite2-City.mmdb"),
]
BY_KEY = {f.key: f for f in FIELDS}
SECRET_KEYS = {f.key for f in FIELDS if f.kind == "secret"}

# which groups restart which component
RESTART_GROUPS = {"unifi": ("unifi_url", "unifi_api_key", "unifi_username", "unifi_password", "unifi_site",
                            "unifi_verify_ssl", "unifi_poll_interval", "unifi_events"),
                  "opnsense": ("opnsense_url", "opnsense_api_key", "opnsense_api_secret", "opnsense_verify_ssl",
                               "opnsense_ca_pem", "poll_interval", "firewall_log_pull", "unbound_query_pull",
                               "crowdsec_pull", "qfeeds_pull", "ids_pull", "nginx_pull", "vpn_pull")}


@dataclass
class _State:
    version: int = 0
    defaults: dict[str, Any] = field(default_factory=dict)


STATE = _State()


class SettingsError(ValueError):
    pass


def _coerce(f: Field, value: Any) -> Any:
    if f.kind == "bool":
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on")
        return bool(value)
    if f.kind == "int":
        try:
            v = int(value)
        except (TypeError, ValueError) as exc:
            raise SettingsError(f"{f.label}: must be a number") from exc
        if (f.min is not None and v < f.min) or (f.max is not None and v > f.max):
            raise SettingsError(f"{f.label}: must be between {f.min} and {f.max}")
        return v
    if f.kind == "list":  # one entry per line (or comma separated): trimmed, duplicates dropped, stored ", " separated
        items = [p.strip() for p in re.split(r"[,;\n]+", "" if value is None else str(value))]
        value = ", ".join(dict.fromkeys(p for p in items if p))
    v = "" if value is None else str(value).strip()
    if f.kind == "choice" and v not in f.choices:
        raise SettingsError(f"{f.label}: must be one of {', '.join(f.choices)}")
    if f.key in ("opnsense_url", "ai_base_url") and v and not v.startswith(("http://", "https://")):
        raise SettingsError(f"{f.label}: must start with http:// or https://")
    if f.key in ("syslog_allowed_senders", "internal_networks", "zenarmor_es_allowed") and v:
        for part in v.split(","):
            try:  # an invalid line is named, nothing is saved
                ipaddress.ip_network(part.strip(), strict=False)
            except ValueError as exc:
                raise SettingsError(f"{f.label}: '{part.strip()}' is not an IP address or CIDR") from exc
    if f.key == "timezone" and v:
        try:
            ZoneInfo(v)
        except Exception as exc:  # noqa: BLE001
            raise SettingsError(f"{f.label}: unknown time zone '{v}'") from exc
    if f.key == "opnsense_ca_pem" and v and "BEGIN CERTIFICATE" not in v:
        raise SettingsError(f"{f.label}: paste a PEM certificate (-----BEGIN CERTIFICATE-----)")
    return v


async def load(settings: Settings) -> None:
    """Import legacy environment values once, then apply the stored values onto ``settings``."""
    pool = db.pool()
    if not STATE.defaults:
        STATE.defaults = {f.key: Settings.model_fields[f.key].default for f in FIELDS}
    rows = {r["key"]: r["value"] for r in await pool.fetch("SELECT key, value FROM app_settings")}
    imported = []
    for f in FIELDS:
        env_name = f.key.upper()
        if f.key not in rows and (os.environ.get(env_name) or os.environ.get(f"{env_name}_FILE")):
            current = getattr(settings, f.key)  # pydantic already read env / .env
            if current != STATE.defaults[f.key]:
                stored = crypto.encrypt(str(current)) if f.kind == "secret" else current
                await pool.execute("INSERT INTO app_settings (key, value) VALUES ($1, $2) ON CONFLICT DO NOTHING", f.key, stored)
                rows[f.key] = stored
                imported.append(env_name)
    if imported:
        log.warning("imported %s from the environment into the encrypted settings store. Remove these variables from "
                    "your compose/.env file - they are ignored from now on and are visible to anyone who can inspect "
                    "the container. Manage them under Settings in the web UI.", ", ".join(imported))
    # legacy file path setting -> CA PEM content
    if "opnsense_ca_pem" not in rows and os.environ.get("OPNSENSE_CA_FILE"):
        try:
            with open(os.environ["OPNSENSE_CA_FILE"], encoding="utf-8") as fh:
                rows["opnsense_ca_pem"] = fh.read()
            await pool.execute("INSERT INTO app_settings (key, value) VALUES ('opnsense_ca_pem', $1) ON CONFLICT DO NOTHING",
                               rows["opnsense_ca_pem"])
        except OSError:
            pass
    for f in FIELDS:
        raw = rows.get(f.key, STATE.defaults[f.key])
        value = crypto.decrypt(raw) if f.kind == "secret" and isinstance(raw, str) else raw
        setattr(settings, f.key, value)
    # encrypt any legacy plaintext secrets
    for key in SECRET_KEYS:
        if key in rows and isinstance(rows[key], str) and rows[key] and not crypto.is_encrypted(rows[key]):
            await pool.execute("UPDATE app_settings SET value = $2 WHERE key = $1", key, crypto.encrypt(rows[key]))
    STATE.version += 1


async def save(settings: Settings, changes: dict[str, Any]) -> list[str]:
    """Validate and store changes. Secrets: '' keeps the current value, None clears it. Returns changed keys."""
    pool = db.pool()
    changed = []
    clean: dict[str, Any] = {}
    for key, value in changes.items():
        f = BY_KEY.get(key)
        if f is None:
            raise SettingsError(f"unknown setting {key}")
        if f.kind == "secret":
            if value == "" or value is ...:
                continue  # unchanged
            clean[key] = "" if value is None else str(value).strip()
        else:
            clean[key] = _coerce(f, value)
    for key, value in clean.items():
        if value == getattr(settings, key):
            continue
        stored = crypto.encrypt(value) if key in SECRET_KEYS and value else value
        await pool.execute("INSERT INTO app_settings (key, value, updated_at) VALUES ($1, $2, now()) "
                           "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()", key, stored)
        setattr(settings, key, value)
        changed.append(key)
    if changed:
        STATE.version += 1
        log.info("settings changed: %s", ", ".join(changed))
    return changed


def public_view(settings: Settings) -> dict[str, Any]:
    """Settings for the UI: secrets are never returned, only whether they are set."""
    out = []
    for f in FIELDS:
        v = getattr(settings, f.key)
        item = {"key": f.key, "group": f.group, "label": f.label, "kind": f.kind, "help": f.help,
                "choices": list(f.choices), "min": f.min, "max": f.max, "placeholder": f.placeholder}
        if f.kind == "secret":
            item["is_set"] = bool(v)
        else:
            item["value"] = v
        out.append(item)
    return {"groups": GROUPS, "fields": out, "version": STATE.version}


def signature(settings: Settings, group: str) -> tuple:
    return tuple(getattr(settings, k) for k in RESTART_GROUPS[group])
