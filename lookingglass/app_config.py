"""Application settings managed in the web UI and stored in the database (secrets encrypted).

Values are applied onto the shared ``Settings`` object, so the rest of the code keeps reading
``settings.opnsense_url`` etc. ``VERSION`` increments on every change; long-running components compare
``signature(group)`` to restart themselves when their group changed.
"""
from __future__ import annotations

import ipaddress
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
    kind: str  # str | secret | bool | int | choice | text
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
    Field("ai_timeout", "ai", "Request timeout (seconds)", "int", "", min=10, max=1800),
    Field("ai_daily_report", "ai", "Daily AI report", "bool", "Write an AI-analysed 24h report every morning (Reports page)."),
    Field("ai_daily_report_hour", "ai", "Daily report hour (local time)", "int", "", min=0, max=23),
    # Zenarmor
    Field("zenarmor_es_user", "zenarmor", "Stream username", "str", "Optional basic auth; must match Zenarmor's streaming username."),
    Field("zenarmor_es_password", "zenarmor", "Stream password", "secret", "Must match Zenarmor's streaming password."),
    Field("zenarmor_es_allowed", "zenarmor", "Allowed senders", "str",
          "Comma separated IPs/CIDRs allowed to stream (empty = same as syslog allowed senders).", placeholder="192.168.1.1"),
    # ingest
    Field("syslog_allowed_senders", "ingest", "Syslog allowed senders", "str",
          "Comma separated IPs/CIDRs (your OPNsense). Empty accepts everyone - not recommended.", placeholder="192.168.1.1"),
    Field("internal_networks", "ingest", "Extra internal networks", "str",
          "CIDRs treated as internal besides RFC1918/CGNAT/ULA, e.g. public ranges you own.", placeholder="203.0.113.0/28"),
    Field("timezone", "ingest", "Time zone", "str", "IANA name; used for syslog timestamps without zone and daily reports.",
          placeholder="Europe/Amsterdam"),
    # data
    Field("retention_days", "data", "Keep events (days)", "int", "", min=1, max=3650),
    Field("metrics_retention_days", "data", "Keep metrics (days)", "int", "", min=1, max=3650),
    Field("detection_interval", "data", "Detection interval (seconds)", "int", "", min=10, max=3600),
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
    v = "" if value is None else str(value).strip()
    if f.kind == "choice" and v not in f.choices:
        raise SettingsError(f"{f.label}: must be one of {', '.join(f.choices)}")
    if f.key in ("opnsense_url", "ai_base_url") and v and not v.startswith(("http://", "https://")):
        raise SettingsError(f"{f.label}: must start with http:// or https://")
    if f.key in ("syslog_allowed_senders", "internal_networks", "zenarmor_es_allowed") and v:
        for part in v.split(","):
            try:
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
