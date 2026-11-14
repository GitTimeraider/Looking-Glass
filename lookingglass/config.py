"""Configuration.

Two kinds of settings live on the same object:

* **Infrastructure**: how the container runs - listen ports, reverse proxy, log level. These come from environment
  variables (or ``<NAME>_FILE`` for Docker secrets) and need a restart. The database connection and the first
  account can be given here too, but normally the first-start wizard in the web UI asks for them.
* **Application** (everything in ``app_config.FIELDS``): OPNsense / AI credentials, retention, detection
  tuning ... These are edited in the web UI (Settings), stored in the database (secrets encrypted) and applied
  live. Environment values for them are only imported once on first start, then ignored.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any
from urllib.parse import quote
from zoneinfo import ZoneInfo

from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger(__name__)


# Shared hosting in the threat feeds (intel.SharedHosts). URLhaus / ThreatFox list malware URLs; a DNS lookup only shows
# the host name, so a URL on a host that many unrelated people use cannot be told apart from all the harmless visits.
# These are the defaults of two settings under Settings › Threat intel & traps (editable there).
# Sites: the domain and ALL its subdomains belong to the platform (raw.githubusercontent.com, cdn.discordapp.com ...).
SHARED_SITES = (
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "sourceforge.net", "codeberg.org", "gitee.com",
    "steamcommunity.com", "steampowered.com", "steamstatic.com",
    "discord.com", "discordapp.com", "discordapp.net", "discord.gg",
    "google.com", "googleusercontent.com", "googleapis.com", "gstatic.com", "youtube.com", "youtu.be",
    "dropbox.com", "dropboxusercontent.com", "mediafire.com", "mega.nz", "mega.io", "box.com", "wetransfer.com", "we.tl",
    "microsoft.com", "live.com", "onedrive.com", "1drv.ms", "office.com", "windows.net",
    "apple.com", "icloud.com", "amazon.com", "cloudflare.com", "archive.org", "jsdelivr.net", "unpkg.com",
    "telegram.org", "t.me", "telegram.me", "telegra.ph", "pastebin.com",
    "twitter.com", "x.com", "facebook.com", "instagram.com", "linkedin.com", "reddit.com", "vk.com",
    "bit.ly", "tinyurl.com",
)
# Endpoints: only this exact name is shared (cloud storage reached as endpoint/<bucket>/file); a name IN FRONT of it
# is one customer's own bucket / account (polarsteps.s3-eu-west-1.amazonaws.com) and is still matched - also below a
# shared site (<account>.blob.core.windows.net, <bucket>.storage.googleapis.com). * = one label (no dots).
SHARED_ENDPOINTS = (
    "s3.amazonaws.com", "s3-*.amazonaws.com", "s3.*.amazonaws.com", "s3.dualstack.*.amazonaws.com",
    "s3-website-*.amazonaws.com", "s3-website.*.amazonaws.com",
    "storage.googleapis.com", "*.core.windows.net",
    "*.digitaloceanspaces.com", "*.linodeobjects.com", "*.your-objectstorage.com",
    "s3.wasabisys.com", "s3.*.wasabisys.com", "s3.*.backblazeb2.com", "f*.backblazeb2.com",
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", validate_assignment=False)

    # ===================== infrastructure (environment) =====================
    # optional: without DATABASE_URL the first-start wizard in the web UI asks for the connection and stores it
    # encrypted in <data_dir>/database.conf (see db_config.py)
    database_url: str = ""
    data_dir: str = "/data"  # persistent volume: encryption key file, optional GeoIP database
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    # optional: creates the first account without the wizard (only used while no user exists)
    admin_user: str = "admin"
    admin_password: str = ""
    secret_key: str = ""  # session cookie signing key; generated and stored in the database if empty
    public_url: str = ""  # e.g. https://looking-glass.home.lan - used as WebAuthn origin (auto-detected if empty)
    webauthn_rp_id: str = ""  # passkey relying party id (defaults to the host name of public_url / the request)
    cookie_secure: bool = False  # set true when served over HTTPS
    syslog_enabled: bool = True
    syslog_host: str = "0.0.0.0"
    syslog_udp_port: int = 5514
    syslog_tcp_port: int = 5514
    log_level: str = "INFO"
    log_ai_requests: bool = False  # LOG_AI_REQUESTS=true: log every AI request and what started it

    # ================ application (web UI -> Settings, database) ============
    # Defaults below; see app_config.FIELDS for labels and help texts.
    timezone: str = "UTC"
    time_format: str = "24h"
    theme: str = "dark"
    accent: str = "blue"
    dns_ignore_domains: str = ""
    # behaviour & anomaly detection (Settings › Behaviour & ML)
    behavior_enabled: bool = True
    behavior_exclude: str = ""
    behavior_learn_days: int = 14
    behavior_min_days: int = 5
    behavior_stable_max: int = 3
    behavior_new_country: bool = True
    behavior_new_port: bool = True
    behavior_new_domain: bool = True
    behavior_new_tls: bool = True
    behavior_odd_hours: bool = True
    behavior_peers: bool = True
    behavior_volume_factor: int = 10
    anomaly_ml_enabled: bool = True
    anomaly_ml_sensitivity: str = "medium"
    seasonal_enabled: bool = True
    seasonal_sensitivity: int = 6
    seasonal_ignore: str = ""
    risk_enabled: bool = True
    risk_threshold: int = 60
    risk_half_life: int = 24
    risk_exclude: str = ""
    feedback_mode: str = "suggest"
    feedback_min: int = 3
    # threat intel & traps (Settings › Threat intel & traps)
    abusech_auth_key: str = ""
    intel_urlhaus: bool = True
    intel_threatfox: bool = True
    intel_feodo: bool = True
    intel_ja3: bool = True
    intel_tor: str = "outbound"
    intel_tor_allow: str = ""
    intel_mining: bool = True
    mining_domains: str = ""
    intel_allow: str = ""
    intel_shared_sites: str = ", ".join(SHARED_SITES)
    intel_shared_endpoints: str = ", ".join(SHARED_ENDPOINTS)
    intel_sources: str = ""
    nod_enabled: bool = True
    nod_rdap: bool = False
    nod_young_days: int = 30
    nod_lookups_per_hour: int = 60
    canary_targets: str = ""
    canary_exclude: str = ""
    canary_internal_only: bool = True
    exposure_watch: bool = True
    arp_watch: bool = True
    arp_exclude: str = ""
    arp_flips: int = 3
    syslog_allowed_senders: str = ""
    internal_networks: str = ""
    opnsense_url: str = ""
    opnsense_api_key: str = ""
    opnsense_api_secret: str = ""
    opnsense_verify_ssl: bool = False
    opnsense_ca_pem: str = ""
    poll_interval: int = 60
    firewall_log_pull: str = "auto"
    unbound_query_pull: bool = True
    crowdsec_pull: bool = True
    blocklist_aliases: str = "CrowdSec: crowdsec_blocklists, crowdsec6_blocklists\nQ-Feeds: __qfeeds_*"
    qfeeds_pull: bool = True
    ids_pull: bool = True
    ids_alert_priority: int = 3
    ids_ignore_sids: str = ""
    nginx_pull: bool = True
    vpn_pull: bool = True
    unifi_url: str = ""
    unifi_api_key: str = ""
    unifi_username: str = ""
    unifi_password: str = ""
    unifi_site: str = "default"
    unifi_verify_ssl: bool = False
    unifi_poll_interval: int = 60
    unifi_events: bool = True
    unifi_offline_grace: int = 10  # minutes
    backrest_url: str = ""  # with the port, e.g. http://192.168.1.10:9898
    backrest_username: str = ""
    backrest_password: str = ""
    backrest_verify_ssl: bool = False
    backrest_poll_interval: int = 300
    backrest_overdue_hours: int = 0  # 0 = from each plan's schedule
    backrest_alert_warnings: bool = True
    backrest_offline_grace: int = 15  # minutes
    bichon_url: str = ""  # with the port, e.g. http://192.168.1.10:15630
    bichon_token: str = ""  # a Bichon API token ("Metrics only" is enough)
    bichon_verify_ssl: bool = False
    bichon_poll_interval: int = 120
    bichon_overdue_hours: int = 0  # 0 = from each account's sync interval
    bichon_backup_overdue_hours: int = 0  # Bichon's own backup; 0 = no overdue alert (its schedule is not readable)
    bichon_alert_warnings: bool = True
    bichon_offline_grace: int = 15  # minutes
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    mail_link_url: str = ""
    ai_base_url: str = "https://api.anthropic.com/v1/"
    ai_api_key: str = ""
    ai_model: str = "claude-opus-5-5"
    ai_max_tool_rounds: int = 12
    ai_timeout: int = 300
    ai_stream: bool = True
    ai_privacy: bool = False
    ai_privacy_names: bool = True
    ai_privacy_terms: str = ""
    ai_privacy_keep: str = ""
    ai_privacy_avoid: str = ""
    ai_daily_report: bool = False
    ai_daily_report_hour: int = 7
    report_every_days: int = 1
    report_categories: str = "OPNsense, UniFi, Unraid, Backups"  # what the scheduled report covers (reports.CATEGORIES)
    report_mail_to: str = ""
    geoip_db: str = "/data/GeoLite2-City.mmdb"
    # container packages (Settings › Unraid servers › Container packages, packages.py)
    pkg_enabled: bool = False
    pkg_image_source: str = "auto"
    pkg_exclude: str = ""
    pkg_registry_host: str = "docker.io"
    pkg_registry_user: str = ""
    pkg_registry_password: str = ""
    pkg_syft_path: str = "syft"
    pkg_syft_args: str = ""
    pkg_tool_env: str = ""
    pkg_timeout: int = 30  # minutes per image
    retention_days: int = 30
    device_remove_days: int = 0
    metrics_retention_days: int = 90
    detection_interval: int = 60
    long_refresh_7d: int = 60  # minutes: 7-day dashboard / Overview results are counted again this often (periods.py)
    long_refresh_30d: int = 360  # minutes: the same for periods over 7 days
    long_keep_days: int = 7  # 7 / 30 day views not opened for this many days are no longer refreshed
    unraid_container_grace: int = 10  # minutes
    unraid_offline_grace: int = 10  # minutes
    unraid_unhealthy_minutes: int = 5  # a failing Docker health check alerts after this long (0 = off)
    unraid_restart_count: int = 5  # restarts in unraid_restart_minutes = "keeps restarting" (0 = off)
    unraid_restart_minutes: int = 15
    unraid_log_error_count: int = 50  # default log rule: error lines in unraid_log_error_minutes (0 = off)
    unraid_log_error_minutes: int = 10

    # legacy: only imported once into the Unraid server list (Settings -> Integrations)
    unraid_name: str = "Unraid"
    unraid_url: str = ""
    unraid_api_key: str = ""
    unraid_verify_ssl: bool = False
    unraid_docker_url: str = ""

    @property
    def opnsense_enabled(self) -> bool:
        return bool(self.opnsense_url and self.opnsense_api_key and self.opnsense_api_secret)

    @property
    def unifi_enabled(self) -> bool:
        return bool(self.unifi_url and (self.unifi_api_key or (self.unifi_username and self.unifi_password)))

    @property
    def backrest_enabled(self) -> bool:
        return bool(self.backrest_url)

    @property
    def bichon_enabled(self) -> bool:
        return bool(self.bichon_url and self.bichon_token)

    @property
    def backups_enabled(self) -> bool:
        """Any backup tool connected (Infrastructure › Backups, the reports' Backups part)."""
        return self.backrest_enabled or self.bichon_enabled

    @property
    def smtp_enabled(self) -> bool:
        return bool(self.smtp_host and self.smtp_from)

    @property
    def ai_enabled(self) -> bool:
        return bool(self.ai_base_url and self.ai_model and self.ai_api_key)


# Docker secrets: DATABASE_URL_FILE=/run/secrets/db_url etc.
_FILE_VARS = ("database_url", "admin_password", "secret_key")


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    for name in _FILE_VARS:
        path = os.environ.get(f"{name.upper()}_FILE")
        if path:
            try:
                with open(path, encoding="utf-8") as fh:
                    setattr(s, name, fh.read().strip())
            except OSError as exc:
                log.error("cannot read %s_FILE (%s): %s", name.upper(), path, exc)
    # DATABASE_PASSWORD_FILE: same secret file as POSTGRES_PASSWORD_FILE, injected into DATABASE_URL
    pw_file = os.environ.get("DATABASE_PASSWORD_FILE")
    if pw_file:
        try:
            with open(pw_file, encoding="utf-8") as fh:
                password = quote(fh.read().strip(), safe="")
            scheme, rest = s.database_url.split("://", 1)
            creds, host = rest.rsplit("@", 1)
            user = creds.split(":", 1)[0]
            s.database_url = f"{scheme}://{user}:{password}@{host}"
        except (OSError, ValueError) as exc:
            log.error("cannot use DATABASE_PASSWORD_FILE (%s): %s", pw_file, exc)
    return s


def local_time(s: Settings, dt: datetime | None = None, seconds: bool = False, date: bool = False) -> str:
    """``dt`` (default: now) in the configured time zone and time format (Settings › Display), e.g. "14:05" or
    "2:05 PM"; with ``date``: "2026-10-19 14:05"."""
    try:
        tz: Any = ZoneInfo(s.timezone or "UTC")
    except Exception:  # noqa: BLE001 - unknown zone name
        tz = timezone.utc
    t = (dt or datetime.now(timezone.utc)).astimezone(tz)
    fmt = ("%I:%M:%S %p" if seconds else "%I:%M %p") if s.time_format == "12h" else ("%H:%M:%S" if seconds else "%H:%M")
    out = t.strftime(fmt)
    if s.time_format == "12h":
        out = out.lstrip("0")
    return f"{t:%Y-%m-%d} {out}" if date else out


def time_style(s: Settings) -> str:
    """How times should be written in text for the user (AI prompts)."""
    zone = s.timezone or "UTC"
    clock = "12-hour clock with AM/PM (e.g. 2:05 PM)" if s.time_format == "12h" else "24-hour clock (e.g. 14:05)"
    return f"{zone} local time, {clock}"
