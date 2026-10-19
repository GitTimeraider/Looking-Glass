"""Configuration.

Two kinds of settings live on the same object:

* **Infrastructure**: how the container runs - listen ports, reverse proxy, log level. These come from environment
  variables (or ``<NAME>_FILE`` for Docker secrets) and need a restart. The database connection and the first
  account can be given here too, but normally the first-start wizard in the web UI asks for them.
* **Application** (everything in ``app_config.FIELDS``): OPNsense / AI / Zenarmor credentials, retention, detection
  tuning ... These are edited in the web UI (Settings), stored in the database (secrets encrypted) and applied
  live. Environment values for them are only imported once on first start, then ignored.
"""
from __future__ import annotations

import logging
import os
from functools import lru_cache
from urllib.parse import quote

from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger(__name__)


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
    zenarmor_es_port: int = 9200  # Zenarmor Elasticsearch-compatible receiver port, 0 disables
    log_level: str = "INFO"

    # ================ application (web UI -> Settings, database) ============
    # Defaults below; see app_config.FIELDS for labels and help texts.
    timezone: str = "UTC"
    time_format: str = "24h"
    dns_ignore_domains: str = ""
    syslog_allowed_senders: str = ""
    internal_networks: str = ""
    zenarmor_es_user: str = ""
    zenarmor_es_password: str = ""
    zenarmor_es_allowed: str = ""
    opnsense_url: str = ""
    opnsense_api_key: str = ""
    opnsense_api_secret: str = ""
    opnsense_verify_ssl: bool = False
    opnsense_ca_pem: str = ""
    poll_interval: int = 60
    firewall_log_pull: str = "auto"
    unbound_query_pull: bool = True
    crowdsec_pull: bool = True
    qfeeds_pull: bool = True
    ids_pull: bool = True
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
    ai_daily_report: bool = False
    ai_daily_report_hour: int = 7
    geoip_db: str = "/data/GeoLite2-City.mmdb"
    retention_days: int = 30
    metrics_retention_days: int = 90
    detection_interval: int = 60

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
