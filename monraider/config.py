"""Runtime configuration, read from environment variables (or a .env file)."""
from __future__ import annotations

import secrets
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- database -----------------------------------------------------------
    database_url: str = "postgresql://monraider:monraider@db:5432/monraider"

    # --- web UI -------------------------------------------------------------
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    admin_user: str = "admin"
    admin_password: str = ""  # empty -> random password is generated and logged at startup
    secret_key: str = ""  # session cookie signing key; random if empty (sessions reset on restart)
    timezone: str = "UTC"

    # --- syslog receiver ----------------------------------------------------
    syslog_enabled: bool = True
    syslog_host: str = "0.0.0.0"
    syslog_udp_port: int = 5514
    syslog_tcp_port: int = 5514
    # comma separated list of IPs allowed to send syslog; empty = accept everyone
    syslog_allowed_senders: str = ""

    # --- OPNsense API -------------------------------------------------------
    opnsense_url: str = ""  # e.g. https://192.168.1.1  (or https://fw.lan:8443)
    opnsense_api_key: str = ""
    opnsense_api_secret: str = ""
    opnsense_verify_ssl: bool = False
    opnsense_ca_file: str = ""
    poll_interval: int = 60  # seconds between status/metric polls
    # pull the firewall log through the API when no filterlog lines arrive via syslog
    firewall_log_pull: str = "auto"  # auto | always | never
    unbound_query_pull: bool = True
    crowdsec_pull: bool = True
    qfeeds_pull: bool = True
    ids_pull: bool = True

    # --- AI assistant (any OpenAI compatible chat/completions endpoint) -------
    ai_base_url: str = "https://api.anthropic.com/v1/"
    ai_api_key: str = ""
    ai_model: str = "claude-opus-5-5"
    ai_max_tool_rounds: int = 12
    ai_timeout: int = 300
    ai_daily_report: bool = False
    ai_daily_report_hour: int = 7

    # --- enrichment / housekeeping -----------------------------------------
    geoip_db: str = "/data/GeoLite2-City.mmdb"  # optional MaxMind mmdb (City or Country)
    retention_days: int = 30
    metrics_retention_days: int = 90
    detection_interval: int = 60
    # comma separated CIDRs considered "internal" (RFC1918 etc. are always internal)
    internal_networks: str = ""
    log_level: str = "INFO"

    @property
    def opnsense_enabled(self) -> bool:
        return bool(self.opnsense_url and self.opnsense_api_key and self.opnsense_api_secret)

    @property
    def ai_enabled(self) -> bool:
        return bool(self.ai_base_url and self.ai_model and self.ai_api_key)


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if not s.secret_key:
        s.secret_key = secrets.token_urlsafe(32)
    return s
