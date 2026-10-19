"""Runtime configuration, read from environment variables (or a .env file)."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- database -----------------------------------------------------------
    database_url: str = "postgresql://lookingglass:lookingglass@db:5432/lookingglass"

    # --- web UI -------------------------------------------------------------
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    admin_user: str = "admin"
    admin_password: str = ""  # initial password of the first user only; empty -> random one is logged at first start
    secret_key: str = ""  # session cookie signing key; generated and stored in the database if empty
    public_url: str = ""  # e.g. https://looking-glass.home.lan - used as WebAuthn origin (auto-detected if empty)
    webauthn_rp_id: str = ""  # passkey relying party id (defaults to the host name of public_url / the request)
    cookie_secure: bool = False  # set true when served over HTTPS
    timezone: str = "UTC"

    # --- syslog receiver ----------------------------------------------------
    syslog_enabled: bool = True
    syslog_host: str = "0.0.0.0"
    syslog_udp_port: int = 5514
    syslog_tcp_port: int = 5514
    # comma separated list of IPs allowed to send syslog; empty = accept everyone
    syslog_allowed_senders: str = ""

    # --- Zenarmor "Stream Reporting Data to External Elasticsearch" receiver (works on the free edition) ---
    zenarmor_es_port: int = 9200  # 0 disables
    zenarmor_es_user: str = ""  # optional basic auth, must match Zenarmor's streaming username/password
    zenarmor_es_password: str = ""
    zenarmor_es_allowed: str = ""  # allowed sender IPs/CIDRs (defaults to SYSLOG_ALLOWED_SENDERS)

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

    # --- Unraid (optional bootstrap; more servers can be added in the web UI under Settings) ---
    unraid_name: str = "Unraid"
    unraid_url: str = ""  # e.g. http://192.168.1.10  (GraphQL API at /graphql)
    unraid_api_key: str = ""
    unraid_verify_ssl: bool = False
    unraid_docker_url: str = ""  # optional docker-socket-proxy, e.g. http://192.168.1.10:2375

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
    return s
