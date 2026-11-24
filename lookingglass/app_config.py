"""Application settings managed in the web UI and stored in the database (secrets encrypted).

Values are applied onto the shared ``Settings`` object, so the rest of the code keeps reading
``settings.opnsense_url`` etc. ``VERSION`` increments on every change; long-running components compare
``signature(group)`` to restart themselves when their group changed.
"""
from __future__ import annotations

import base64
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
    #            | image (an uploaded picture, stored as a data:image/...;base64 URL; empty = the built-in one)
    #            | multi (a checkbox per choice, at least one; stored ', ' separated in the order of the choices)
    help: str = ""
    choices: tuple[str, ...] = ()
    min: int | None = None
    max: int | None = None
    placeholder: str = ""


GROUPS = {
    "opnsense": "OPNsense",
    "unifi": "UniFi",
    "backrest": "Backrest",
    "bichon": "Bichon",
    "swag": "SWAG & CrowdSec",
    "email": "Email",
    "ai": "AI analyst",
    "reports": "Reports",
    "ingest": "Log ingestion & network",
    "data": "Data & detection",
    "display": "Display",
    "behavior": "Behaviour & ML",
    "intel": "Threat intel & traps",
    "packages": "Container packages",
    "blocking": "Blocking",
    "mute": "Recurring mute windows",  # shown under Settings › Alert filters
}

FIELDS: list[Field] = [
    # Blocking (blocking.py)
    Field("block_alias", "blocking", "OPNsense alias for blocked addresses", "str",
          "Name of a Firewall › Aliases entry of type 'External (advanced)' that Looking Glass fills with the "
          "addresses you block (and removes them when the block ends). Use it in a block rule on your WAN "
          "(Firewall › Rules › WAN: Block, source = this alias) - and on other interfaces if you like. Empty = "
          "blocking is off. The API user needs the privilege 'Firewall: Alias: Edit'.", placeholder="LookingGlass_block"),
    Field("block_hours", "blocking", "Default block duration (hours)", "int",
          "Offered when you block an address on the Alerts page. 0 = until you remove it.", min=0, max=8760),
    Field("block_never", "blocking", "Never block", "list",
          "IP addresses and networks (CIDR) that are never blocked, by hand or automatically - e.g. your VPN "
          "provider, monitoring services, your office. The address you are using right now and OPNsense itself are "
          "never blocked; internal devices only by hand, after a warning (to quarantine one, use the alias in a "
          "rule on that device's interface too)."),
    Field("block_auto", "blocking", "Block automatically", "bool",
          "Block the internet source of every new open alert of the severity below (or worse). Internal devices are "
          "never blocked automatically. Every automatic block is listed under General › Blocked addresses."),
    Field("block_auto_severity", "blocking", "Automatically block from severity", "choice",
          "critical = only the worst alerts (an attacker who got in); high also blocks e.g. brute force that "
          "succeeded and confirmed attacks.", choices=("critical", "high")),
    Field("block_auto_hours", "blocking", "Automatic blocks last (hours)", "int", "0 = until you remove them.",
          min=0, max=8760),
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
    Field("service_down_grace", "opnsense", "Service alerts wait (minutes)", "int", "A 'service is not running' "
          "alert only once the service has been stopped this long - a restart (config change, update) or a quick "
          "stop / start stays quiet. Such an alert closes by itself when the service runs again. 0 = alert right away.",
          min=0, max=240),
    Field("wan_alerts", "opnsense", "WAN quality alerts", "bool",
          "Alert when a gateway's latency over the last 24 hours is far above its own 7-day normal, or it loses "
          "packets for a day (Infrastructure › OPNsense › WAN quality). Down / degraded right now is alerted separately."),
    Field("wan_latency_factor", "opnsense", "WAN: latency alert at (% of normal)", "int",
          "200 = the 24-hour median latency is twice the median of the 7 days before.", min=110, max=1000),
    Field("wan_latency_min_ms", "opnsense", "WAN: and at least (ms) above normal", "int",
          "Keeps a jump from 2 to 5 ms on a fibre line quiet.", min=1, max=1000),
    Field("wan_loss_pct", "opnsense", "WAN: loss alert at (% over 24 h)", "int", "0 = no loss alerts.", min=0, max=100),
    Field("firewall_log_pull", "opnsense", "Pull firewall log via API", "choice",
          "auto = only when no filterlog arrives via syslog.", choices=("auto", "always", "never")),
    Field("unbound_query_pull", "opnsense", "Pull Unbound DNS queries", "bool", "Needs Reporting › Settings › Unbound DNS statistics."),
    Field("crowdsec_pull", "opnsense", "Pull CrowdSec alerts & decisions", "bool",
          "Off also hides the CrowdSec tab under Threats and its Overview widgets."),
    Field("crowdsec_opnsense_alerts", "opnsense", "CrowdSec (OPNsense) ban of an internet address: alert", "choice",
          "The alert level when the CrowdSec plugin on OPNsense detects and bans / captchas an internet address (one "
          "alert per address and scenario). That is CrowdSec doing its job: 'off' raises none and closes the open ones - "
          "the bans stay visible under Threats › CrowdSec, in reports and the Overview. An address inside your network "
          "is always high.", choices=("off", "info", "low")),
    Field("crowdsec_shared_lapi", "opnsense", "CrowdSec on OPNsense uses the Docker CrowdSec's Local API", "choice",
          "When OPNsense's CrowdSec is a log processor / bouncer of the CrowdSec of Settings › SWAG & CrowdSec (it logs "
          "in to that Local API), both list the same alerts and decisions. Then each is stored and counted once: the "
          "OPNsense pages show the Local API's, and only one alert per address and scenario is raised (its level: "
          "Settings › SWAG & CrowdSec). auto: recognised by the same alert and decision ids in both.",
          choices=("auto", "yes", "no")),
    Field("blocklist_aliases", "opnsense", "Blocklist aliases", "text", "The firewall aliases (pf tables) of blocking "
          "tools, one tool per line: Name: alias, alias - * matches any characters. For each line Looking Glass finds the "
          "rules that use these aliases (the tool's own and yours), counts the addresses in them and the packets the "
          "rules blocked, and marks their firewall log lines. The line named CrowdSec feeds the CrowdSec tiles. Change "
          "it when a plugin renames its aliases. Needs the privileges 'Firewall: Alias: Edit' (sizes) and "
          "'Diagnostics: Firewall statistics' (rules).",
          placeholder="CrowdSec: crowdsec_blocklists, crowdsec6_blocklists\nQ-Feeds: __qfeeds_*"),
    Field("qfeeds_pull", "opnsense", "Pull Q-Feeds events", "bool",
          "Off also hides the Q-Feeds tab under Threats and its Overview widgets."),
    Field("ids_pull", "opnsense", "Pull Suricata alerts", "bool",
          "Off also hides the Suricata tab under Threats and its Overview widgets (also when Suricata sends syslog)."),
    Field("ids_alert_priority", "opnsense", "Suricata: raise alerts up to priority", "int",
          "Suricata rates every signature priority 1 (most severe) to 3. 1 = only priority 1 becomes an alert, 2 = "
          "priority 1 and 2, 3 = all. Lower-priority hits still show under Threats › Suricata.", min=1, max=3),
    Field("ids_ignore_sids", "opnsense", "Suricata: SIDs that never raise an alert", "list",
          "Signature IDs (the SID column under Threats › Suricata). Their hits are still stored and shown.",
          placeholder="2210050"),
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
          "Client connects / roams, AP / switch offline, rogue APs - shown in Event search and on the Overview."),
    Field("unifi_offline_grace", "unifi", "Offline alerts wait (minutes)", "int", "An 'access point / switch is "
          "offline' or 'controller unreachable' alert only once it has been down this long - a reboot of OPNsense, the "
          "controller or the device itself (updates) stays quiet. Such an alert closes by itself when the device / "
          "controller is back. 0 = alert right away.", min=0, max=240),
    # Backrest (backups)
    Field("backrest_url", "backrest", "Backrest URL (with port)", "str",
          "Address of the Backrest web UI including its port - Backrest's default is 9898, use the port you mapped in "
          "Docker if it is different. From another container on the same Docker network: http://<container name>:9898. "
          "Behind a reverse proxy: its https address with port 443 and path, e.g. https://backup.example.com:443.",
          placeholder="http://192.168.1.10:9898"),
    Field("backrest_username", "backrest", "Username", "str",
          "A Backrest user (Backrest › Settings › Users › Add user). Backrest has no read-only users: a separate user "
          "only for Looking Glass is best. Leave empty when Backrest's authentication is disabled."),
    Field("backrest_password", "backrest", "Password", "secret", "Password of that Backrest user."),
    Field("backrest_verify_ssl", "backrest", "Verify TLS certificate", "bool",
          "Only for an https URL. Off accepts a self-signed certificate."),
    Field("backrest_poll_interval", "backrest", "Poll interval (seconds)", "int",
          "How often plans, repositories and backup runs are read from Backrest.", min=60, max=3600),
    Field("backrest_overdue_hours", "backrest", "Backup overdue after (hours)", "int",
          "A 'backup overdue' alert when a plan has had no successful backup for this long. 0 = automatic: from each "
          "plan's schedule (the longest normal gap between two runs, plus a margin).", min=0, max=2160),
    Field("backrest_alert_warnings", "backrest", "Alert on backups with warnings", "bool",
          "A backup that finished with warnings (usually files that could not be read) raises a low alert. Off: only "
          "failed backups do."),
    Field("backrest_offline_grace", "backrest", "Unreachable alert waits (minutes)", "int",
          "A 'Backrest unreachable' alert only once it has not answered for this long (container restarts / updates "
          "stay quiet). 0 = alert right away.", min=0, max=240),
    # Bichon (mail archive)
    Field("bichon_url", "bichon", "Bichon URL (with port)", "str",
          "Address of the Bichon web UI including its port - Bichon's default is 15630, use the port you mapped in "
          "Docker if it is different. From another container on the same Docker network: http://<container name>:15630. "
          "With a base path (BICHON_BASE_URL) or behind a reverse proxy: add it, e.g. https://mail.example.com:443/bichon.",
          placeholder="http://192.168.1.10:15630"),
    Field("bichon_token", "bichon", "API token", "secret",
          "Bichon › API tokens › new token. Tick 'Metrics only': that token can read the status figures and nothing "
          "else - no mail. Its user needs the system:metrics permission (an admin has it). A normal token of a user "
          "that may read the accounts' details also gives Bichon's own sync history (results per run, failed folders)."),
    Field("bichon_verify_ssl", "bichon", "Verify TLS certificate", "bool",
          "Only for an https URL. Off accepts a self-signed certificate."),
    Field("bichon_poll_interval", "bichon", "Poll interval (seconds)", "int",
          "How often Bichon is read. With a metrics-only token every sync that is the latest at a poll is kept, so "
          "keep this shorter than the accounts' sync interval.", min=60, max=3600),
    Field("bichon_overdue_hours", "bichon", "Mail sync overdue after (hours)", "int",
          "A 'mail sync overdue' alert when an account has had no successful sync for this long. 0 = automatic: from "
          "each account's sync interval (plus a quarter and 2 hours).", min=0, max=2160),
    Field("bichon_backup_overdue_hours", "bichon", "Bichon backup overdue after (hours)", "int",
          "Bichon's own backup (Bichon › Backup): an 'overdue' alert when it has not succeeded for this long, e.g. 26 "
          "for a daily backup. 0 = no overdue alert (its schedule cannot be read with the token); failed runs still "
          "raise an alert.", min=0, max=2160),
    Field("bichon_alert_warnings", "bichon", "Alert on partial syncs", "bool",
          "A sync that finished but could not archive every folder (Bichon: 'Partial') raises a low alert. Off: only "
          "failed syncs do."),
    Field("bichon_offline_grace", "bichon", "Unreachable alert waits (minutes)", "int",
          "A 'Bichon unreachable' alert only once it has not answered for this long (container restarts / updates "
          "stay quiet). 0 = alert right away.", min=0, max=240),
    # SWAG + CrowdSec in Docker (swag.py, crowdsec_lapi.py)
    Field("swag_log_dir", "swag", "SWAG log folder (inside this container)", "str",
          "SWAG's /config/log folder, mounted read-only into the Looking Glass container - e.g. on Unraid add the path "
          "/mnt/user/appdata/swag/log → /swag/log (read only) to the Looking Glass container, then enter /swag/log. "
          "Looking Glass reads nginx's access and error logs and fail2ban's log from it (like tail -f; rotated logs are "
          "followed). Empty = SWAG off.", placeholder="/swag/log"),
    Field("swag_name", "swag", "Name", "str", "Shown as the host of SWAG's events.", placeholder="SWAG"),
    Field("swag_access_logs", "swag", "nginx access logs", "list", "Inside the log folder; * as wildcard, e.g. "
          "nginx/*access.log for per-site logs. Combined format (SWAG's default) or the same with $host in front.",
          placeholder="nginx/access.log"),
    Field("swag_error_logs", "swag", "nginx error logs", "list", "Inside the log folder. CrowdSec bouncer blocks "
          "(SWAG's crowdsec mod) and AppSec / WAF blocks are read from here.", placeholder="nginx/error.log"),
    Field("swag_fail2ban_log", "swag", "fail2ban log", "str", "Inside the log folder. Empty = no fail2ban.",
          placeholder="fail2ban/fail2ban.log"),
    Field("swag_backfill_mb", "swag", "First read: older lines (MB)", "int", "The first time a log is read, this much of "
          "its end is read too (so the dashboards are not empty). After that only new lines. 0 = only new lines.",
          min=0, max=500),
    Field("swag_honeypot", "swag", "Honeypot", "list", "What is a trap - one per line: a request path (/wp-admin, "
          "/secret* - * as wildcard, without one it is a prefix), a host name (honeypot.example.com), a fail2ban jail "
          "(jail:nginx-honeypot) or a whole log file (file:nginx/honeypot.log). Jails and log files with 'honeypot' in "
          "their name count automatically. Nobody legitimate touches a trap: every hit is shown under SWAG › Honeypot.",
          placeholder="/wp-login.php\njail:nginx-honeypot\nfile:nginx/honeypot.log"),
    Field("swag_honeypot_conf", "swag", "Honeypot from nginx config", "list", "Instead of (or as well as) typing traps "
          "above: SWAG's nginx config file(s) holding your trap locations, e.g. the file with "
          "location ~* ^/(wp-admin|\\.env|...)(/|\\.|$) { return 404; }. Every location in it is a trap (regex ~ / ~*, "
          "exact =, prefix); one that matches every page (location /) is skipped. The file is read again whenever it "
          "changes, so a growing list needs no work here. Mount SWAG's nginx folder read only into the Looking Glass "
          "container (on Unraid: /mnt/user/appdata/swag/nginx → /swag/nginx) and enter e.g. /swag/nginx/honeypot.conf. "
          "A path without a leading / is taken from the folder above the log folder (nginx/honeypot.conf = "
          "/swag/nginx/honeypot.conf). * as wildcard.", placeholder="/swag/nginx/honeypot.conf"),
    Field("swag_honeypot_internet", "swag", "Honeypot hit from the internet: alert", "choice", "The alert level of a "
          "honeypot hit from an internet address (one alert per address). From inside your network it is always high.",
          choices=("off", "info", "low", "medium", "high")),
    Field("crowdsec_lapi_alerts", "swag", "CrowdSec (SWAG) ban of an internet address: alert", "choice", "The alert "
          "level when CrowdSec in Docker detects and bans / captchas an internet address (one alert per address and "
          "scenario). That is CrowdSec doing its job: 'off' raises none - the bans stay visible under SWAG & CrowdSec › "
          "CrowdSec, in reports and the Overview. An address inside your network is always high.",
          choices=("off", "info", "low")),
    Field("swag_fail2ban_alerts", "swag", "fail2ban ban of an internet address: alert", "choice", "The alert level "
          "when fail2ban bans an internet address (one alert per address and jail). A ban of an address inside your "
          "network is always high.", choices=("off", "info", "low", "medium")),
    Field("swag_proxy_ports", "swag", "Ports forwarded to SWAG", "str", "The ports OPNsense forwards to SWAG "
          "(comma separated). An address SWAG's CrowdSec / fail2ban banned, or that touched a honeypot, and that the "
          "firewall afterwards still lets in on any OTHER port raises a 'Banned on SWAG, still let in by the firewall' "
          "alert: those bans only work inside SWAG.", placeholder="80,443"),
    Field("crowdsec_lapi_url", "swag", "CrowdSec Local API URL", "str", "The CrowdSec container's API (LAPI), port "
          "8080 inside the container. On the same Docker network: http://crowdsec:8080 (the container name); else the "
          "host's IP address and the port you mapped. Empty = off.", placeholder="http://crowdsec:8080"),
    Field("crowdsec_lapi_machine", "swag", "Machine name (alerts)", "str", "Alerts with all their details need a "
          "machine login. In a shell on the Docker host: docker exec crowdsec cscli machines add lookingglass "
          "--password <a long password> -f /dev/null - then enter lookingglass here.", placeholder="lookingglass"),
    Field("crowdsec_lapi_password", "swag", "Machine password", "secret", "The password of that machine."),
    Field("crowdsec_lapi_bouncer_key", "swag", "Bouncer API key (decisions)", "secret", "Optional: the active decisions "
          "including the community blocklist. In a shell on the Docker host: docker exec crowdsec cscli bouncers add "
          "lookingglass - it prints the key once. Without it the decisions come from the alerts (your own only)."),
    Field("crowdsec_lapi_metrics_url", "swag", "CrowdSec metrics URL", "str", "Optional: CrowdSec's Prometheus "
          "endpoint (port 6060) - shows which logs CrowdSec reads and parses and what its AppSec (WAF) blocked. Needs "
          "prometheus listen_addr: 0.0.0.0 in CrowdSec's config.yaml.", placeholder="http://crowdsec:6060/metrics"),
    Field("crowdsec_lapi_verify_ssl", "swag", "Verify TLS certificate", "bool",
          "Only for an https URL. Off accepts a self-signed certificate."),
    Field("crowdsec_lapi_poll_interval", "swag", "CrowdSec poll interval (seconds)", "int",
          "How often alerts and decisions are read from the Local API.", min=15, max=3600),
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
    Field("ai_privacy", "ai", "Privacy mode: pseudonymize local data", "bool", "Before anything is sent to the AI, "
          "local identifiers are replaced by consistent pseudonyms, and translated back in the answer - you keep seeing "
          "the real values. Replaced: private IP addresses (the network part; the last number stays), your own public / "
          "WAN addresses and IPv6 prefixes, MAC addresses (the vendor part stays), email addresses and the names below. "
          "Not replaced: internet addresses, domains, ports, countries and container / program names - the analysis "
          "needs them. The analysis stays about as good; only meaning carried by a name is lost (a hint such as "
          "'iphone' or 'camera' is kept). Free text in log lines can still hold a name Looking Glass does not know - "
          "add those below. For full privacy use a local model (Ollama, LM Studio)."),
    Field("ai_privacy_names", "ai", "Privacy mode: also replace names", "bool", "Device names and UniFi aliases, "
          "Wi-Fi names (also neighbouring networks - they can locate you), user names that logged in, Unraid server "
          "names. Off = only addresses and your own terms below."),
    Field("ai_privacy_terms", "ai", "Privacy mode: always replace these", "list", "Your own domains (subdomains "
          "included), family names, a static WAN address, a street ... anything that identifies you. Case does not "
          "matter.", placeholder="example.com\njansen\nlab.example.net"),
    Field("ai_privacy_keep", "ai", "Privacy mode: never replace these", "list", "Names that should stay readable "
          "(common words that are also a device or user name). Generic names such as root, admin, nas, router are "
          "never replaced anyway.", placeholder="media-server"),
    Field("ai_privacy_avoid", "ai", "Privacy mode: never use these networks for fake addresses", "list", "A fake "
          "address keeps the structure of the real one: devices in the same /24 get fake addresses in the same fake "
          "/24 (the last number stays), devices in another /24 a different one. The fake networks are picked at "
          "random and never one of your own networks (devices, OPNsense interfaces, Extra internal networks). List "
          "networks or ranges here that should never be used for them either; fake addresses already in them are "
          "replaced. One per line: 10.0.0.0/8, an address, or a range 192.168.0.0-192.168.50.255.",
          placeholder="10.0.0.0/8\n192.168.0.0-192.168.50.255"),
    # reports (the setting keys keep their old names: ai_daily_report*)
    Field("ai_daily_report", "reports", "Scheduled report", "bool", "Write a report on a schedule (Reports page), with "
          "the AI analysis when the AI analyst is set up."),
    Field("report_every_days", "reports", "Every … days", "int", "1 = daily, 7 = weekly. The report covers that many "
          "days.", min=1, max=31),
    Field("ai_daily_report_hour", "reports", "Hour (local time)", "int", "When the report is written (Time zone under "
          "Ingestion & network).", min=0, max=23),
    Field("report_categories", "reports", "What the report covers", "multi", "All ticked = the full report. Untick "
          "what you don't want, e.g. only Unraid and Backups for a weekly server report.",
          choices=("OPNsense", "UniFi", "Unraid", "Backups")),
    Field("report_mail_to", "reports", "Email the report to", "list", "Mail addresses, one per line; uses the mail server "
          "under Email & notifications. Empty = not mailed.", placeholder="you@example.com"),
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
          "from Suricata (eve)."),
    Field("behavior_odd_hours", "behavior", "Alert: activity at hours the device is never active", "bool"),
    Field("behavior_peers", "behavior", "Compare with similar devices", "bool", "Devices of the same vendor form a "
          "group: something the others do too is not alerted; something none of them do weighs heavier."),
    Field("behavior_volume_factor", "behavior", "Alert: traffic N times the device's normal", "int", "Connections / "
          "DNS lookups in one hour compared to the device's median for that hour. 0 = off.", min=0, max=1000),
    Field("anomaly_ml_enabled", "behavior", "Machine learning (Isolation Forest)", "bool", "Scores every device-hour on "
          "7 features (connections, destinations, ports, countries, DNS, failed lookups, blocks) against the "
          "device's own history and alerts on combinations that are rare. Runs locally, nothing leaves the server."),
    Field("anomaly_ml_sensitivity", "behavior", "Machine learning: sensitivity", "choice", "low = only hours rarer "
          "than 1 in 2000 normal hours with a feature 4+ deviations off; medium = 1 in 500, 3.5; high = 1 in 200, 3.",
          choices=("low", "medium", "high")),
    Field("seasonal_enabled", "behavior", "Unusual for this hour of the week", "bool", "Totals per hour (firewall "
          "blocks, failed logins, DNS, failed lookups, per log source) against the same hour in previous weeks."),
    Field("seasonal_sensitivity", "behavior", "Hour of the week: sensitivity", "int", "How many 'normal deviations' "
          "above usual before an alert (3 = sensitive, 10 = only big spikes).", min=2, max=30),
    Field("seasonal_ignore", "behavior", "Hour of the week: ignore", "list", "A metric name from these alerts (e.g. "
          "blocks, dns, source:unraid; * = all), optionally only on some days and hours (local time, the end hour not "
          "included): 'source:unraid tue 01-02' = Tuesdays 01:00-02:00, 'blocks mon-fri 22-06' = weeknights, "
          "'* sun 03-05', 'dns 02-04' = every day. Without days / hours it is ignored always.",
          placeholder="source:unraid tue 01-02, blocks"),
    Field("mute_schedule", "mute", "Recurring mute windows", "list", "At these days / times (every week, month or N "
          "weeks), new alerts of "
          "a category are stored silently: not shown as open and not mailed, but still counted for attack chains and "
          "the risk score. Local time (Settings › Display › Time zone), the end time not included. Format: category "
          "[days] [from-to] [every N weeks from YYYY-MM-DD], e.g. 'unraid_container_errors tue 01:00-04:00', "
          "'backups 1st 02:00-06:00' (1st of the month), 'unraid 1st-mon', 'unraid tue 01-04 every 2 weeks from "
          "2026-11-10' - see Format & categories for all options and every category.", placeholder="unraid_container_errors tue 01:00-04:00"),
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
    Field("fp_repeat", "behavior", "Repeats of a false positive", "choice", "The exact same alert again (same rule, "
          "device, port and remote address, no higher severity) after you closed it as false positive: close = store "
          "it closed (not notified, listed under closed alerts with a link to your earlier verdict); info = keep it "
          "open but lower it to info; off = raise it as usual. A repeat that is more severe is always raised.",
          choices=("close", "info", "off")),
    Field("fp_repeat_days", "behavior", "Remember a false positive for (days)", "int", "Counted from the last time "
          "the alert was seen: as long as it keeps coming back unchanged, your verdict keeps applying.", min=1, max=365),
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
    Field("intel_shared_sites", "intel", "Shared sites (whole domain)", "list", "Sites where anyone can host files "
          "(GitHub, Discord, Google Drive ...). A feed that lists one malware URL on them does not flag the site: DNS "
          "only shows the host name, never which file. Covers the domain and all its subdomains - only add a domain "
          "whose subdomains all belong to the platform itself (not e.g. github.io, where <name>.github.io is someone's "
          "own site). Pre-filled with the built-in list; Restore built-in list shows the current one after an update.",
          placeholder="github.com\ndiscordapp.com"),
    Field("intel_shared_endpoints", "intel", "Shared storage endpoints (exact name only)", "list", "Cloud storage "
          "addresses shared by all customers (endpoint/<bucket>/file), e.g. s3-eu-west-1.amazonaws.com. Only this exact "
          "name is skipped: a name in front of it is one customer's own bucket (<bucket>.s3-eu-west-1.amazonaws.com) and "
          "is still flagged when a feed lists it - also below a shared site (<account>.blob.core.windows.net). "
          "* = one label: s3.*.amazonaws.com. Pre-filled with the built-in list.",
          placeholder="s3-*.amazonaws.com\nstorage.googleapis.com"),
    Field("intel_sources", "intel", "Feed download addresses", "text", "Your own addresses for the feeds, e.g. when "
          "one moved. One per line: feed: URL - feeds: urlhaus, threatfox, feodo, sslbl_ja3, tor_relay, tor_exit. "
          "Tried before the built-in addresses (top to bottom); the first that answers with entries is used, so a "
          "working one of yours replaces the built-in one. For an API that wants a POST: feed: POST URL {json body}. "
          "The abuse.ch Auth-Key is only sent to abuse.ch addresses.",
          placeholder="threatfox: POST https://threatfox-api.abuse.ch/api/v1/ {\"query\": \"get_iocs\", \"days\": 3}\n"
                      "feodo: https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
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
          choices=("blue", "indigo", "purple", "pink", "red", "crimson", "darkred", "orange", "green", "teal", "cyan", "gray")),
    Field("nav_position", "display", "Menu bar position", "choice", "Where the navigation bar sits: left, right, or "
          "top / bottom as a horizontal bar whose sections open as menus. Phones always use the menu button. "
          "The preview changes as you pick; Save to keep it.", choices=("left", "right", "top", "bottom")),
    Field("corners", "display", "Corners", "choice", "rounded or square corners on cards, widgets, buttons and fields. "
          "The preview changes as you pick; Save to keep it.", choices=("rounded", "square")),
    Field("app_name", "display", "Application name", "str", "Name on the menu bar, the login page and the browser "
          "tab. Empty = Looking Glass.", placeholder="Looking Glass"),
    Field("logo", "display", "Logo on the menu bar", "image", "A picture shown in front of the name on the menu bar "
          "and the login page (PNG, JPEG, GIF, WebP or SVG, at most 256 KB; shown 28 pixels high). None = only the name."),
    Field("favicon", "display", "Browser tab icon (favicon)", "image", "The icon in the browser tab and bookmarks "
          "(PNG, ICO, GIF, WebP or SVG, at most 256 KB; square, e.g. 64×64). None = the built-in magnifier."),
    # data
    Field("retention_days", "data", "Keep events (days)", "int", "", min=1, max=3650),
    Field("metrics_retention_days", "data", "Keep metrics (days)", "int", "", min=1, max=3650),
    Field("device_remove_days", "data", "Remove devices not seen for (days)", "int", "0 = never. Devices you marked "
          "trusted, named yourself, wrote notes for or gave their own "
          "alert limits are kept. A removed device that comes back is a new device again.",
          min=0, max=3650),
    Field("detection_interval", "data", "Detection interval (seconds)", "int", "", min=10, max=3600),
    Field("source_silence_hours", "data", "Alert when a source goes quiet (hours)", "int", "A source that normally sends "
          "something every hour (firewall, web server, DNS, Suricata …) but has sent nothing new for this long raises an "
          "alert - a log pull that stalled, a plugin that stopped, a syslog target that was removed. Counted by the time "
          "of the events, so a pull running hours behind counts as quiet too. Closes by itself when events come back. "
          "0 = off.", min=0, max=168),
    Field("long_refresh_7d", "data", "7-day views: count again every (minutes)", "int", "Overview and dashboards over "
          "7 days are counted in the background on this schedule, one at a time, and shown from the stored result "
          "(switching to 7d does not count anything). The refresh button next to the period counts one again at once.",
          min=10, max=1440),
    Field("long_refresh_30d", "data", "30-day views: count again every (minutes)", "int", "The same for 30 days (and "
          "other periods over 7 days). Counting 30 days takes the database a while: every few hours is plenty.",
          min=30, max=10080),
    Field("long_keep_days", "data", "7 / 30 day views: keep refreshing for (days)", "int", "A 7- or 30-day view (a page, "
          "tab and period) is counted again on the schedule above for this many days after it was last opened; after "
          "that it is no longer counted until someone opens it again (it then shows its last result and counts anew). "
          "Lower = less background work for views nobody looks at.", min=1, max=365),
    Field("dns_ignore_domains", "data", "DNS: domains to ignore", "list",
          "Domains (subdomains included) the DNS checks - random-looking / DGA names, tunneling, NXDOMAIN "
          "storms - skip, e.g. CDNs or latency probes with random names. Logs and dashboards still show them.",
          placeholder="atoma.cloud, example-cdn.net"),
    Field("unraid_container_grace", "data", "Unraid: container alerts wait (minutes)", "int", "No 'container stopped' "
          "alert until the Unraid server has been up this long (after a reboot containers are still starting) and the "
          "container has been stopped this long. An open one closes by itself once the container has been running "
          "again this long.", min=1, max=240),
    Field("unraid_offline_grace", "data", "Unraid: unreachable alerts wait (minutes)", "int", "No 'Unraid server is "
          "unreachable' alert until Looking Glass has not reached the server for this long - a reboot of the server or "
          "of OPNsense in between stays quiet. The alert closes by itself when the server answers again. 0 = alert "
          "right away (after 3 failed polls).", min=0, max=240),
    Field("unraid_unhealthy_minutes", "data", "Unraid: unhealthy alerts wait (minutes)", "int", "A container whose own "
          "Docker health check (status 'unhealthy') keeps failing for this long raises an alert; it closes by itself "
          "once the check passes again. Only containers whose image has a health check can be unhealthy. 0 = off.",
          min=0, max=1440),
    Field("unraid_restart_count", "data", "Unraid: container keeps restarting from (restarts)", "int", "A container "
          "that started this many times within the minutes below raises an alert ('keeps restarting'); 2-3 restarts "
          "(an update, a manual restart) stay quiet. It closes by itself once the container stays up. 0 = off.",
          min=0, max=100),
    Field("unraid_restart_minutes", "data", "Unraid: … within (minutes)", "int", "", min=2, max=1440),
    Field("web_internet_alerts", "data", "Web attacks / scanners from the internet: alert", "choice",
          "through = only when requests got through (a successful answer to an attack or probe request, or the "
          "scanner logged in) - scanners that only got errors or were blocked (CrowdSec, WAF) raise nothing; "
          "attacks = also every RCE / SQL injection attempt, even when it failed; all = every scanner and attack "
          "pattern, as before. From inside your network these always alert.", choices=("through", "attacks", "all")),
    Field("web_through_min", "data", "… got through from (requests)", "int", "How many attack / probe requests "
          "(per address and pattern; for a scanner: distinct probed paths in 10 minutes) must get a successful answer "
          "before it alerts. 1 = the first one.", min=1, max=10000),
    Field("web_success_codes", "data", "… a successful answer is", "choice", "2xx = only real answers; 2xx+3xx = "
          "redirects count too (often just the redirect to HTTPS or a login page).", choices=("2xx", "2xx+3xx")),
    Field("unraid_log_error_count", "data", "Unraid: container log errors from (lines)", "int", "Default rule for "
          "container logs: this many error lines within the minutes below raise an alert - lines whose level is error "
          "or worse ([error], level=error, ERROR ...), or without a level that contain error / fatal / panic / "
          "exception / traceback / critical. Containers with their own rule (Unraid › Docker › Log alert rules) use "
          "that instead. Needs 'Collect container logs' on the server. 0 = off.", min=0, max=100000),
    Field("unraid_log_error_minutes", "data", "Unraid: … within (minutes)", "int", "", min=1, max=1440),
    Field("unraid_log_critical_count", "data", "Unraid: emergency / critical log lines from (lines)", "int",
          "Lines with level emergency, alert or critical (nginx [emerg] / [crit], FATAL, PANIC) within the minutes "
          "above raise their own alert - for every container, also those with their own rule, unless that rule has "
          "limit 0. 0 = off.", min=0, max=100000),
    Field("unraid_log_critical_severity", "data", "Unraid: … alert severity", "choice", "",
          choices=("medium", "high", "critical")),
    Field("geoip_db", "data", "GeoIP database path", "str", "MaxMind GeoLite2-City or -Country .mmdb inside the data volume.",
          placeholder="/data/GeoLite2-City.mmdb"),
    # container packages (packages.py; shown under Settings › Unraid servers)
    Field("pkg_enabled", "packages", "Read the packages of container images", "bool",
          "Lists what is inside the image of every container on your Unraid servers (Unraid › Packages): operating "
          "system packages, libraries, language packages and the programs they are built into. An image is read when "
          "it is new or updated, or when you press Update - never on a schedule."),
    Field("pkg_image_source", "packages", "Image source", "choice", "auto = from the registry by the exact digest the "
          "container runs (needs the Docker API with IMAGES=1 to know it), else exported through the Docker API, else "
          "the registry's current image of the tag; registry = only from the registry; docker = only through the Docker "
          "API (also for images built locally).", choices=("auto", "registry", "docker")),
    Field("pkg_exclude", "packages", "Containers / images not to read", "list", "Names or images, * as wildcard.",
          placeholder="my-test-*\nlocalhost/*"),
    Field("pkg_registry_host", "packages", "Registry login: registry", "str", "Optional login for pulling images (Docker "
          "Hub limits anonymous pulls; private registries need one).", placeholder="docker.io"),
    Field("pkg_registry_user", "packages", "Registry login: user", "str", ""),
    Field("pkg_registry_password", "packages", "Registry login: password / token", "secret", "Docker Hub: Account "
          "settings › Personal access tokens › Generate (read-only)."),
    Field("pkg_syft_path", "packages", "Syft program", "str", "Included in the image; change only to use another one.",
          placeholder="syft"),
    Field("pkg_syft_args", "packages", "Extra Syft arguments", "str", "Added to every image read, e.g. --platform "
          "linux/arm64 or --scope all-layers.", placeholder="--scope squashed"),
    Field("pkg_tool_env", "packages", "Extra environment for Syft", "text", "NAME=value per line - any Syft setting "
          "(HTTPS_PROXY=..., SYFT_REGISTRY_INSECURE_USE_HTTP=true).", placeholder="HTTPS_PROXY=http://proxy:3128"),
    Field("pkg_timeout", "packages", "Time limit per image (minutes)", "int", "Large images over a slow connection "
          "need longer.", min=2, max=240),
]
BY_KEY = {f.key: f for f in FIELDS}
SECRET_KEYS = {f.key for f in FIELDS if f.kind == "secret"}

# which groups restart which component
RESTART_GROUPS = {"backrest": ("backrest_url", "backrest_username", "backrest_password", "backrest_verify_ssl",
                               "backrest_poll_interval"),
                  "bichon": ("bichon_url", "bichon_token", "bichon_verify_ssl", "bichon_poll_interval"),
                  "swag": ("swag_log_dir", "swag_name", "swag_access_logs", "swag_error_logs", "swag_fail2ban_log",
                           "swag_backfill_mb", "swag_honeypot", "swag_honeypot_conf"),
                  "crowdsec_lapi": ("crowdsec_lapi_url", "crowdsec_lapi_machine", "crowdsec_lapi_password",
                                    "crowdsec_lapi_bouncer_key", "crowdsec_lapi_metrics_url",
                                    "crowdsec_lapi_verify_ssl", "crowdsec_lapi_poll_interval"),
                  "unifi": ("unifi_url", "unifi_api_key", "unifi_username", "unifi_password", "unifi_site",
                            "unifi_verify_ssl", "unifi_poll_interval", "unifi_events"),
                  "opnsense": ("opnsense_url", "opnsense_api_key", "opnsense_api_secret", "opnsense_verify_ssl",
                               "opnsense_ca_pem", "poll_interval", "firewall_log_pull", "unbound_query_pull",
                               "crowdsec_pull", "qfeeds_pull", "ids_pull", "vpn_pull")}


@dataclass
class _State:
    version: int = 0
    defaults: dict[str, Any] = field(default_factory=dict)


STATE = _State()


class SettingsError(ValueError):
    pass


# Settings › Display › Logo / favicon: an uploaded picture, stored as a data URL (served by /brand/<key>)
IMAGE_TYPES = {"png": "image/png", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp",
               "svg+xml": "image/svg+xml", "x-icon": "image/x-icon", "vnd.microsoft.icon": "image/x-icon"}
IMAGE_RE = re.compile(r"data:image/(png|jpeg|gif|webp|svg\+xml|x-icon|vnd\.microsoft\.icon);base64,([A-Za-z0-9+/]+={0,2})")
IMAGE_MAX_BYTES = 256 * 1024
IMAGE_MAX_CHARS = 64 + (IMAGE_MAX_BYTES + 2) // 3 * 4


def image_bytes(value: str) -> tuple[str, bytes] | None:
    """(content type, bytes) of a stored picture, None when empty or invalid."""
    m = IMAGE_RE.fullmatch(value or "")
    if not m:
        return None
    try:
        return IMAGE_TYPES[m.group(1)], base64.b64decode(m.group(2), validate=True)
    except ValueError:
        return None


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
    if f.kind == "multi":  # a list or a ', ' separated text; case-insensitive, stored in the order of the choices
        items = value if isinstance(value, (list, tuple)) else re.split(r"[,;\n]+", "" if value is None else str(value))
        wanted = {str(p).strip().lower() for p in items if str(p).strip()}
        unknown = wanted - {c.lower() for c in f.choices}
        if unknown:
            raise SettingsError(f"{f.label}: unknown {', '.join(sorted(unknown))} (one or more of {', '.join(f.choices)})")
        if not wanted:
            raise SettingsError(f"{f.label}: tick at least one")
        return ", ".join(c for c in f.choices if c.lower() in wanted)
    v = "" if value is None else str(value).strip()
    if f.kind == "image" and v:
        m = IMAGE_RE.fullmatch(v)
        if not m:
            raise SettingsError(f"{f.label}: must be a PNG, JPEG, GIF, WebP, ICO or SVG picture")
        if len(v) > IMAGE_MAX_CHARS:
            raise SettingsError(f"{f.label}: the picture is too large (at most {IMAGE_MAX_BYTES // 1024} KB)")
        try:
            base64.b64decode(m.group(2), validate=True)
        except ValueError as exc:
            raise SettingsError(f"{f.label}: the picture is damaged") from exc
    if f.key == "app_name" and len(v) > 60:
        raise SettingsError(f"{f.label}: at most 60 characters")
    if f.kind == "choice" and v not in f.choices:
        raise SettingsError(f"{f.label}: must be one of {', '.join(f.choices)}")
    if f.key in ("opnsense_url", "ai_base_url", "backrest_url", "bichon_url", "crowdsec_lapi_url",
                 "crowdsec_lapi_metrics_url") and v and \
            not v.startswith(("http://", "https://")):
        raise SettingsError(f"{f.label}: must start with http:// or https://")
    if f.key in ("backrest_url", "bichon_url") and v:
        tool, default_port = ("Backrest", 9898) if f.key == "backrest_url" else ("Bichon", 15630)
        from urllib.parse import urlsplit
        try:
            port, host = urlsplit(v).port, urlsplit(v).hostname
        except ValueError as exc:
            raise SettingsError(f"{f.label}: invalid port ({exc})") from exc
        if not host:
            raise SettingsError(f"{f.label}: no host name or IP address")
        if port is None:
            raise SettingsError(f"{f.label}: add the port, e.g. {v.rstrip('/')}:{default_port} ({tool}'s default) or "
                                "the port you mapped in Docker")
    if f.key in ("syslog_allowed_senders", "internal_networks", "block_never") and v:
        for part in v.split(","):
            try:  # an invalid line is named, nothing is saved
                ipaddress.ip_network(part.strip(), strict=False)
            except ValueError as exc:
                raise SettingsError(f"{f.label}: '{part.strip()}' is not an IP address or CIDR") from exc
    if f.key == "seasonal_ignore" and v:
        from .behavior import parse_seasonal_ignore
        try:
            parse_seasonal_ignore(v)
        except ValueError as exc:
            raise SettingsError(f"{f.label}: {exc}") from exc
    if f.key == "mute_schedule" and v:
        from .mute_schedule import parse
        try:
            parse(v)
        except ValueError as exc:
            raise SettingsError(f"{f.label}: {exc}") from exc
    if f.key == "pkg_tool_env" and v:
        from .packages import parse_env
        try:
            parse_env(v)
        except ValueError as exc:
            raise SettingsError(f"{f.label}: {exc}") from exc
    if f.key == "pkg_syft_args" and v:
        import shlex
        try:
            shlex.split(v)
        except ValueError as exc:
            raise SettingsError(f"{f.label}: {exc}") from exc
    if f.key == "ids_ignore_sids" and v and not all(p.strip().isdigit() for p in v.split(",")):
        raise SettingsError(f"{f.label}: one number (SID) per line")
    if f.key == "timezone" and v:
        try:
            ZoneInfo(v)
        except Exception as exc:  # noqa: BLE001
            raise SettingsError(f"{f.label}: unknown time zone '{v}'") from exc
    if f.key == "blocklist_aliases" and v:
        from .parsers.filterlog import parse_blocklist_aliases
        try:
            parse_blocklist_aliases(v)
        except ValueError as exc:
            raise SettingsError(f"{f.label}: {exc}") from exc
    if f.key in ("intel_shared_sites", "intel_shared_endpoints") and v:
        from .intel import check_shared_entry
        for part in v.split(","):
            try:  # an invalid line is named, nothing is saved
                check_shared_entry(part.strip(), wildcards=f.key == "intel_shared_endpoints")
            except ValueError as exc:
                raise SettingsError(f"{f.label}: {exc}") from exc
    if f.key == "intel_sources" and v:
        from .intel import parse_sources
        try:
            parse_sources(v)
        except ValueError as exc:
            raise SettingsError(f"{f.label}: {exc}") from exc
    if f.key == "ai_privacy_avoid" and v:
        from .privacy import parse_avoid
        try:
            parse_avoid(v)
        except ValueError as exc:
            raise SettingsError(f"{f.label}: {exc}") from exc
    if f.key == "report_mail_to" and v:
        from .notify import recipients
        try:
            recipients(v)
        except ValueError as exc:
            raise SettingsError(f"{f.label}: {exc}") from exc
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
        if f.kind == "list" and (d := Settings.model_fields[f.key].default):
            item["default"] = d  # the UI offers to restore a built-in list
        if f.group == "display":
            item["default"] = Settings.model_fields[f.key].default  # Settings › Display › Restore defaults
        out.append(item)
    return {"groups": GROUPS, "fields": out, "version": STATE.version}


def signature(settings: Settings, group: str) -> tuple:
    return tuple(getattr(settings, k) for k in RESTART_GROUPS[group])
