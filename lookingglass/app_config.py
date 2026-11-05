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
    section: str = ""  # sub-heading inside the group (fields of one section are listed together)


# what a section is for, shown under its heading
SECTIONS = {
    "Scanning": "What is scanned and how often.",
    "Vulnerabilities page": "What the Vulnerabilities page lists. Does not change what raises an alert.",
    "Alerts": "When a finding raises an alert. Only used while 'Create alerts for vulnerabilities' is on; the findings "
              "that meet these rules are under 'Meets alert rules' on the Vulnerabilities page either way.",
    "Exceptions": "Findings you accept: no alert, listed under 'Exceptions' on the Vulnerabilities page. To hide "
                  "single findings for good, tick them on the Vulnerabilities page and press Close selected.",
    "Application versions": "The App version column, and CVE checks for the application itself.",
    "Data sources": "Where scores and 'actively exploited' come from.",
    "Registry login": "Optional: for pulling images (Docker Hub limits anonymous pulls; private registries need one).",
    "Advanced: Grype and Syft": "Only change these when you know you need to.",
}


GROUPS = {
    "opnsense": "OPNsense",
    "unifi": "UniFi",
    "email": "Email",
    "ai": "AI analyst",
    "reports": "Reports",
    "zenarmor": "Zenarmor stream",
    "ingest": "Log ingestion & network",
    "data": "Data & detection",
    "display": "Display",
    "behavior": "Behaviour & ML",
    "intel": "Threat intel & traps",
    "vulns": "Container vulnerabilities",
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
    Field("blocklist_aliases", "opnsense", "Blocklist aliases", "text", "The firewall aliases (pf tables) of blocking "
          "tools, one tool per line: Name: alias, alias - * matches any characters. For each line Looking Glass finds the "
          "rules that use these aliases (the tool's own and yours), counts the addresses in them and the packets the "
          "rules blocked, and marks their firewall log lines. The line named CrowdSec feeds the CrowdSec tiles. Change "
          "it when a plugin renames its aliases. Needs the privileges 'Firewall: Alias: Edit' (sizes) and "
          "'Diagnostics: Firewall statistics' (rules).",
          placeholder="CrowdSec: crowdsec_blocklists, crowdsec6_blocklists\nQ-Feeds: __qfeeds_*"),
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
    Field("unifi_offline_grace", "unifi", "Offline alerts wait (minutes)", "int", "An 'access point / switch is "
          "offline' or 'controller unreachable' alert only once it has been down this long - a reboot of OPNsense, the "
          "controller or the device itself (updates) stays quiet. Such an alert closes by itself when the device / "
          "controller is back. 0 = alert right away.", min=0, max=240),
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
    Field("report_mail_to", "reports", "Email the report to", "list", "Mail addresses, one per line; uses the mail server "
          "under Email & notifications. Empty = not mailed.", placeholder="you@example.com"),
    # Zenarmor
    Field("zenarmor_es_user", "zenarmor", "Stream username", "str", "Optional basic auth; must match Zenarmor's streaming username."),
    Field("zenarmor_es_password", "zenarmor", "Stream password", "secret", "Must match Zenarmor's streaming password."),
    Field("zenarmor_es_allowed", "zenarmor", "Allowed senders", "list",
          "IPs / CIDRs allowed to stream (empty = same as syslog allowed senders).", placeholder="192.168.1.1"),
    Field("zenarmor_blocked_alerts", "zenarmor", "Alert on traffic Zenarmor blocked", "choice",
          "threats = blocked malware, botnet / command & control, phishing, ransomware or crypto mining only when the "
          "device keeps trying (repeated over time / many sites) or other sources and alerts point at it too - a single "
          "blocked ad or link is Zenarmor doing its job; every_threat = every blocked threat (low); all = also policy / "
          "app category blocks (low); never = no alerts for blocked traffic at all. Traffic Zenarmor flagged but did "
          "NOT block is always alerted.", choices=("threats", "every_threat", "all", "never")),
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
          choices=("blue", "indigo", "purple", "pink", "red", "orange", "green", "teal", "cyan", "gray")),
    # data
    Field("retention_days", "data", "Keep events (days)", "int", "", min=1, max=3650),
    Field("metrics_retention_days", "data", "Keep metrics (days)", "int", "", min=1, max=3650),
    Field("device_remove_days", "data", "Remove devices not seen for (days)", "int", "0 = never. Devices you marked "
          "trusted, named yourself, wrote notes for or gave their own "
          "alert limits are kept. A removed device that comes back is a new device again.",
          min=0, max=3650),
    Field("detection_interval", "data", "Detection interval (seconds)", "int", "", min=10, max=3600),
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
    Field("unraid_log_error_count", "data", "Unraid: container log errors from (lines)", "int", "Default rule for "
          "container logs: this many lines with error / fatal / panic / exception / traceback / critical within the "
          "minutes below raise an alert. Containers with their own rule (Unraid › Docker › Log alert rules) use that "
          "instead. Needs 'Collect container logs' on the server. 0 = off.", min=0, max=100000),
    Field("unraid_log_error_minutes", "data", "Unraid: … within (minutes)", "int", "", min=1, max=1440),
    Field("geoip_db", "data", "GeoIP database path", "str", "MaxMind GeoLite2-City or -Country .mmdb inside the data volume.",
          placeholder="/data/GeoLite2-City.mmdb"),
    # container vulnerabilities (vulnscan.py), shown in these sections
    Field("vuln_scan_enabled", "vulns", "Scan container images for vulnerabilities", "bool",
          "Every container of your Unraid servers (and the extra images below) is checked with Grype / Syft for known "
          "vulnerabilities in the operating system packages, libraries and programs inside the image. Results: "
          "Vulnerabilities page.", section="Scanning"),
    Field("vuln_recheck_hours", "vulns", "Check against new vulnerabilities every (hours)", "int", "Updates Grype's "
          "database and matches the stored package lists of all images again - fast, the images are not downloaded.",
          min=1, max=168, section="Scanning"),
    Field("vuln_rescan_days", "vulns", "Read the images again every (days)", "int", "The package list of an image is "
          "made again after this many days (and always when a container runs a new image).", min=1, max=90, section="Scanning"),
    Field("vuln_image_source", "vulns", "Image source", "choice", "auto = from the registry by the exact digest the "
          "container runs (Docker API with IMAGES=1 needed to know it), else exported through the Docker API, else the "
          "registry's current image of the tag; registry = only from the registry; docker = only through the Docker API "
          "(also for images built locally).", choices=("auto", "registry", "docker"), section="Scanning"),
    Field("vuln_images", "vulns", "Extra images to scan", "list", "Images that do not run on an Unraid server Looking "
          "Glass knows, e.g. on another Docker host. Scanned from their registry.",
          placeholder="ghcr.io/gittimeraider/looking-glass:latest\npostgres:18", section="Scanning"),
    Field("vuln_exclude", "vulns", "Containers / images not to scan", "list", "Names or images, * as wildcard.",
          placeholder="my-test-*\nlocalhost/*", section="Scanning"),
    Field("vuln_show_min_cvss", "vulns", "Minimum CVSS score to show", "str", "Findings below this score are not shown "
          "on the Vulnerabilities page (nor counted there). 0 = show everything. A finding that raises an alert is "
          "always shown, whatever this says.", placeholder="0", section="Vulnerabilities page"),
    Field("vuln_alerts", "vulns", "Create alerts for vulnerabilities", "bool", "Off by default. On = one alert per "
          "container image for the findings that meet the rules below. Off = findings are only listed on the "
          "Vulnerabilities page (open alerts are closed). Scan problems alert either way.", section="Alerts"),
    Field("vuln_min_cvss", "vulns", "Minimum CVSS score for an alert", "str", "A finding with this CVSS base score or "
          "higher raises an alert. 7.0 = high and critical; 9.0 = critical only. Without a score the severity word "
          "counts (critical 9, high 7, medium 4, low 0.1).", placeholder="7.0", section="Alerts"),
    Field("vuln_kev_always", "vulns", "Also alert on actively exploited vulnerabilities", "bool",
          "A CVE on CISA's Known Exploited Vulnerabilities list is attacked in the wild: alert (critical) whatever its "
          "CVSS score, also when no fixed version exists yet.", section="Alerts"),
    Field("vuln_epss_min", "vulns", "Also alert from EPSS chance", "str", "EPSS = the chance a CVE gets exploited in the next "
          "30 days (0-1 or a percentage). Findings at or above it alert even below the minimum CVSS score. Empty = not used.",
          placeholder="0.1 or 10%", section="Alerts"),
    Field("vuln_only_fixed", "vulns", "Only alert when a fix exists", "bool", "Skip findings without a fixed version "
          "(Debian / Alpine 'will not fix', or not fixed yet) - there is nothing to update to. Actively exploited ones "
          "still alert when the switch above is on. They are always listed on the Vulnerabilities page.", section="Alerts"),
    Field("vuln_ignore", "vulns", "Exceptions", "text", "Findings you accept, one per line: a CVE / GHSA id (patterns "
          "with * allowed) or pkg:<package>, optionally 'on <containers or images>' and 'until <date>' - after that date "
          "it counts again. Still listed (marked) on the Vulnerabilities page. # starts a comment.",
          placeholder="CVE-2023-45853 on mariadb*  # not reachable\npkg:perl-base\nCVE-2024-* on test-* until 2026-12-31", section="Exceptions"),
    Field("vuln_version_sources", "vulns", "Where image versions are read", "text", "For the App version column of "
          "every image, tried top to bottom: label NAME, env NAME, tag or package NAME, optionally followed by a /regex/ "
          "(first group = the version; default: the first number like 1.2.3). {NAME} / {name} = the image's own name "
          "(env {NAME}_VERSION -> FILEFLOWS_VERSION for revenz/fileflows). A tag like latest or stable holds no version. "
          "Only shown - CVEs of the application itself are looked up by the App version checks. Empty = the built-in "
          "list.", section="Application versions"),
    Field("vuln_app_checks", "vulns", "App version checks", "text", "Own checks for the application itself, which package "
          "scanners often miss: one per line 'images | version source | OSV ecosystem package'. Version source: env NAME, "
          "label NAME, tag or package NAME (from the image's package list), optionally followed by a /regex/ whose first "
          "group is the version (default: the first number like 30.0.2). The version is looked up with the osv source "
          "below. Ecosystems: osv.dev/list (Packagist, npm, PyPI, Go, Maven, ...). # = comment.", section="Application versions"),
    Field("vuln_sources", "vulns", "Sources", "text", "Where extra information comes from - change an address or format "
          "when a provider moves or changes its format, or add a mirror. One per line 'kind: [POST] address | format'; "
          "per kind tried top to bottom until one answers. kev (actively exploited CVEs): '| json <path>', '| csv "
          "<column>' or '| text' (every CVE id in the answer). epss: '| json <rows> <cve field> <score field> "
          "[<percentile field>]' or '| csv <cve column> <score column> [...]' - {cves} in the address = asked 100 at a "
          "time, without it = one full download (.gz is unpacked). cvss (for findings without a score): address with "
          "{cve}, '| json <path>, <path>' (highest number found). osv: OSV-compatible query API. Paths: a.b[].c ([] = "
          "every list item, * = every value). 'kind: off' switches a kind off. Empty = the built-in list. Test sources "
          "tries every line.", section="Data sources"),
    Field("vuln_nvd_api_key", "vulns", "NVD API key", "secret", "Optional: more CVSS lookups per minute. Free at "
          "nvd.nist.gov › Developers › Request an API Key. Only sent to nvd.nist.gov.", section="Data sources"),
    Field("vuln_registry_host", "vulns", "Registry login: registry", "str", "Optional login for pulling images (Docker "
          "Hub limits anonymous pulls; private registries need one).", placeholder="docker.io", section="Registry login"),
    Field("vuln_registry_user", "vulns", "Registry login: user", "str", "", section="Registry login"),
    Field("vuln_registry_password", "vulns", "Registry login: password / token", "secret", "Docker Hub: Account "
          "settings › Personal access tokens › Generate (read-only).", section="Registry login"),
    Field("vuln_grype_path", "vulns", "Grype program", "str", "Included in the image; change only to use another one.",
          placeholder="grype", section="Advanced: Grype and Syft"),
    Field("vuln_syft_path", "vulns", "Syft program", "str", "Included in the image.", placeholder="syft", section="Advanced: Grype and Syft"),
    Field("vuln_grype_db_url", "vulns", "Grype database address", "str", "Where Grype downloads its vulnerability "
          "database (the listing / latest.json URL); empty = Grype's own. For a mirror or when Anchore moves it.",
          placeholder="https://grype.anchore.io/databases", section="Advanced: Grype and Syft"),
    Field("vuln_grype_args", "vulns", "Extra Grype arguments", "str", "Added to every match, e.g. --only-fixed or "
          "--exclude '/usr/share/**'.", placeholder="--exclude /usr/share/doc/**", section="Advanced: Grype and Syft"),
    Field("vuln_syft_args", "vulns", "Extra Syft arguments", "str", "Added to every image read, e.g. --platform "
          "linux/arm64 or --scope all-layers.", placeholder="--scope squashed", section="Advanced: Grype and Syft"),
    Field("vuln_tool_env", "vulns", "Extra environment for Grype / Syft", "text", "NAME=value per line - any Grype / "
          "Syft setting (GRYPE_DB_MAX_ALLOWED_BUILT_AGE=240h, HTTPS_PROXY=..., GRYPE_DB_CA_CERT=...).",
          placeholder="GRYPE_DB_MAX_ALLOWED_BUILT_AGE=240h", section="Advanced: Grype and Syft"),
    Field("vuln_scan_timeout", "vulns", "Time limit per run (minutes)", "int", "For one image read or database update; "
          "large images over a slow connection need longer.", min=2, max=240, section="Advanced: Grype and Syft"),
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
    if f.key == "blocklist_aliases" and v:
        from .parsers.filterlog import parse_blocklist_aliases
        try:
            parse_blocklist_aliases(v)
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
    if f.key.startswith("vuln_") and v:
        from . import vulnscan
        try:
            if f.key == "vuln_min_cvss":
                vulnscan.parse_threshold(v, f.label, 10)
            elif f.key == "vuln_show_min_cvss":
                vulnscan.parse_threshold(v, f.label, 10)
            elif f.key == "vuln_epss_min":
                vulnscan.parse_threshold(v, f.label, 1)
            elif f.key == "vuln_sources":
                vulnscan.parse_sources(v)
            elif f.key == "vuln_app_checks":
                vulnscan.parse_app_checks(v)
            elif f.key == "vuln_version_sources":
                vulnscan.parse_version_sources(v)
            elif f.key == "vuln_ignore":
                vulnscan.parse_ignore(v)
            elif f.key == "vuln_tool_env":
                vulnscan.parse_env(v)
            elif f.key in ("vuln_grype_args", "vuln_syft_args"):
                import shlex
                shlex.split(v)
            elif f.key == "vuln_grype_db_url" and not v.startswith(("http://", "https://")):
                raise ValueError("must start with http:// or https://")
        except ValueError as exc:
            msg = str(exc)
            raise SettingsError(msg if msg.startswith(f.label) else f"{f.label}: {msg}") from exc
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
                "choices": list(f.choices), "min": f.min, "max": f.max, "placeholder": f.placeholder,
                "section": f.section}
        if f.kind == "secret":
            item["is_set"] = bool(v)
        else:
            item["value"] = v
        out.append(item)
    return {"groups": GROUPS, "fields": out, "sections": SECTIONS, "version": STATE.version}


def signature(settings: Settings, group: str) -> tuple:
    return tuple(getattr(settings, k) for k in RESTART_GROUPS[group])
