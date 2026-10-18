# MonRaider

Self-hosted security monitoring for **OPNsense**. MonRaider collects and stores the firewall's logs and system state,
detects attacks and anomalies, shows dashboards and reports, and includes an **AI analyst** that you can talk to
(Claude or any other OpenAI-compatible model) to find problems, vulnerabilities, hacking attempts, intruders and
strange traffic.

Image: `ghcr.io/gittimeraider/monraider:latest` (linux/amd64 + linux/arm64), built by GitHub Actions.

## What it collects

| Source | How | What you get |
|---|---|---|
| Firewall (pf `filterlog`) | syslog, or API fallback | blocked/allowed traffic, rule names, scans, sweeps |
| nginx plugin | syslog (access via nginx *SYSLOG Targets*, errors automatically) | requests, status codes, attack patterns (SQLi, RCE, traversal, scanners), WAF / rate limit |
| Unbound DNS | API (reporting DB) and/or syslog (`log-queries`) | per-client queries, blocklist hits, NXDOMAIN, DNS tunneling / DGA detection |
| CrowdSec | API (alerts + decisions) + syslog | scenarios, bans |
| Suricata IDS/IPS | API + syslog | signatures, classifications |
| Zenarmor | syslog streaming (paid editions) | L7 apps, categories, security tags |
| Q-Feeds | API (events + stats) | threat-intel matches, especially **internal hosts contacting malicious IPs** |
| SSH / web GUI / OpenVPN / IPsec | syslog | failed and successful logins, config changes |
| DHCP + ARP | syslog + API | device inventory, **new/rogue device** alerts |
| System | API | CPU load, memory, disks, temperature, states, interfaces, gateways, services, firmware updates |

## Built-in detections

Port scans, host sweeps, brute force (SSH / web GUI / VPN), **successful login after failures**, logins from public IPs,
web attacks & scanners, IDS signatures, CrowdSec alerts, Q-Feeds hits (inbound probing / outbound C2), Zenarmor threats,
DNS tunneling, DGA domains, NXDOMAIN storms, malicious-domain lookups, internal hosts blocked to many destinations,
outbound connections on suspicious ports (Tor, IRC, RDP, SMB, mining pools…), new devices, gateway down, resources
(disk/memory/states) high, stopped services, firmware updates available and "logs stopped arriving" (possible tampering).

---

## Installation

You need a machine that runs Docker (Linux server, NAS, VM…) and that the OPNsense box can reach.
MonRaider uses its own PostgreSQL container (included in the compose file) — no separate SQL server needed.
If you prefer an existing PostgreSQL 14+ server, drop the `db` service and point `DATABASE_URL` at it.

### 1. Create the API key in OPNsense (OPNsense web UI)

1. Open **System › Access › Users**, click **+** and create a user, e.g. `monraider` (any random password).
2. Give it privileges. Simplest: tick **GUI - All pages**. Stricter: only the *Diagnostics*, *Reporting*, *Firmware*,
   *Gateways*, *Unbound*, *CrowdSec*, *Q-Feeds* and *Intrusion Detection* pages (MonRaider's *Setup & Status* page
   shows every API call that is refused, so you can add the missing privilege later).
3. Save, open the user again, scroll to **API keys** and click **+**. Your browser downloads a text file with
   `key=...` and `secret=...`. Keep it for step 3.

### 2. Get the files (shell on your Docker host)

```bash
mkdir -p ~/monraider && cd ~/monraider
curl -O https://raw.githubusercontent.com/GitTimeraider/MonRaider/master/docker-compose.yml
curl -o .env https://raw.githubusercontent.com/GitTimeraider/MonRaider/master/.env.example
```

### 3. Configure (edit `~/monraider/.env` with any text editor, e.g. `nano .env`)

* `POSTGRES_PASSWORD`, `ADMIN_PASSWORD` – choose strong passwords.
* `SECRET_KEY` – paste the output of `openssl rand -hex 32` (run on the Docker host).
* `OPNSENSE_URL` – e.g. `https://192.168.1.1` (add `:port` if the web GUI runs on a different port).
* `OPNSENSE_API_KEY` / `OPNSENSE_API_SECRET` – the values from the file of step 1.
* `AI_API_KEY` – your Anthropic API key (from <https://console.anthropic.com> › *API keys*). The defaults
  `AI_BASE_URL=https://api.anthropic.com/v1/` and `AI_MODEL=claude-opus-5-5` use Claude through Anthropic's
  OpenAI-compatible API. Any other OpenAI-compatible service works as well (OpenAI, OpenRouter, LiteLLM, a local
  Ollama at `http://host:11434/v1/` …) by changing the base URL, model and key.
* `TIMEZONE` – your local zone (used for BSD-style syslog timestamps and the daily report).

### 4. Start (shell on your Docker host, in `~/monraider`)

```bash
docker compose up -d
docker compose logs -f monraider     # Ctrl+C to stop following
```

Open `http://<docker-host>:8080` in your browser and log in with `ADMIN_USER` / `ADMIN_PASSWORD`.

> Port 514 on the host must be free. If something else uses it, change `"514:5514/udp"` in `docker-compose.yml`
> to e.g. `"1514:5514/udp"` and use that port in OPNsense in the next step.

### 5. Send logs from OPNsense (OPNsense web UI)

1. **Remote syslog** – **System › Settings › Logging**, tab **Remote** (on older versions *System › Settings › Logging / targets*), click **+**:
   * Enabled ✓, Transport `UDP(4)` (or `TCP(4)`)
   * Applications: leave **empty** (= everything, recommended)
   * Levels: select everything from *info* up
   * Hostname: IP of your Docker host, Port: `514`
   * **rfc5424** ✓
   * Save, then **Apply**.
2. **Firewall logging** – default block rules are logged already. Open your important pass rules / port forwards
   (**Firewall › Rules › WAN** etc.) and tick **Log packets that are handled by this rule** so allowed traffic is visible too.
3. **Unbound DNS** – **Reporting › Settings**: enable *Unbound DNS reporting* (MonRaider pulls queries via the API).
   For complete query logs also enable **Services › Unbound DNS › Advanced › Log Queries** (and *Log Replies*).
4. **nginx plugin** – **Services › Nginx › Configuration**, tab **Other › SYSLOG Targets**: add a target
   (Host = Docker host, Port = 514). Then edit each **HTTP(S) › HTTP Server**, select that target under
   *SYSLOG targets* and use Access Log Format `main` or `main_ext`. Apply.
5. **Suricata** – **Services › Intrusion Detection › Administration**: tick **Enable syslog alerts**
   (optionally *Enable eve syslog output*). Alerts are also pulled from the API.
6. **Zenarmor** (SOHO/Business edition) – **Zenarmor › Configuration › Reporting & Data › Streaming Data**:
   stream to a syslog server = Docker host, port 514, and select the event types.
7. **CrowdSec** and **Q-Feeds** need nothing extra – they are read through the API.

Check **Setup & Status** in MonRaider: every source should show a recent "last message" and every API job "ok"
(jobs for plugins you don't have show `n/a`).

### 6. Optional: GeoIP countries (shell on your Docker host)

Create a free account at MaxMind, download **GeoLite2-City.mmdb** (or Country) and place it in `~/monraider/data/`,
then `docker compose restart monraider`. Make sure the `data` folder is readable by UID 10001
(`sudo chown -R 10001 ~/monraider/data`).

### Updating (shell on your Docker host, in `~/monraider`)

```bash
docker compose pull && docker compose up -d
```

---

## Using it

* **Dashboard** – KPIs, events over time, top blocked sources/ports/countries, allowed inbound, logins, DNS, web,
  IDS, CrowdSec, Q-Feeds, Zenarmor, internal top talkers, new devices.
* **Alerts** – detections ranked by severity; acknowledge / close; **Ask AI** investigates one alert.
* **Events** – search all stored logs by source, IP/CIDR, action, text, severity, time range (click a row for details).
* **System** – OPNsense health, firmware, gateways, interfaces with throughput graphs, services, device inventory.
* **Reports** – 24h / 7d / 30d reports, optionally with an AI-written analysis; print to PDF or download JSON.
  Set `AI_DAILY_REPORT=true` to get one automatically every morning.
* **AI Analyst** – chat with the model. It can run read-only SQL against the log database, search events, profile an
  IP, read alerts, system status and traffic statistics, and answers with evidence and remediation steps.
  Data sent to the AI provider consists of the query results the model asks for (IPs, domains, log lines).

## Configuration reference

All settings are environment variables (see `.env.example`). The most important:

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | `postgresql://monraider:monraider@db:5432/monraider` | PostgreSQL connection |
| `ADMIN_USER` / `ADMIN_PASSWORD` | `admin` / random (printed in the log) | web login |
| `SECRET_KEY` | random per start | cookie signing key (set it, or you are logged out on every restart) |
| `SYSLOG_UDP_PORT` / `SYSLOG_TCP_PORT` | `5514` | container syslog ports |
| `SYSLOG_ALLOWED_SENDERS` | *(all)* | comma-separated IPs/CIDRs allowed to send syslog |
| `OPNSENSE_URL`, `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET` | – | API access |
| `OPNSENSE_VERIFY_SSL` / `OPNSENSE_CA_FILE` | `false` / – | TLS verification of the OPNsense GUI certificate |
| `POLL_INTERVAL` | `60` | seconds between system polls |
| `FIREWALL_LOG_PULL` | `auto` | `auto`/`always`/`never` pull of the firewall log through the API |
| `UNBOUND_QUERY_PULL`, `CROWDSEC_PULL`, `QFEEDS_PULL`, `IDS_PULL` | `true` | per-source API pulls |
| `AI_BASE_URL` / `AI_MODEL` / `AI_API_KEY` | Anthropic / `claude-opus-5-5` / – | AI endpoint |
| `AI_DAILY_REPORT`, `AI_DAILY_REPORT_HOUR` | `false`, `7` | automatic daily AI report |
| `RETENTION_DAYS` / `METRICS_RETENTION_DAYS` | `30` / `90` | data retention |
| `INTERNAL_NETWORKS` | – | extra CIDRs treated as internal |
| `GEOIP_DB` | `/data/GeoLite2-City.mmdb` | MaxMind database path |

## Security notes

* Put MonRaider on your LAN / management network; don't expose port 8080 to the internet (use a VPN or a reverse
  proxy with TLS and extra authentication if you need remote access).
* Use `SYSLOG_ALLOWED_SENDERS=<opnsense-ip>` so nobody else can inject log lines.
* The AI's SQL tool runs inside read-only transactions with a statement timeout and only accepts `SELECT`.

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest -q                                   # parser tests
DATABASE_URL=postgresql://... ADMIN_PASSWORD=x python -m monraider.main
python tools/simulate.py --port 5514                  # send simulated OPNsense logs (scans, brute force, tunnels…)
```

Architecture: one asyncio Python process (FastAPI web UI, UDP/TCP syslog receiver with RFC 3164/5424 + octet
counting, OPNsense API poller, detection engine, retention) writing to PostgreSQL (`events`, `alerts`, `metrics`,
`snapshots`, `devices`, `reports`, `ai_chats`). Front-end libraries (Chart.js, marked, DOMPurify) are vendored, so the
UI works without internet access.
