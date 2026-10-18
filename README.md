# MonRaider

Self-hosted security monitoring for **OPNsense** (and your **Unraid** server). MonRaider collects and stores the
firewall's logs and system state, detects attacks and anomalies, shows dashboards and reports, keeps a device
inventory of everything on your network, and includes an **AI analyst** that you can talk to (Claude or any other
OpenAI-compatible model) to find problems, vulnerabilities, hacking attempts, intruders and strange traffic.
The web UI is protected by a password **plus mandatory MFA** (authenticator app / TOTP or passkey).

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
| DHCP leases (Kea, dnsmasq, ISC) + ARP | API + syslog | **device list**: name, IP, MAC, vendor, interface, lease, online state, per-device activity; **new/rogue device** alerts |
| System / hardware | API | CPU %, load, memory, swap, ZFS ARC, disks, temperatures, states, interface throughput/errors, gateways, services, top processes, firmware updates |
| **Unraid** | Unraid API (GraphQL) + optional Docker socket proxy | CPU/cores, memory, temperatures, network, array/parity, disks (temp, errors, SMART), shares, **Docker containers** (state, updates, CPU/mem) and **their logs**, Unraid syslog, **notifications**, VMs, UPS |

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

Other ready-made compose files are in [`examples/`](examples):

| File | Use it when |
|---|---|
| [`docker-compose.yml`](docker-compose.yml) | standard: MonRaider + its own PostgreSQL |
| [`examples/docker-compose.https.yml`](examples/docker-compose.https.yml) + [`Caddyfile`](examples/Caddyfile) | you want HTTPS (required for **passkeys**) via a bundled Caddy reverse proxy |
| [`examples/docker-compose.external-postgres.yml`](examples/docker-compose.external-postgres.yml) | you already run PostgreSQL 14+ |
| [`examples/docker-compose.all-in-one.yml`](examples/docker-compose.all-in-one.yml) | Portainer / Dockge stacks: all settings inline, no `.env` |
| [`examples/docker-compose.build.yml`](examples/docker-compose.build.yml) | build the image from source |
| [`examples/docker-compose.unraid-socket-proxy.yml`](examples/docker-compose.unraid-socket-proxy.yml) | run **on Unraid** for per-container CPU/memory graphs |
| [`examples/unraid/monraider.xml`](examples/unraid/monraider.xml) | run MonRaider itself **on Unraid** as a Docker template |

### 3. Configure (edit `~/monraider/.env` with any text editor, e.g. `nano .env`)

* `POSTGRES_PASSWORD` – choose a long random password.
* `ADMIN_USER` / `ADMIN_PASSWORD` – the first account (only used when the database is still empty).
* `OPNSENSE_URL` – e.g. `https://192.168.1.1` (add `:port` if the web GUI runs on a different port).
* `OPNSENSE_API_KEY` / `OPNSENSE_API_SECRET` – the values from the file of step 1.
* `AI_API_KEY` – your Anthropic API key (from <https://console.anthropic.com> › *API keys*). The defaults
  `AI_BASE_URL=https://api.anthropic.com/v1/` and `AI_MODEL=claude-opus-5-5` use Claude through Anthropic's
  OpenAI-compatible API. Any other OpenAI-compatible service works as well (OpenAI, OpenRouter, LiteLLM, a local
  Ollama at `http://host:11434/v1/` …) by changing the base URL, model and key.
* `TIMEZONE` – your local zone (used for BSD-style syslog timestamps and the daily report).
* `PUBLIC_URL` – only when you use HTTPS / a reverse proxy, e.g. `https://monraider.home.lan` (for passkeys).

### 4. Start and log in

On the Docker host, in `~/monraider`:

```bash
docker compose up -d
docker compose logs -f monraider     # Ctrl+C to stop following
```

In your browser open `http://<docker-host>:8080`, log in with `ADMIN_USER` / `ADMIN_PASSWORD`. You are sent to
**Account & MFA** and must set up a second factor before anything else is accessible:

* **Authenticator app (TOTP)** – click *Set up authenticator app*, scan the QR code with Google/Microsoft
  Authenticator, Aegis, 1Password, Bitwarden…, type the 6-digit code, *Confirm*.
* **Passkey / security key** – type a name, click *Add passkey* and follow your browser / phone / YubiKey prompt.
  Passkeys only work when MonRaider is opened over **HTTPS** (or `http://localhost`); use
  `examples/docker-compose.https.yml` or your own reverse proxy (Nginx Proxy Manager, Traefik, SWAG…).

Then change the initial password on the same page. Next logins ask for password + TOTP code or passkey.

> Port 514 on the host must be free. If something else uses it, change `"514:5514/udp"` in `docker-compose.yml`
> to e.g. `"1514:5514/udp"` and use that port in OPNsense in the next step.

### Forgot the password or lost the MFA device?

1. On the login page click **Forgot password / lost MFA device?** (or open `http://<docker-host>:8080/reset`) and
   click **Generate reset code**.
2. Read the code from the container log – shell on the Docker host: `docker logs monraider --tail 20`
   (Unraid: Docker tab › MonRaider icon › *Logs*; Portainer: *Containers › monraider › Logs*). It looks like
   `Reset code: 7F3A-91BC (valid 15 minutes, single use)`.
   Alternatively create a code from the shell: `docker exec monraider python -m monraider.cli reset-code`.
3. Enter the code and a new password on the reset page. Password **and** all MFA factors are reset; you set up
   MFA again at the next login. Codes are single use, expire after 15 minutes and are destroyed after 5 wrong attempts.

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

## Adding an Unraid server

1. **Unraid web UI** (Unraid 7.2+ has the API built in; on 6.12–7.1 install the *Unraid Connect* plugin from
   Community Apps first): *Settings › Management Access › API Keys › Create*, name `monraider`, role **Viewer**,
   copy the key. (Or in the Unraid terminal: `unraid-api apikey --create --name monraider --roles VIEWER --json`.)
2. **MonRaider web UI**: *Integrations* › fill in name, URL (e.g. `http://192.168.1.10`) and the API key ›
   *Test connection* › *Add server*. Add as many servers as you like.
3. Optional, for per-container CPU / memory graphs: on Unraid start
   [`examples/docker-compose.unraid-socket-proxy.yml`](examples/docker-compose.unraid-socket-proxy.yml)
   (a read-only Docker API) and enter `http://<unraid-ip>:2375` as *Docker API* for that server.

The **Unraid** page then shows Overview (CPU/cores, memory, temperatures, network, VMs, UPS), Array & disks
(array/parity status, per-disk temperature, usage, errors, shares, SMART), Docker (containers, state, updates,
CPU/memory), Logs (container logs and Unraid syslog, searchable) and Notifications. Disk errors/overheating, stopped
auto-start containers, array problems, UPS on battery and Unraid *warning/alert* notifications become MonRaider alerts.

## Using it

* **Overview** – KPIs and the most important tables of every source in one page.
* **Alerts** – detections ranked by severity; acknowledge / close; **Ask AI** investigates one alert.
* **Security dashboards** (one per function, each with KPIs, charts over time, breakdowns, top-N tables and a live log):
  *Firewall* (actions, interfaces, protocols, ports, countries, rules, allowed inbound, internal hosts being blocked),
  *DNS* (queries vs. blocked, types, rcodes, blocklists, clients, NXDOMAIN, tunneling candidates),
  *Web server* (status classes, attack patterns over time, vhosts, paths, 4xx probing, user agents, clients),
  *Threats* (IDS, CrowdSec, Q-Feeds, alerts by rule/severity, top attackers across all sources, active bans),
  *Zenarmor* (actions, categories, apps, hosts, blocked destinations, threats),
  *Authentication & VPN* (failed/successful logins, usernames tried, config changes) and *System logs*.
* **OPNsense** – gateways, interfaces, services, firmware. **Hardware** – CPU, load, memory/swap/ARC, temperatures,
  disks, states, interface throughput/errors, gateway latency/loss, top processes.
* **Devices** – everything connected to OPNsense (ARP + DHCP leases from Kea / dnsmasq / ISC): online state, name,
  IP, MAC, vendor, interface, lease, first/last seen, events/blocks/DNS queries/alerts per device; mark devices as
  trusted, rename them, add notes.
* **Unraid** – see above.
* **Event search** – search all stored logs by source, IP/CIDR, action, text, severity, time range.
* **Reports** – 24h / 7d / 30d reports, optionally with an AI-written analysis; print to PDF or download JSON.
  Set `AI_DAILY_REPORT=true` to get one automatically every morning.
* **AI Analyst** – chat with the model. It can run read-only SQL against the log database, search events, profile an
  IP, read alerts, OPNsense + Unraid status and traffic statistics, and answers with evidence and remediation steps.
  Credentials (users, MFA secrets, API keys) are never accessible to it. Data sent to the AI provider consists of the
  query results the model asks for (IPs, domains, log lines).

## Configuration reference

All settings are environment variables (see `.env.example`). The most important:

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | `postgresql://monraider:monraider@db:5432/monraider` | PostgreSQL connection |
| `ADMIN_USER` / `ADMIN_PASSWORD` | `admin` / random (printed in the log) | first account, created only when no user exists |
| `PUBLIC_URL` / `WEBAUTHN_RP_ID` | auto | public https URL / passkey relying-party id when behind a reverse proxy |
| `COOKIE_SECURE` | `false` | mark the session cookie HTTPS-only |
| `SECRET_KEY` | generated, stored in DB | cookie signing key |
| `UNRAID_NAME` / `UNRAID_URL` / `UNRAID_API_KEY` / `UNRAID_DOCKER_URL` | – | optional first Unraid server (more via *Integrations*) |
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

* Login = password (scrypt-hashed) + mandatory TOTP or passkey; failed logins are rate limited per IP and logged.
  Password changes and resets invalidate all other sessions.
* Put MonRaider on your LAN / management network; don't expose port 8080 to the internet (use a VPN or a reverse
  proxy with TLS if you need remote access).
* The reset code only appears in the container log, so a reset requires access to the Docker host.
* Use `SYSLOG_ALLOWED_SENDERS=<opnsense-ip>` so nobody else can inject log lines.
* The AI's SQL tool runs inside read-only transactions with a statement timeout and only accepts `SELECT`.

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest -q                                   # parser tests
DATABASE_URL=postgresql://... ADMIN_PASSWORD=x python -m monraider.main
python tools/simulate.py --port 5514                  # send simulated OPNsense logs (scans, brute force, tunnels…)
python tools/mock_opnsense.py --port 18443            # fake OPNsense API  (OPNSENSE_URL=http://127.0.0.1:18443)
python tools/mock_unraid.py --port 18500              # fake Unraid API    (UNRAID_URL=http://127.0.0.1:18500, key test-key)
TEST_DATABASE_URL=postgresql://... python -m pytest   # also runs every dashboard query against PostgreSQL
```

Architecture: one asyncio Python process (FastAPI web UI, UDP/TCP syslog receiver with RFC 3164/5424 + octet
counting, OPNsense API poller, detection engine, retention) writing to PostgreSQL (`events`, `alerts`, `metrics`,
`snapshots`, `devices`, `reports`, `ai_chats`). Front-end libraries (Chart.js, marked, DOMPurify) are vendored, so the
UI works without internet access.
