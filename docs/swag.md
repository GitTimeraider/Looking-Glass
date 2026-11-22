# SWAG, CrowdSec, fail2ban and honeypot (Docker)

[← Back to the README](../README.md)

Reading a [SWAG](https://docs.linuxserver.io/general/swag/) reverse proxy (nginx + fail2ban) and a
[CrowdSec](https://www.crowdsec.net/) container that run on the **same Docker host** as Looking Glass (e.g. an Unraid
server). Read only: nothing is changed in SWAG or CrowdSec.

| What | How | What you get |
|---|---|---|
| SWAG nginx access logs | the log file, from SWAG's log folder mounted read-only | every request: site, path, status, client, country, user agent, attack patterns (SQLi, RCE, traversal, scanners) |
| SWAG nginx error logs | the same | errors, rate limiting, `access forbidden`, **CrowdSec bouncer blocks** and **AppSec / WAF blocks** of SWAG's crowdsec mod |
| fail2ban (inside SWAG) | the same (`fail2ban/fail2ban.log`) | matches, bans, unbans per jail, *banned now* |
| Honeypot | paths, host names, jails or log files you mark as traps | every hit, who it was, what they tried |
| CrowdSec (Docker) | its Local API (machine login and/or bouncer key) + metrics | alerts with scenario, AS, country, target site / URI, AppSec rule, decisions; active decisions incl. the community blocklist; which logs CrowdSec reads, AppSec counters, which bouncers are alive |

Everything shows up under **Proxy & web security › SWAG & CrowdSec** (tabs *Web*, *CrowdSec*, *fail2ban*, *Honeypot*).
SWAG's requests and Docker-CrowdSec's alerts and decisions are also part of the Overview's *SWAG & CrowdSec*
widgets, the reports, the AI analyst and the web attack / scanner / CrowdSec detections (SWAG's events have program
`swag`, Docker-CrowdSec's `crowdsec-lapi`). They are kept apart from the OPNsense CrowdSec plugin: *OPNsense security ›
Threats* and the Overview's *CrowdSec (OPNsense)* widgets count only the plugin; alerts say *CrowdSec (OPNsense)* or
*CrowdSec (SWAG)*, and the reports have a section for each.

## 1. Give Looking Glass SWAG's log folder

SWAG keeps all logs in its `/config/log` folder: `nginx/access.log`, `nginx/error.log`, `fail2ban/fail2ban.log`.

**Unraid web UI** › *Docker* › click the **Looking Glass** icon › *Edit* › at the bottom **Add another Path, Port,
Variable, Label or Device**:

* Config Type: **Path**
* Name: `SWAG logs`
* Container Path: `/swag/log`
* Host Path: SWAG's log folder, normally `/mnt/user/appdata/swag/log`
* Access Mode: **Read Only**

*Add*, then *Apply* (the container is recreated).

**docker compose instead** (file `docker-compose.yml` of Looking Glass, on the Docker host) - add under
`looking-glass:` › `volumes:` and run `docker compose up -d` in that folder:

```yaml
      - /mnt/user/appdata/swag/log:/swag/log:ro   # SWAG's /config/log
```

Looking Glass runs as user 10001 (or your PUID). SWAG's logs are normally readable by everyone (`-rw-r--r--`). If the
test below says *permission denied*, run this in a **shell on the Docker host** (Unraid: *Terminal* icon top right):

```bash
chmod -R o+rX /mnt/user/appdata/swag/log
```

## 2. Get a CrowdSec login for Looking Glass

In a **shell on the Docker host** (`crowdsec` = the name of your CrowdSec container, see `docker ps`):

```bash
docker exec crowdsec cscli machines add lookingglass --password 'choose-a-long-password' -f /dev/null
```

This is the login for alerts (the `-f /dev/null` keeps CrowdSec's own credentials file untouched). It is also what
the **Unban** button of *SWAG & CrowdSec › CrowdSec › Active bans* uses (`cscli decisions delete --id`) - without the
machine login the list is shown but has no Unban buttons. Optional - the active decisions including the community
blocklist:

```bash
docker exec crowdsec cscli bouncers add lookingglass
```

It prints an API key **once**; copy it.

Looking Glass must reach CrowdSec's API (port 8080 inside the CrowdSec container):

* **Same Docker network** (best): on Unraid, *Docker* › Looking Glass › *Edit* › *Network Type*: the custom network
  SWAG and CrowdSec use (e.g. `proxynet`). The URL is then `http://crowdsec:8080`.
* **Otherwise**: map the port in the CrowdSec container (e.g. host 8081 → container 8080) and use
  `http://<server-ip>:8081`.

Optional metrics (port 6060 inside the CrowdSec container, same choice as above): CrowdSec's `config.yaml` needs
`prometheus:` › `listen_addr: 0.0.0.0` (the default in the Docker image).

## 3. Settings in Looking Glass

**Looking Glass web UI** › *Settings* › **SWAG & CrowdSec**:

* **SWAG log folder**: `/swag/log`
* **nginx access logs / error logs / fail2ban log**: keep the defaults unless you changed SWAG's log files. Several
  files and `*` work (`nginx/*access.log` for per-site logs).
* **Honeypot** (optional, see below)
* **CrowdSec Local API URL**: `http://crowdsec:8080`; **Machine name** `lookingglass` + its **password**; optionally
  the **Bouncer API key** and the **metrics URL** `http://crowdsec:6060/metrics`.
* No fail2ban? Empty the **fail2ban log** field: the *fail2ban* tab and widgets disappear.
* **Test connection** - lists every log file (readable? lines understood?) and every CrowdSec part. Then **Save**.

Also check *Settings › Ingestion & network › Time zone*: nginx's error log and fail2ban write local time without a
zone, so it must be the time zone of the SWAG container (its `TZ` variable). Access-log times carry their own zone.

Then **Setup & status** shows *SWAG (nginx + fail2ban)* and *CrowdSec (Docker)* with what arrives and what is missing
(for example: CrowdSec does not read SWAG's logs, or no bouncer has asked CrowdSec for decisions - SWAG's crowdsec
mod is not working).

**Active bans** (tab *CrowdSec*) lists the decisions in force - address, country, type, scenario, origin and the
**time left** - refreshed at every poll (*Poll interval*). **Unban** asks for confirmation, then removes the decision
in CrowdSec; SWAG's bouncer lets the address in again almost at once (live mode, the default; it
caches an answer for `CACHE_EXPIRATION` seconds) or at its next update (stream mode: `UPDATE_FREQUENCY`). CrowdSec can ban the address again if it keeps misbehaving. Community-blocklist
bans (CAPI) are not listed there and cannot be unbanned one by one - use an allowlist in CrowdSec for those. fail2ban
bans (tab *fail2ban*) are read from its log; lifting one needs `docker exec swag fail2ban-client set <jail> unbanip <ip>`
in a shell on the Docker host.

The first time a log is read, its last 5 MB are read too (*First read: older lines*), so the dashboards are not empty;
CrowdSec's alerts of the last 7 days are read on the first poll. After that only new lines / alerts. Where each file
was read up to is stored, so a restart neither misses nor repeats lines, and log rotation is followed.

## Only local or only internet traffic

**All / Local / Non-local** at the top of *SWAG & CrowdSec* filters every tab, chart and table by source address
(local = private, CGNAT / Tailscale, loopback and link-local), e.g. *Non-local* to hide the NAS's own Unraid page and
Nextcloud sync, or *Local* to see only them. Clicking a chart opens Event search with the same filter; the live log
follows the switch. The current bans and CrowdSec's metrics are not events and are shown as they are.

## Honeypot

A honeypot is something nobody legitimate ever touches, so every hit is a scanner or an intruder. In *Settings › SWAG
& CrowdSec › Honeypot*, one per line:

| Line | Means |
|---|---|
| `/wp-login.php` | a request path; without `*` a prefix (also `/wp-login.php?x`), with `*` a pattern (`/secret*/admin`) |
| `honeypot.example.com` | every request to that host name (a decoy subdomain) |
| `jail:nginx-honeypot` | every match / ban of that fail2ban jail |
| `file:nginx/honeypot.log` | everything in that log file (a decoy site with its own `access_log`) |

Jails and log files with *honeypot* in their name count automatically. **With none of these set, every honeypot
widget stays at 0.**

### Honeypot from your nginx config file (no typing)

Already have the trap locations in a SWAG config file, e.g.

```nginx
location ~* ^/(wp-admin|wp-login\.php|xmlrpc\.php|phpmyadmin|\.git|\.env|\.aws|server-status|cgi-bin|boaform|HNAP1)(/|\.|$) {
    return 404;
}
```

then point Looking Glass at that file instead of copying the paths:

1. **Unraid web UI › Docker tab ›** click the Looking Glass icon › **Edit** › **Add another Path, Port, Variable,
   Label or Device**: Config Type *Path*, Container Path `/swag/nginx`, Host Path `/mnt/user/appdata/swag/nginx`
   (SWAG's nginx folder), Access Mode **Read Only** › **Add** › **Apply**. (Docker Compose:
   `- /path/to/swag/config/nginx:/swag/nginx:ro`.)
2. **Looking Glass web UI › Settings › SWAG & CrowdSec › Honeypot from nginx config**: the file as the container sees
   it, e.g. `/swag/nginx/honeypot.conf` (a path without a leading `/` is taken from the folder above the log folder, so
   `nginx/honeypot.conf` works too; several files and `*` are allowed). **Test connection** shows how many trap
   locations it found, then **Save**.

Every `location` in the file is a trap, matched the way nginx does it: `~` (regex), `~*` (regex, any case), `=`
(exact path) and prefix (`^~ /x/` or `/x`), against the decoded path without the query. A location that matches
every page (`location /`) is skipped, as is a named one (`@x`); put the traps in a file of their own rather than
pointing at a whole site config. The file is read again within 30 seconds whenever it changes - **adding a path to the
regex is all you do**. When the traps change, the requests of the last 30 days are checked again, so the Honeypot tab
shows earlier hits at once (no alerts are raised for those old hits). *Setup & status* shows the number of traps
read, or why the file could not be read.

Hits are marked (`data.honeypot`, tag `honeypot`) and shown under *SWAG & CrowdSec › Honeypot*. Whether a visitor got
banned is taken from **CrowdSec** (a ban for any scenario, by CrowdSec in Docker or the OPNsense plugin): the key
figures *Banned by CrowdSec* (banned in the period or now) and *Banned now*, and the *CrowdSec* / *Ban ends* columns of
*Who touched the honeypot* (also on the Overview widget and in reports). *Bans by honeypot jails* is only shown when
fail2ban is set up. Alerts (rule
*Honeypot touched*): one per address - **high** from inside your network, from the internet the level of *Honeypot hit
from the internet: alert* (default low, or off).

A simple decoy in SWAG (file `/config/nginx/site-confs/default.conf` of SWAG, inside its `server { … }` block;
restart SWAG afterwards with `docker restart swag`): paths that only scanners ask for, logged to their own file:

```nginx
location ~* ^/(wp-login\.php|xmlrpc\.php|phpmyadmin|\.env|\.git/) {
    access_log /config/log/nginx/honeypot.log;
    return 404;
}
```

Then add `file:nginx/honeypot.log` and keep `nginx/access.log` in the access logs (those requests are then only in
`honeypot.log` - add it to CrowdSec's `acquis.yaml` too if CrowdSec should see them). To also ban them, a fail2ban jail named e.g. `nginx-honeypot` on that file counts automatically.

## Optional: the site name in every request

SWAG's default access log has no host name, so the *Sites* chart shows *(not logged)*. To get it without changing the
log CrowdSec reads, let nginx write a second log for Looking Glass. In SWAG's `/config/nginx/nginx.conf`, inside
`http { … }`:

```nginx
log_format lookingglass '$host $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';
access_log /config/log/nginx/lookingglass.log lookingglass;
```

Restart SWAG (`docker restart swag` in a shell on the Docker host), then in *Settings › SWAG & CrowdSec › nginx access
logs* replace `nginx/access.log` by `nginx/lookingglass.log` (not both: every request would be counted twice).
SWAG's logrotate already rotates every `*.log` in that folder.

## Alerts

| Rule (*Settings › Alert filters › SWAG & CrowdSec*) | Severity |
|---|---|
| fail2ban banned an internet address / an address inside | the level of *fail2ban ban of an internet address: alert* (default low, or off) / **high** |
| Honeypot touched from the internet / from inside | *Honeypot hit from the internet: alert* (default low) / **high** |
| *CrowdSec (SWAG): …* - CrowdSec banned an internet address / an address inside | the level of *CrowdSec (SWAG) ban of an internet address: alert* (default low, info, or **off**: no alert, and the open ones are closed - the bans stay visible on the CrowdSec tab) / **high** |
| Web attacks and scanners on SWAG | *Settings › Data & detection › Web attacks* |
| CrowdSec Local API unreachable for 10 minutes | medium, closes by itself |

### Tied to OPNsense and Unraid

What SWAG, CrowdSec, fail2ban and the honeypot see is also matched with what the OPNsense firewall and the Unraid
containers see. On its own each says little; together they point at an attack that worked. These rules are under
*Settings › Alert filters › Correlation*:

| Rule | When | Severity |
|---|---|---|
| **Device connected to an address that attacked the web proxy** | an internet address attacked SWAG (web attack pattern, honeypot, CrowdSec, fail2ban, bouncer / WAF block) and afterwards a device **inside** connects out to it (OPNsense firewall log): a reverse shell, a payload download or data sent home. Addresses that forward for others (X-Forwarded-For) and addresses 3+ of your devices talk to (CDNs, cloud) are skipped | **high**, **critical** when the firewall let it through |
| **Banned on SWAG, still let in by the firewall** | an address SWAG's CrowdSec or fail2ban banned, or that touched a honeypot, is afterwards still passed by the OPNsense firewall to **another** port (SSH, Plex, a VPN …). Those bans only work inside SWAG - block it on OPNsense (*Blocked addresses*). Already blocked addresses are skipped; which ports are SWAG itself: *Settings › SWAG & CrowdSec › Ports forwarded to SWAG* (default `80,443`) | medium |
| **Web attack, then trouble in the site's container** | an attack request on a site got a successful answer (2xx / 3xx), and within 60 minutes the site's Unraid container keeps restarting, turned unhealthy, stopped or logged errors. The container belongs to the site when a part of its host name is the container's name (`nextcloud.example.com` → `nextcloud`) | high |

And the other way round: a **web attack** or **web scanning** alert for an internet address that OPNsense also knows -
Suricata hits, Q-Feeds / CrowdSec blocklist hits, a port scan alert - is rated one step higher (up to high) and says so.
All three rules feed the *attack chain*: a device that called an attacker back is *command & control*, and a web
attack followed by container trouble is an outside chain *attack → impact*.

## Troubleshooting

* **"… does not exist in the Looking Glass container"** - the volume of step 1 is missing or has another container
  path than the one in Settings.
* **CrowdSec: "wrong machine name / password"** - list the machines in a shell on the Docker host with
  `docker exec crowdsec cscli machines list`; a machine must be *validated* (`cscli machines validate lookingglass`).
* **CrowdSec: ConnectError / timeout** - Looking Glass cannot reach the container: same Docker network, or the host
  IP and the mapped port (step 2).
* **Development**: `python tools/mock_crowdsec.py --port 18080` is a fake Local API (machine `lookingglass` /
  `test-pass`, bouncer key `test-bouncer-key`, metrics at `/metrics`).
