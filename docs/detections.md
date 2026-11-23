# Detections and alerts

[← Back to the README](../README.md)

What Looking Glass detects, how alerts are muted, mailed and closed, and how severity is decided.

## Built-in detections

Port scans, host sweeps, brute force (SSH / web GUI / VPN), **successful login after failures**, logins from public IPs,
web attacks & scanners ([SWAG](swag.md)), Suricata signatures, CrowdSec alerts (OPNsense plugin and
CrowdSec in Docker), fail2ban bans, honeypot hits, Q-Feeds hits (inbound probing / outbound C2),
DNS tunneling, DGA domains, NXDOMAIN storms, malicious-domain lookups, internal hosts blocked to many destinations,
outbound connections on suspicious ports (Tor, IRC, RDP, SMB, mining pools…), new devices, UniFi access point / switch
offline, foreign APs using your Wi-Fi name ("evil twin"), rogue DHCP servers, gateway down, resources
(disk/memory/states) high, services stopped for longer than a few minutes (Settings › OPNsense › Service alerts wait), firmware updates available and "logs stopped arriving" (possible tampering).
A **source that went quiet**: a source that normally sends something every hour (firewall, web server, DNS,
Suricata …) with no new events for 3 hours (Settings › Data › *Alert when a source goes quiet*; 0 = off) - a stalled log
pull, a stopped plugin, a removed syslog target. Counted by event time, so a pull that runs hours behind counts too.
Closes by itself when events come back. Sources switched off in Settings never raise it.

**WAN quality** (*Settings › OPNsense › WAN …*, page *Infrastructure › OPNsense › WAN quality*): **WAN much slower than normal**
when the median latency of a gateway over the last 24 hours is at least 200 % of the median of the 7 days before
*and* at least 15 ms above it (needs 3 days of history), and **WAN packet loss** when its average loss over 24 hours
is 2 % or more (medium from 10 %). Both close by themselves when the line is fine again.

**Snoozed alerts** (*General › Snooze & maintenance*) are stored closed and not mailed while the snooze lasts; see
[Snooze and maintenance windows](user-guide.md#snooze-and-maintenance-windows).

**Logins on all systems**: OPNsense (web GUI, SSH, API, VPN), **Unraid** (web GUI and SSH, from its syslog) and the
**UniFi controller** (admin logins with their address) all feed the same login rules: brute force, password spraying,
login after failures, logins from the internet and logins from a new country. Alert titles say which system was hit
("Brute force against Tower (webGUI)"). The UniFi Network application does not report *failed* admin logins.

**Correlation rules** (inspired by RITA / Zeek beacon analysis, Sigma rules and MITRE ATT&CK):

| Rule | What it finds |
|---|---|
| Password spraying | one address trying 5+ usernames in an hour (T1110.003) |
| Distributed brute force | one username attacked from 10+ addresses (botnet); critical if one of them then logs in |
| Login from a new country / impossible travel | a user logging in from a country never seen in 90 days, or two countries within 2 h (needs GeoIP) |
| Beaconing | a device contacting a domain / address nobody else uses at a near-constant rhythm for hours - malware check-ins (T1071) |
| Lateral movement | one device reaching SSH / SMB / RDP / WinRM / VNC / Docker API on 5+ internal hosts in 15 min (T1021) |
| DNS bypass | devices using DNS servers on the internet directly, past your resolver and blocklists |
| Call back to a web attacker | a device inside opening a connection out (not replies on the attacker's own session) to an address that attacked the web proxy (SWAG) shortly before - reverse shell / payload download; high, critical when let through ([SWAG](swag.md#tied-to-opnsense-and-unraid)) |
| Banned on SWAG, still let in | an address SWAG's CrowdSec / fail2ban banned (or that touched a honeypot) that the OPNsense firewall still passes to other forwarded ports; medium |
| Web attack, then container trouble | a successful answer to an attack request on a site, then its Unraid container crashes / turns unhealthy / logs errors within 60 min; high |
| Attack chain | ties **open** alerts about one address together: outside *recon → attack → access / impact*, or inside *threat sign → command & control → spreading* (plus "new device"); needs one strong link (threat intel, IDS, lateral movement, scan, canary … or a behaviour alert rated high), so e.g. beaconing to a time server plus a big download is no chain; acknowledged alerts and a rule you closed as false positive for that address (30 days) are left out; high or critical |

*NAT redirects*: a port forward that sends DNS / NTP (or any port) to your own server, e.g. *VLAN_IoT TCP/UDP to !RFC1918 port domain ⇒ VLAN_IoT address*, answers those packets locally, but the firewall's pass log still shows the original destination. DNS bypass, Tor and threat-feed alerts therefore skip traffic on redirected ports that the firewall never logged leaving towards the internet - e.g. an NTP query to a pool server that is also a Tor relay. Looking Glass knows the redirects from the API (privilege *Firewall: NAT: Port Forward*) or from the NAT rule's own log lines (tick *Log* on it).

*DGA domains* are random-looking names such as `kq3v9x7w2m8p4z1r.com`, which malware generates by the thousands
(Domain Generation Algorithm) to find its control server. Some CDNs and latency probes use random names too: list
those under *Settings › Data & detection › DNS: domains to ignore* (subdomains included) and the DNS checks skip them.

## Muting alerts (alert filters)

*Settings › Alert filters* (or **Mute similar…** on any alert, which pre-fills one) stops alerts you don't want:

* Conditions: **severity** (e.g. "low and below"), **rules / sources** (tick one or more), **text** in the title or
  description (several terms: comma separated, *any* or *all* of them), **IP addresses / networks** (source or
  destination) and **source / destination ports** (ports and ranges, `22, 8000-8100`). A port condition matches only
  when *every* port of the alert's events on that side is in the list - muting port 22 never hides an alert that also
  hit 3389 - and never for an alert without known ports. **Mute similar…** pre-fills the destination port when the
  alert has exactly one. Ranges copied from documentation with an en dash (`19294–19344`) are accepted too. Example,
  Discord voice calls flagged as beaconing: rule *Beaconing* + IP *192.168.3.3* + destination ports *19294-19344*, all
  conditions must match (the ports of an address-beaconing alert are those of the traffic to that address only).
* **AND / OR**: per filter choose *all conditions must match* or *any one is enough*. Inside one condition it is always
  "or" (any ticked rule, any listed IP), and filters together work as "or" - so "(A and B) or C" is two filters.
* Action: **don't create** the alert, **create it as closed** (kept under Alerts › Closed for reference), or
  **change the severity** to the level you choose - e.g. "new device on 192.168.30.0/24 → high" or "port scans → info".
  Severity changes are applied first, mute filters then see the new severity. Logs, dashboards and reports are never
  affected.
* **Change severity…** on any alert pre-fills such a rule; re-rated alerts show "⚙ Severity changed by … (was low)"
  with **Undo** (deleting the rule gives open alerts their own severity back).
* **Preview** shows what a filter would have caught in the last 30 days; **close matching** closes existing ones.
* **Unmute**: alerts matched by a filter show "🔇 Muted by …" with an **Unmute** button on the Alerts page; in the
  filter list, untick *On* to pause a filter or use *unmute (delete)*. Each filter counts its hits.
* **Undo / adjust anything**: every muted or re-rated alert links (✎) to the rule that did it, so you can edit, pause or
  delete it; a re-rated alert also has **Restore <old severity>** for just that alert. The Alerts page shows
  **Mute & severity rules (N active)**, a direct link to the full list.
* **Configuration changes** name what was changed and by whom, e.g. *Configuration change on fw: Nginx by admin from
  192.168.1.10* (taken from the OPNsense audit log line). Filter on the part with the text condition (`Nginx`,
  `Unbound DNS`, `firewall rules` …), on the user (`admin`) or on the IP condition (the address the change came from).
  **Mute similar…** on such an alert pre-fills the rule and the changed part.

## Email notifications

*Settings › Email & notifications*:

1. **Mail server (SMTP)**: server, port, encryption (`starttls` on 587, `ssl` on 465, `none` only for a relay inside
   your network), username / password (stored encrypted; Gmail and Microsoft 365 with MFA need an **app password**),
   sender address and the address you open Looking Glass on (for the links in the mails). **Send test mail** checks it
   before you save.
2. **Notification rules** ("mail me when…"): the same conditions as alert filters plus a **minimum severity**
   (e.g. *high and above*), one or more recipients, **how often** (right away, or at most every 5 min … daily digest:
   alerts in between are bundled into one mail) and *also mail when the severity of an alert goes up*. Each alert is
   mailed once per rule; muted alerts are never mailed. **Preview** shows what a rule would have matched, **send test**
   mails the newest matching alert, untick *On* to pause a rule. Delivery errors show in the rule list.

## Closing an alert

**Close** sticks: while the same thing keeps happening, the closed alert only counts the new sightings - it comes back
as open only when it gets **worse** (higher severity) or after 24 quiet hours. **Close as false positive** does the same
and also teaches Looking Glass: the *exact same* alert coming back later (same rule, device, port and remote address,
no higher severity) is stored closed as **known false positive #id**, linked to your verdict and not notified - for 30
days after it was last seen (*Settings › Behaviour & ML › Repeats of a false positive*: close / info / off, and for how
many days). A repeat that is worse, or about another remote address, is raised as usual. Repeated false positives of
one rule and address also become a mute / lower suggestion. To never see something again: **Mute
similar…**. **Trusted** on the Devices page marks a device as known: it is never counted as "new device" in attack
chains (it does not silence real alerts about the device).

**Comments**: open an alert (any status - open, acknowledged or closed) and write why it was closed or a false
positive, what the device is, or what you already did. *Comment & close* / *Comment & false positive* / *Comment &
re-open* do both in one click; comments can be edited and deleted, and the filter box searches them too. The **AI
analyst reads them**: for the alert itself and for earlier alerts of the same rule and address, so it doesn't report
again what you already explained as expected (unless the data shows it changed).


## How severity is decided

Every alert shows **"Why <severity>"**: the base reason and every step up (↑) or down (↓). The same four questions
decide it for every rule:

1. **Did anything get through?** Blocked traffic from the internet is background noise that every public IP gets.
   Allowed connections, successful logins and attacks that got a 2xx/3xx answer are what matter.
2. **Where does it come from?** The same behaviour from *inside* your network (a scan, password guessing, contact with a
   malicious address) is worse than from the internet: it means a device of yours misbehaves.
3. **Do other sources confirm it?** When the same IP also has IDS alerts, threat-intel (Q-Feeds) hits or other open
   alerts in the last 24 hours, the alert goes up one or two steps.
   For a device of yours, Q-Feeds hits only count when it keeps coming back (blocked attempts in 6 separate 10-minute
   periods or to 5 listed addresses): one blocked visit is Q-Feeds doing its job, as is a threat-intel alert rated low.
   The hits and the threat-intel alert made of them count once. Suricata: a priority 1–2 alert that got through
   counts; a dropped or priority-3 (policy / info) hit only when it keeps happening, and eve flow / dns / tls records
   never. CrowdSec, Suricata and threat-intel alerts rated low (handled, blocked, policy noise) don't count; an
   internal CrowdSec detection (rated high) does. Alerts built from the same
   events (e.g. a brute force and the login after it) don't count as confirmation for each other. Traffic that was
   **blocked** - by the firewall, Q-Feeds, Suricata in IPS mode or a DNS blocklist, in any rule (scans,
   threat feeds, Tor, suspicious ports, beaconing, lateral movement, ...) - stays at **high** at most, however much
   confirms it, and so does an attack chain whose steps were all blocked: critical is for what got through. Only your
   own *Change the severity* rules can still set critical.
4. **How reliable is the signal?** Size is not severity: a scan of 400 ports is still a scan.

| Situation | Severity |
|---|---|
| Port scan / host sweep from the internet (any size) | **no alert** - blocked scans are background noise every public IP gets, also when one reaches an open port you host; **high** if the scanner logged in, **medium** if it also got successful answers from an attack on your web server |
| Port scan / host sweep from inside | medium, up to high / critical when other sources confirm |
| Password guessing from the internet / from inside | medium / high |
| Login succeeded after failures: from the internet / from inside (5+ failures) / from inside (few failures, typos) | critical / high / medium |
| Admin (GUI / SSH / API) login from the internet / VPN login from the internet / any login from inside | high / low / info |
| Web attack: RCE / SQLi, path traversal / sensitive file, scanner signatures | medium, low, info - one step up if a request got a successful response or comes from inside. From the internet **only when something got through** (see below) |
| Web scanning (many 4xx) from the internet / from inside | low (only when a probed path answered successfully, or the address logged in) / medium |

**Web attacks and scanners from the internet** that only got errors or were blocked (CrowdSec, a WAF) are background
noise, like a blocked port scan, and raise **no alert** by default. *Settings › Data & detection*:

* *Web attacks / scanners from the internet: alert* - **through** (default): only when requests got through;
  **attacks**: also every RCE / SQL injection attempt, even a failed one; **all**: every pattern and scanner, as before.
* *… got through from (requests)* - how many attack / probe requests must get a successful answer (per address and
  pattern; a scanner: distinct probed paths in 10 minutes). Default 1. A request whose only sign is a scanner user
  agent (`curl/`, `python-requests`) is a visit, not a probe, and never counts.
* *… a successful answer is* - **2xx** (default) or **2xx+3xx** (redirects count too - often just HTTPS / login).

From inside your network web attacks and scanning always alert.
| Suricata (IDS) from the internet / from inside | a signature hit is **no alert** on its own, like CrowdSec / Q-Feeds - an internet address only once it triggers 20+ hits in 24h (one alert per address: info when IPS mode dropped every hit, else low); a device inside: high for a priority-1 signature that was NOT dropped, otherwise low and only an alert when other sources confirm it or it repeats (same signature in 6+ separate 10-minute periods, or 5+ different signatures, in 24h). *Settings › OPNsense*: which priorities count and SIDs that never do |
| CrowdSec decision for an internet IP / for an internal IP | the level of *Settings › OPNsense › CrowdSec (OPNsense) ban of an internet address: alert* (default low, info, or **off**: no alert, and the open ones are closed - the bans stay visible under *Threats › CrowdSec*; CrowdSec in Docker has its own, see [SWAG](swag.md)) / high |
| fail2ban (SWAG) banned an internet IP / an internal IP | *Settings › SWAG & CrowdSec* (default low, or off) / high |
| Honeypot touched from the internet / from inside | *Settings › SWAG & CrowdSec* (default low, or off) / high |
| Internal device contacted a threat-intel address (blocked by Q-Feeds) / internet address of a threat list probes you | low - medium / high when other sources confirm it or the device keeps coming back (blocked threat traffic in 6+ separate 10-minute periods, or to 5+ different listed addresses, in 24h - the retries of one page visit count once) / info |
| DNS tunneling, DGA names, NXDOMAIN storm | high, medium, low - each up when confirmed |
| Malicious domain looked up (blocked): 1-2 domains / 3+ | medium / high, up when confirmed |
| Suspicious outbound port (Tor, IRC, RDP, SMB, mining…) blocked / allowed | low / medium, up when confirmed |

"Blocked" in an alert means the firewall **logged a block** for it. An outbound NAT line (`nat out on pppoe0 …`, an
outbound NAT rule with logging on) is a connection that left, so it counts as allowed; a connection seen without any
pass or block line is described as "not blocked as far as the log shows", never as blocked.

"Up when confirmed" (*also seen by other sources*) counts other alerts about the same device only when they are
related or serious on their own: about the same remote address, rated high / critical, or not blocked. A blocked
lookup or connection rated low / medium elsewhere (a listed site in a browser tab) is the blocklist doing its job and
does not raise an unrelated alert, nor does a rule you closed as false positive for the device in the last 30 days.
The reason names the alerts it counted (e.g. `open alerts: tor #1290`).
| Gateway down / degraded, security service stopped / other service stopped, logs stopped | high / low, medium / low, medium |
| UniFi: switch offline / AP offline (after *Offline alerts wait*), foreign AP with your Wi-Fi name (open or strong signal: up), rogue DHCP | high / medium, medium-high, high |
| New device | low |

Severities of rules that look at a time window (scans, brute force, DNS) are re-evaluated on every run, so they can
go down again when the confirming evidence is older than 24 hours; rules that react to new events only ever go up.
