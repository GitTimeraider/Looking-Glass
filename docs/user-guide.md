# Using Looking Glass

[← Back to the README](../README.md)

A tour of the pages: overview, alerts, dashboards, infrastructure, devices, event search, reports and the AI analyst.

## Pages

* **Overview** – KPIs and the most important tables of every source in one page.
* **Alerts** – detections ranked by severity, naming the device behind an IP (from the device list) and the evidence
  (e.g. the non-existent domains looked up); **Events** opens exactly the events behind an alert; acknowledge / close;
  **Ask AI** investigates one alert. **Timeline** shows everything that address did around the alert, **Block…** puts
  its source in OPNsense's block alias (see [Blocking addresses](#blocking-addresses-in-opnsense)), **Snooze…** keeps
  alerts like it quiet for a while (see [Snooze and maintenance windows](#snooze-and-maintenance-windows)).
* **Timeline** (General › Timeline) – everything about one device or address in one list, newest first: its alerts
  (with your comments), logins, DNS lookups, firewall blocks and passes, web requests, Suricata / CrowdSec / Q-Feeds
  hits, blocks and snoozes, and when the device was first seen. Repeats within one time step (1 minute for an hour,
  10 minutes for a day, an hour for a week) are one line with a count; *events* behind every line opens them in Event
  search, ⤷ opens the timeline of the other side. Tick categories on or off with the chips. A device covers every
  address it had (its VLAN addresses too). Open it from an alert (*Timeline*: an hour before until an hour after it),
  from the Devices page (*timeline* next to *edit*) or type an address.
* **Overview** – key figures, events over time and per source, open alerts and the top-N tables of every source.
  **All / Local / Non-local** (top right) counts only events from local source addresses (private, CGNAT / Tailscale,
  loopback, link-local - your own devices and servers) or only the others, e.g. to hide a NAS that polls its own web
  page every second. Open alerts, devices, *banned now* and the UniFi / Unraid / backup state are not filtered. The
  choice is remembered in this browser. The SWAG & CrowdSec page has the same switch for all its tabs.
  **Customize** (top right) lets you drag widgets around (or use ◀ ▶), make them ⅓ / ⅔ / full width and normal or
  tall, remove them and add others (e.g. *Firewall system*); *Done* saves the layout for your account, *Reset to
  default* brings back the standard one. Widgets of sources you switched off (e.g. Suricata) hide themselves.
  More widgets are under *+ Add widget…*, grouped:
  * *SWAG & CrowdSec* - on the page by default: **SWAG: responses**, **SWAG: blocked by CrowdSec / WAF** (addresses
    the bouncer, AppSec or rate limit stopped), **CrowdSec: banned now** (with the time left; *all / unban →* opens
    the full list, searchable by IP, country or scenario), **Honeypot hits**, **fail2ban: banned now**, **SWAG: attack patterns**, **SWAG: top clients**;
    under *+ Add widget…*: **SWAG: requests per site** and **fail2ban jails**. With SWAG set up the key figures also
    show **SWAG blocked** and **Honeypot hits**. (A layout you saved before keeps itself: add the new widgets with
    *Customize › + Add widget…*.)
  * *Threats* - Suricata (top sources, targeted hosts, classifications, internal hosts alerting, **dropped
    signatures**), **threat blocks by source**, **CrowdSec firewall: top blocked IPs**, **devices with security
    events** (with where they are connected in UniFi);
  * *UniFi* - **devices now** (state, clients, firmware updates), **devices offline / restarted**, **Wi-Fi clients
    dropping / roaming**;
  * *Unraid* - **storage** (used, free, errors, temperature per array / pool), **CPU / memory**, **containers stopped /
    unhealthy** now, **notifications**, **container log errors**;
  * *Backups* - **backup jobs** of every tool (Backrest, Bichon) with their state.
  The UniFi, Unraid and Backups widgets hide themselves while that part is not set up.
* **Menu**: *General* (overview, alerts, event search over all sources), *OPNsense security* (the OPNsense security
  dashboards; other security products get their own group), *Infrastructure* (OPNsense and Unraid hardware & status,
  devices), *Tools* (system logs, reports, AI analyst) and *Admin*.
* **Dashboards** (one per function, each with KPIs, charts over time, breakdowns, top-N tables and a live log).
  Each live log has a **Local / Non-local** switch for its *From* address: turn one off and the log shows the newest
  events from the other kind (not the same rows with some hidden). Local = private (10/8, 172.16/12, 192.168/16,
  fc00::/7), CGNAT / Tailscale (100.64/10), loopback and link-local. Remembered per log in this browser.
  **Everything is clickable**: a tile, a bar, a pie slice, a moment in a time chart or a table row opens *Event search*
  with exactly those events (same filters and time span):
  *Firewall* (actions, interfaces, protocols, ports, countries, rules, allowed inbound, internal hosts being blocked),
  *DNS* (queries vs. blocked, types, rcodes, blocklists, clients, NXDOMAIN, tunneling candidates),
  *Threats* with four tabs: *Main* (all three sources together: key figures, threat events and blocks per source,
  alerts by rule/severity, top attackers, blocklists, live log), *CrowdSec* (alerts, decisions, **Active bans** – every
  current decision with the time it has left and an **Unban** button that removes it on OPNsense –, blocklist blocks over
  time, direction, countries, ports, blocked IPs), *Q-Feeds* (hits in / out over time, interfaces, matches, internal
  hosts contacting listed addresses, ports) and *Suricata* (alerts by priority, alerted vs dropped, classifications,
  app protocols, countries, signatures with SID, interfaces, sources, targeted hosts, internal hosts alerting, TLS
  JA3/JA4 fingerprints and SNI). Switching a source off (Settings › OPNsense › Pull …) hides its tab, its tiles
  and its Overview widgets right away;
  */dash/threats#suricata* opens a tab directly,
  *Authentication* (failed/successful logins, IPs with failed logins, usernames tried, config changes),
  *VPN* (live WireGuard peers, OpenVPN sessions and IPsec tunnels, connects/disconnects, VPN logins) and
  *System logs* (OPNsense and Unraid, per host and program).
* **Infrastructure › OPNsense** – tab *Overview* (hardware & performance): CPU, load, memory/swap/ARC, temperatures, disk usage, states,
  interface throughput/errors, gateway latency/loss, services, ARP/DHCP devices, top processes; tab *System & network*:
  system, firmware, disks & temperature, gateways, interfaces; tab *WAN quality* (below).
* **Infrastructure › OPNsense › WAN quality** (tab; the old `/wan` address opens it) – every OPNsense gateway over 30 days to 2 years: median / 95th percentile / worst
  latency, jitter, packet loss and availability per day (how often the gateway monitor said *down*), with key figures
  for the last 24 hours, the 7 days before (its "normal") and 30 days. Two alerts watch for slow degradation that
  "gateway down / degraded right now" misses - see [Detections](detections.md#built-in-detections). The day values
  are kept for two years, independent of *Keep metrics (days)*. Needs gateway monitoring on in OPNsense (*System ›
  Gateways › Configuration* › the gateway › *Disable Gateway Monitoring* unticked).
  Per gateway: **▲ ▼** set the order, and the menu next to them sets **shown**, **hidden** (still collected and
  alerted, just not on this page) or **ignored** (no longer collected, and never alerted - also no "gateway down /
  degraded" - for gateways you do not use; their open alerts are closed). Hidden and ignored gateways are listed at the
  bottom, where you can show them again.
  A gateway OPNsense does not measure (monitoring off, or the monitor IP does not answer ping - common for VPN
  gateways such as a WireGuard tunnel to a VPN provider: the far end often drops ping) shows a note instead of numbers.
  To measure it, in the OPNsense web UI: *System › Gateways › Configuration* › edit the gateway › untick *Disable
  Gateway Monitoring* and set *Monitor IP* to a public address that answers ping (e.g. `9.9.9.10`). OPNsense then
  routes that address through this gateway, so pick one nothing else needs to reach another way.
* **Infrastructure › UniFi** – tabs *Overview* (APs / switches online, clients over time per SSID and AP, Wi-Fi
  experience, device load and uplink throughput, health), *Devices* (firmware/updates, uptime, clients, radios, uplink;
  click a switch for its ports with PoE, traffic and errors), *Clients* (filter and sort by name, AP / switch port,
  SSID, signal, traffic and OPNsense security findings of the last 24 hours) and *Neighbouring Wi-Fi* (foreign APs,
  evil-twin warnings). UniFi events (connects, roams, device offline, rogue APs) are in Event search (source *unifi*).
* **Devices** – everything connected to OPNsense (ARP + DHCP leases from dnsmasq / Kea / ISC + UniFi clients):
  online state, name,
  IP, MAC, vendor, interface, lease, first/last seen, events/blocks/DNS queries/alerts per device; mark devices as
  trusted, rename them, add notes.
  Names come from, best first: a name you typed (never replaced; clear it to go back to automatic) → OPNsense's own interfaces (the ARP table marks their addresses *permanent*): one device per interface, "OPNsense (LAN)", "OPNsense (VLAN_IoT)" - also when VLANs share the port's MAC; alerts, counts and learned behaviour follow each interface's own addresses → a dnsmasq
  *Hosts* entry for the MAC or IP (*Services > Dnsmasq DNS & DHCP > Hosts*) → the host name the device sent with its
  DHCP request → the name Unbound shows for the IP → the ARP table. The placeholders dnsmasq (`*`) and the
  ARP table (`-`, `?`) use for "no name" are ignored. A device that still has no name sends none and has no Hosts
  entry: add one in OPNsense (host name + its MAC) or name it on the Devices page.
  Offline: once it leaves the ARP table.
  Devices stay on the list until you **delete** them (Devices page, next to *edit*; what was learned about them goes
  too) or *Settings › Data & detection › Remove devices not seen for (days)* removes them (default 0 = never; trusted
  devices, devices you named, devices with notes and devices with a type or their own settings are kept).
* **Unraid** – see [Unraid](unraid.md).
* **Settings › Data & detection › Backup** – one file with the database and the encryption key; see
  [Backup and restore](installation.md#backup-and-restore).
* **Admin › Audit log** – who did what: logins (also failed ones, with the step that failed), log-outs, password
  resets, backups downloaded and every change made in the web UI with its result (settings show which ones changed,
  never their values). Filter by kind and user or search; kept for a year.
* **Settings › Data & detection › Delete collected data** – wipe logs/events, alerts, graphs, reports, AI conversations
  and optionally the device list to start over; or only the WAN quality history (every gateway's latency, loss, jitter
  and up / down, e.g. after it was measured wrongly), or only the
  backup run history (what Backrest still lists comes back on its next poll). Settings, credentials, accounts/MFA, Unraid servers and the encryption
  key are kept; needs your password and typing DELETE.
* **Event search** – search all stored logs by source, IP/CIDR, local or non-local source address, action, text,
  severity, time range; filters that come
  from a dashboard click (program, host, domain, user, port, protocol, interface, country, time span, any data field)
  show as removable chips. Click an event for all its fields; **Ask AI** there (with the AI analyst enabled) explains
  that one event - what it means, whether it is normal and what to do - looking at what the same address did around
  it, how often it happens and alerts about its addresses.
* **Reports** – 24h / 7d / 30d reports, optionally with an AI-written analysis; print to PDF, download JSON or
  **Email** it. Tick what a report covers: **OPNsense** (firewall, DNS, SWAG web server, Suricata, CrowdSec, Q-Feeds,
  logins), **UniFi** (APs / switches going offline, clients dropping off or roaming, UniFi events, clients with
  security events), **Unraid** (array / pool state and free space, notifications, container log errors, CPU / memory)
  and **Backups** (jobs, failures). All ticked (the default) is the full *security report*; otherwise only those parts
  are collected (faster), the alerts are limited to their rules (the groups of *Settings › Alert filters*), the title
  says what it covers (*Weekly Unraid + Backups report*) and the AI analysis reviews only those. *Settings › Reports*:
  a *Scheduled report* every N days (1 = daily, 7 = weekly; it covers those days) at the hour you choose, covering what
  is ticked under *What the report covers*, optionally mailed to the addresses under *Email the report to* (with the
  mail server from *Settings › Email & notifications*).
* **AI Analyst** – chat with the model (any OpenAI-compatible endpoint; with Claude it uses Anthropic's
  [OpenAI SDK compatibility layer](https://platform.claude.com/docs/en/api/openai-sdk)). It can run read-only SQL against the log database, search events, profile an
  IP, read alerts, OPNsense + Unraid status and traffic statistics, and answers with evidence and remediation steps.
  Credentials (users, MFA secrets, API keys) are never accessible to it. Data sent to the AI provider consists of the
  query results the model asks for (IPs, domains, log lines) - with **privacy mode** on, local addresses and names
  in them are pseudonyms (see [AI privacy mode](ai-analyst.md#ai-privacy-mode-pseudonyms)). It also reads your comments on alerts.

## Blocking addresses in OPNsense

Looking Glass can put attackers in **one OPNsense alias** and take them out again when the block ends. It never
touches your firewall rules: you decide what the alias blocks. Set it up once:

1. **OPNsense web UI** › *Firewall › Aliases* › **+**: Type **External (advanced)**, Name `LookingGlass_block` (any
   name), Save, **Apply**. (An *External* alias is filled from outside; OPNsense resets *Host(s)* aliases to their
   configured content on every filter reload, so those do not work.)
2. **OPNsense web UI** › *Firewall › Rules › WAN* › **+**: Action **Block**, Source **LookingGlass_block**, Save, drag
   it to the top, **Apply**. Add the same rule on other interfaces if you also want to quarantine internal devices.
3. **OPNsense web UI** › *System › Access › Users* › your Looking Glass API user › add the privilege
   **Firewall: Alias: Edit**, Save.
4. **Looking Glass web UI** › *Settings › Blocking*: enter the alias name, Save.

Then block from an alert (**Block…**, asks how many hours; 0 = until you remove it) or on **General › Blocked
addresses**, which also lists every active and ended block, whether it is in OPNsense, and unblocks. Every minute
Looking Glass compares the alias with its list: blocks that ended are taken out, missing ones (OPNsense empties
External aliases on a reboot) are put back. Addresses someone else put in the alias are left alone.

**Automatic blocking** (*Settings › Blocking › Block automatically*, off by default) blocks the internet source of
every new open alert of the chosen severity (critical, or high and above) for *Automatic blocks last (hours)*.

Never blocked: the address of the browser you are using, OPNsense itself, loopback / link-local addresses and the
*Never block* list. Internal addresses only by hand, after a warning - never automatically.

## Snooze and maintenance windows

**General › Snooze & maintenance** (or **Snooze…** on an alert, **snooze** on the Devices page): for a while, store
alerts that match silently - not shown as open and not mailed. They still count for attack chains, corroboration and
the risk score, so a real attack during the maintenance is not lost. A snooze has a start (now, or later for a
planned window), an end (a duration or a time, at most 31 days) and optionally IP addresses / networks (source or
destination) and rules; with neither, it covers every alert. Alerts that were already open stay open but are not
mailed while the snooze lasts; the Alerts page shows a banner while one is active. *End now* stops it early. For
something that should stay quiet for good, use *Mute similar…* (an alert filter) instead.

### Recurring mute windows

For noise that comes back at the same time every week - an Unraid appdata backup that stops containers or fills their
logs with errors, a scheduled parity check - use **Settings › Alert filters › Recurring mute windows**. One window per
line, in local time (Settings › Display › Time zone), the end time not included:

```
category [days] [from-to]

unraid_container_errors tue 01:00-04:00     errors in container logs, Tuesdays 01:00-04:00
unraid mon+thu 03-05                        every Unraid alert, Mondays and Thursdays 03:00-05:00
backups sun                                 every backup alert, all of Sunday
unraid_container_down mon-fri 23:30-01:00   past midnight: belongs to the day it starts on
```

The category is a single rule, a whole group (`unraid`, `backups`, `firewall`, `dns` …) or `*` for every alert; days
are `mon` … `sun`, ranges (`mon-fri`) or several (`sat+sun`); left out = every day or the whole day (at least one of
the two is needed). **Format & categories…** next to the Save button lists every category and adds a line for the one
you click. Inside a window new alerts are handled exactly like during a snooze: stored closed (marked *snoozed*), not
mailed, still counted for attack chains and the risk score; alerts that were already open are not mailed.

