# OPNsense setup

[← Back to the README](../README.md)

The API user Looking Glass reads with, and what to set in OPNsense so all logs arrive.

## Create the API user and key (OPNsense web UI)

1. Open **System › Access › Users**, click **+** and create a user, e.g. `lookingglass` (any random password).
2. Give it privileges. Simplest: tick **GUI - All pages**. Stricter: only the *Diagnostics*, *Reporting*, *Firmware*,
   *Gateways*, *Unbound*, *CrowdSec*, *Q-Feeds* and *Intrusion Detection* pages (Looking Glass's *Setup & Status* page
   shows every API call that is refused, so you can add the missing privilege later). For **blocking from Looking
   Glass** add *Firewall: Alias: Edit* - see [Blocking addresses](user-guide.md#blocking-addresses-in-opnsense).
3. Save, open the user again, scroll to **API keys** and click **+**. Your browser downloads a text file with
   `key=...` and `secret=...`. You enter both in Looking Glass under *Settings › OPNsense*.


## Send logs from OPNsense (OPNsense web UI)

These steps were checked against the current OPNsense documentation and source (26.x).

1. **Remote syslog** – **System › Settings › Logging**, tab **Remote** (on older versions *System › Settings › Logging / targets*), click **+** (add a *Destination*):
   * Enabled ✓, Transport `UDP(4)` (or `TCP(4)`)
   * Applications: leave **empty** (= everything, recommended). Only then are the general system logs (kernel,
     opnsense …), sshd logins and API-key failures sent, because none of them has an entry in the list.
   * Levels: select everything from *info* up
   * Hostname: IP of your Docker host, Port: `514`
   * **rfc5424** ✓
   * Save, then **Apply**.

   **Recommended: configd only from *warning* up.** *configd* (OPNsense's backend) logs a *notice* line for every
   backend action it runs - hundreds of thousands a day, partly from Looking Glass's own API polling - and those lines
   say nothing useful. A destination's levels count for every application it sends, so use **two destinations**
   instead of the one above (both: Transport, Hostname, Port and *rfc5424* as above):

   | Destination | Applications | Levels |
   |---|---|---|
   | 1 - everything, only what matters | leave **empty** (= everything, configd too) | *warning*, *error*, *critical*, *alert*, *emergency* |
   | 2 - the rest, without configd | select **every application except configd** | *notice*, *info* |

   configd's real problems still arrive through destination 1, its flood of *notice* lines does not. Looking Glass
   files configd's lines under *system*. Note: the general system logs (kernel, opnsense …), sshd logins and API-key
   failures have no entry in the list, so destination 2 cannot send them - their *warning* and up lines still arrive
   through destination 1, their *notice* / *info* lines (e.g. sshd logins) do not. If you need those, keep the single
   destination above instead.
2. **Firewall logging** – default block rules are logged already. Open your important pass rules / port forwards
   (**Firewall › Rules › WAN** etc.) and tick **Log packets that are handled by this rule** so allowed traffic is visible too.
3. **Unbound DNS** – **Reporting › Settings**: enable the Unbound DNS statistics (off by default; Looking Glass then pulls
   every query with client, answer and blocklist via the API). Don't also enable *Log Queries* / *Log Replies* in
   **Services › Unbound DNS › Advanced** – that duplicates every query and slows Unbound down.

> **Check your setup:** Looking Glass › **Setup & status** lists every data source with what actually arrived in the last
> 24 hours and through which channel, marked *to do* (what to change, and where), *duplicate* (the same data arrives
> twice – which one to switch off), *tip*, *ok* or *optional*. Each source needs only one channel.
4. **nginx plugin** – nothing to do. OPNsense remote syslog never forwards nginx *access* logs; they exist only as files.
   Looking Glass therefore reads access, error and stream logs through the nginx log API (*Settings ›
   OPNsense › Pull nginx access / error logs*; the API user needs the nginx pages): a log with new lines every minute,
   a quiet one less often (up to every 10 minutes; every read is a configd action on OPNsense). For real-time delivery instead:
   **Services › Nginx › Configuration**, tab **Other › SYSLOG Targets**, add a target (Host = Docker host,
   Port = 514, Severity *info*), then select it in each **HTTP(S) › HTTP Server** under *SYSLOG targets*.
   nginx then sends straight to Looking Glass over UDP.
   **VPN** – WireGuard writes no connection logs, so WireGuard peers (status, last handshake, traffic), OpenVPN sessions
   and IPsec tunnels are read from the API (*Pull VPN status*). A WireGuard peer going online or offline becomes an event.
   Each peer is also listed under **Devices** (by its tunnel IP), named after your dnsmasq *Hosts* entry for that IP or
   else the peer name, so alerts show the name instead of the IP.
5. **Suricata** – nothing to do: alerts are pulled from the API. Don't also tick *Enable syslog alerts* in
   Intrusion Detection, that would count every alert twice.
6. **Q-Feeds** – the plugin only creates firewall aliases. Its *Events* (which Looking Glass reads) only appear when you
   add **block rules that use the Q-Feeds aliases with logging enabled**, e.g. on LAN: *block, destination = Q-Feeds
   alias, Log ✓* and on WAN: *block, source = Q-Feeds alias, Log ✓* (**Firewall › Rules**). The domain feeds are
   applied through Unbound's blocklist (*Register domain feeds* in **Security › Q-Feeds Connect**).
   The log lines of those rules (on any interface or interface group) count as Q-Feeds blocks under *Threats ›
   Q-Feeds*, for alerts and in reports - also blocks the plugin's own *Events* miss. While they arrive, the plugin's
   events (read from the same log) are not stored again. In / out is taken from the addresses: a LAN rule logs an
   outgoing connection as "in" on the LAN interface.
7. **CrowdSec** needs nothing extra – alerts and decisions are read through the API. These are only CrowdSec's own detections; the community blocklist (usually by far the most bans) blocks in the firewall, through the rules that use its aliases. *Settings › OPNsense › Blocklist aliases* names those aliases per tool (default `CrowdSec: crowdsec_blocklists, crowdsec6_blocklists` and `Q-Feeds: __qfeeds_*`, `*` as wildcard - change it when a plugin renames them, or add your own lists): Looking Glass finds every rule using them, reads the addresses in the tables and the packets the rules blocked, and marks their firewall log lines. Needs the API user's *Firewall: Alias: Edit* and *Diagnostics: Firewall statistics* privileges; for the logged blocks enable *Services › CrowdSec › Settings › Enable log for rules*.

Check **Setup & Status** in Looking Glass: every source should show a recent "last message" and every API job "ok"
(jobs for plugins you don't have show `n/a`).
