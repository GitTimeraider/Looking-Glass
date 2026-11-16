# Behaviour, machine learning and threat intel

[← Back to the README](../README.md)

What Looking Glass learns about every device, the anomaly detection, threat feeds and traps.

## Behaviour & machine learning

*Settings › Behaviour & ML* - every check has its own switch, and **Never analyse these devices** (IPs, CIDRs, MACs)
excludes devices from all of them.

| Check | What it does | Tune it with |
|---|---|---|
| **Device profiles** | learns per device (MAC) which countries, ports, domains, TLS programs (JA3/JA4) and hours are normal; alerts on the first use of something new | learning period, quiet period for new devices, one switch per kind; per device / device type on the Devices page |
| **Predictable devices only** | "new …" alerts only for devices that rarely pick up anything new (cameras, TVs, plugs) - PCs and phones are skipped automatically | *max. new things per day* (0 = all devices) |
| **Similar devices** | devices of the same vendor form a group: what the others do too is normal, what none of them do weighs heavier - unless other devices on the network do it too (a phone and a PC both using WhatsApp or IMAP) | on / off |
| **Odd hours** | activity at an hour the device has never been active | on / off |
| **Traffic spike** | connections or DNS lookups of one hour N× the device's median | factor (0 = off); per device on the Devices page |
| **Machine learning** | an Isolation Forest (one per pair of 7 features, pure Python, nothing leaves the server) scores each device-hour against the device's own history; alerts name the features that were off ("connections 9,000, normally ~100") | sensitivity low / medium / high; per device (incl. off) on the Devices page |
| **Hour of the week** | network totals (blocks, failed logins, DNS, NXDOMAIN, per log source) against the same hour in previous weeks | sensitivity, metrics to ignore - always or only on some days / hours (e.g. `source:unraid tue 01-02`) |
| **Risk score** | every open alert (not acknowledged / closed) adds points (info 1 … critical 40, once per rule) that fade with a half-life; one alert when a device's total is high; shown on the Devices page | threshold, half-life, addresses to skip; threshold per device on the Devices page |
| **Learning from false positives** | **Close as false positive** on the Alerts page; the same rule + address 3× in 30 days becomes a suggestion (mute / lower to info), or in *auto* mode a "Learned: …" severity rule (visible and removable under Alert filters). The exact same alert again (same rule, device, port and remote address, not worse) is stored closed as *known false positive* right away | suggest / auto / off, how many; repeats: close / info / off, days to remember |

**Devices › Learned** shows what was learned for a device and lets you forget it (per kind or everything). The
**Delete collected data** option in Settings can also clear all learned behaviour.

**Per-device settings** - **Devices › settings** (next to *edit*) gives one device its own settings instead of the
global ones above. Every setting has a **Use default** box: ticked, the device follows its device type's default, else
the global setting (also when that changes later); unticked, the value next to it is the device's own.

* **Device type** - *Laptop / desktop*, *Phone / tablet*, *Server / NAS*, *IoT*, *Network equipment* or *Other*, for
  every device. Laptops / desktops and phones / tablets
  reach new countries, domains and apps all the time (travel, a VPN, updates), so their *new country*, *new port* and
  *odd hours* alerts are **silent** and *new domain* / *new TLS program* **off** by default. The other types use the
  global settings. A device's own setting wins over its type.
* **Alert limits** - the **traffic spike** factor (0 = no spike alerts for it), the **machine learning** sensitivity
  (off / low / medium / high) and the **risk score** threshold (0 = never alert, the score is still kept). Raise them
  for devices that are busy at random (a gaming PC, a backup or download server), lower them for very steady ones
  (cameras, plugs, TVs) so smaller changes already alert.
* **Alert modes** - per kind (*new country*, *new port*, *new domain*, *new TLS program*, *odd hours*: alert / silent
  / off; *traffic spike*, *machine learning*: alert / silent). **Silent** alerts are stored closed (marked *silent* on
  the Alerts page), never shown as open and never notified. They still count for combined alerts: attack chains, the
  risk score and the corroboration of other alerts about the device. You hear about them only when they add up.
* Also per device: **predictable** (max. new things per day) and the **quiet period** before a device is judged.

*Use defaults for everything* clears the device's own settings (its type stays). Devices with their own settings or a
type show *⚙ settings*, the alerts they raise say which limit was used, and they are never removed automatically. A
device setting also works when the global switch is off (e.g. traffic spikes only for your cameras), as long as *Learn
device behaviour* (spike, machine learning, new things) or the *Risk score* is on.

## Threat intel & traps

*Settings › Threat intel & traps*:

| Check | What it does | Set up / tune |
|---|---|---|
| **abuse.ch feeds** | URLhaus (malware sites), ThreatFox (malware / C2 domains and IPs), Feodo Tracker (botnet C2), SSLBL (malware JA3) - daily, matched against DNS lookups, connections and TLS fingerprints. A malware URL on a shared site (GitHub, Steam, Discord, Google Drive, ...) or a shared cloud storage endpoint (`s3-eu-west-1.amazonaws.com/<bucket>/...`) does not flag the whole site / every bucket - a listed bucket of its own (`<bucket>.s3...amazonaws.com`) still does; both lists are editable (*Shared sites*, *Shared storage endpoints*, with *Restore built-in list*); ThreatFox IOCs below 50% confidence are skipped. A list moved? *Feed download addresses*: one `feed: URL` per line (or `feed: POST URL {json}`), tried before the built-in ones | a free **abuse.ch Auth-Key**: [auth.abuse.ch](https://auth.abuse.ch) › log in › Optional › Generate Auth-Key, paste it, Save, **Update feeds now**; one switch per feed; *Never flag these domains / IPs* |
| **Tor** | devices connecting to Tor relays; optionally Tor exits reaching your services | outbound / both / off; *Devices allowed to use Tor* |
| **Crypto mining** | lookups of / connections to mining pools (built-in list) | extra pool domains, on / off |
| **Newly seen domains** | remembers the first lookup of every domain; beaconing to a brand-new domain weighs heavier; optionally asks the registry (RDAP) for the registration date and alerts on domains younger than N days | on / off, RDAP on / off (sends those domain names to the registry), age, lookups per hour |
| **Canary addresses** | IPs / ports nothing should ever use - any contact is someone exploring the network | see below; sources to ignore; inside only / also internet |
| **Exposure watch** | alerts when a port forward or firewall rule is added / changed (medium when it opens something to the internet) | on / off; OPNsense 25.7+ shows details (API privileges *Firewall: Rules* and *Firewall: NAT*), older versions compare rule names |
| **ARP spoofing** | a device claiming the firewall's address, an IP flipping between devices, one device holding many IPs | IPs / MACs to ignore (CARP, repeaters, VM hosts), flips per hour |
| **Malware TLS** | JA3 fingerprints of known malware (SSLBL) | needs TLS records: OPNsense › Services › Intrusion Detection › Administration › *Enable eve syslog output* with TLS logging |

**Canary setup** (traffic inside one subnet never passes the firewall, so use the firewall itself or another VLAN):
1. OPNsense › Firewall › Rules › LAN › **+**: Action *Block*, Protocol *TCP*, Destination *This Firewall* (or *LAN address*),
   Destination port e.g. *23* (telnet) - repeat for *445* and *3389* - tick **Log packets that are handled by this rule**,
   place it **above** the allow rules, Save, Apply.
2. Looking Glass › Settings › Threat intel & traps › **Canary addresses**: `192.168.1.1:23, 192.168.1.1:445,
   192.168.1.1:3389` (your firewall's LAN address), Save.
