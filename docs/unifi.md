# UniFi

[← Back to the README](../README.md)

Adding a UniFi controller.

## Adding a UniFi controller

Optional. Looking Glass only reads from the controller; it never changes anything there.

**Which login?**

| Controller | Use |
|---|---|
| UniFi OS console (UDM, UCG, UDR, Cloud Key Gen2+, UX) or UniFi OS Server | an **API key** (recommended) |
| Self-hosted *UniFi Network Application* (e.g. Docker on Unraid, port 8443) | a **local username + password** (these installs have no API keys) |

1. **UniFi web UI** (API key): *UniFi Network › Settings › Control Plane › Integrations › Create API key* (newer versions:
   *Integrations* in the left menu). Copy the key - it is shown once. The key has the rights of the admin who created
   it, so ideally create it while logged in as a **View Only** admin.
   **UniFi web UI** (username / password): *UniFi OS › Admins & Users › Create* (or *Settings › Admins* on the
   self-hosted app) a **local** admin (not a UI.com account), *Restrict to local access only*, role **View Only** for
   Network, **without MFA**.
2. **Looking Glass web UI**: *Settings › UniFi* › URL (`https://<console-ip>` or `https://<host>:8443` for the self-hosted
   app), the API key **or** username + password, the site (usually `default`) › *Test connection* › *Save*.
   You can enter both a key and an account: the key is used where it works and the account fills in the rest.

What you get depends on what the controller accepts:

* **Full** (account, or an API key on a UniFi OS console): devices with ports / radios, clients with SSID, signal,
  experience and traffic, health, events (connects, roams, device offline, PoE, rogue DHCP) and neighbouring APs.
* **Basic** (API key accepted only by the official integration API): devices, load and which AP / switch each client
  uses - no SSID, signal, events or rogue APs. *Setup & status* tells you when this happens.

Polled every 60 seconds (Settings › UniFi › Poll interval), events every 2 minutes, neighbouring APs every 10 minutes.

**Offline alerts wait** (Settings › UniFi › *Offline alerts wait (minutes)*, default 10): an "access point / switch is
offline" or "UniFi controller is unreachable" alert only appears once it has been down that long, so rebooting OPNsense
(e.g. for an update), the controller or the device itself stays quiet. Such an alert closes by itself when the device
or controller is back (with how long it was down), and opens again if it goes down for that long once more. 0 = alert
right away. The offline / online *events* are always recorded (Event search, source *unifi*).
Don't also send UniFi's *SIEM / Activity Logging (syslog)* to Looking Glass: the API already delivers those events.

How UniFi and OPNsense data are combined:

* **Device list**: UniFi clients join the list (by MAC) with *Connected to* (AP + SSID or switch port) and signal; a name
  given in UniFi outranks DHCP host names.
* **Alerts** about an internal device (threat intel, IDS, DNS, new device…) say where it is connected and how to cut it
  off (*UniFi Network › Client Devices › … › Block*, or an OPNsense rule).
* **Infrastructure › UniFi › Clients** has a *Security (24 h)* column: open alerts, threat events (Suricata / CrowdSec /
  Q-Feeds), firewall blocks and DNS blocks from OPNsense per Wi-Fi or wired client. Sort on it, or pick *with security
  findings* in the filter; the badge opens the client's events. Reports have the same section.
* The **AI analyst** can read UniFi state (tool `unifi_status`) and is told to use location / SSID / VLAN when judging a
  device and to give UniFi containment steps.
