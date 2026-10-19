"""UniFi Network controller: access points, switches, Wi-Fi / wired clients, health, events and rogue APs.

Two APIs, both read-only here (field names checked against the controller OpenAPI specs 9.0-11.0, aiounifi and unpoller):

* Integration API v1 (API key, header ``X-API-KEY``): ``/proxy/network/integration/v1`` on UniFi OS consoles and
  UniFi OS Server, ``/integration/v1`` elsewhere. Devices, per-device statistics and clients - but no SSID, signal,
  traffic, switch ports, events or alarms.
* Classic API (``/proxy/network/api/s/<site>/...`` on UniFi OS, ``/api/s/<site>/...`` on the self-hosted Network
  Application): ``stat/device``, ``stat/sta``, ``stat/health``, ``stat/sysinfo``, ``stat/rogueap``, ``stat/event``
  (up to Network 10.x) and the v2 ``system-log`` (Network 11+). On UniFi OS the API key also works here; the
  self-hosted application needs a local username / password (cookie login).

Whatever the classic API answers is used; the v1 API fills in when it does not (e.g. API key on a self-hosted install).
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from . import db
from .config import Settings
from .detections import Rating, raise_alert, track_devices
from .ingest import EventWriter
from .parsers.common import event, ip_or_none, real_name

log = logging.getLogger("lookingglass.unifi")

# classic stat/device "state" codes (aiounifi DeviceState)
DEVICE_STATES = {0: "offline", 1: "online", 2: "pending adoption", 3: "firmware mismatch", 4: "upgrading",
                 5: "provisioning", 6: "heartbeat missed", 7: "adopting", 8: "deleting", 9: "inform error",
                 10: "adoption failed", 11: "isolated"}
DEVICE_TYPES = {"uap": "access point", "usw": "switch", "ugw": "gateway", "udm": "console / gateway", "uxg": "gateway",
                "ucg": "console / gateway", "uck": "cloud key", "ubb": "building bridge", "usp": "smart power",
                "uas": "application server", "uph": "phone"}
RADIOS = {"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz", "ad": "60 GHz"}

# classic event keys -> (action, severity); everything else is kept as "event"
EVENT_KEYS = {
    "EVT_WU_Connected": ("client_connect", 6), "EVT_WG_Connected": ("client_connect", 6),
    "EVT_LU_Connected": ("client_connect", 6), "EVT_LG_Connected": ("client_connect", 6),
    "EVT_WU_Disconnected": ("client_disconnect", 6), "EVT_WG_Disconnected": ("client_disconnect", 6),
    "EVT_LU_Disconnected": ("client_disconnect", 6), "EVT_LG_Disconnected": ("client_disconnect", 6),
    "EVT_WU_Roam": ("client_roam", 6), "EVT_WG_Roam": ("client_roam", 6),
    "EVT_WU_RoamRadio": ("client_roam", 6), "EVT_WG_RoamRadio": ("client_roam", 6),
    "EVT_WC_Blocked": ("client_blocked", 5), "EVT_LC_Blocked": ("client_blocked", 5),
    "EVT_WC_Unblocked": ("client_unblocked", 6), "EVT_LC_Unblocked": ("client_unblocked", 6),
    "EVT_AP_Lost_Contact": ("device_offline", 3), "EVT_SW_Lost_Contact": ("device_offline", 3),
    "EVT_GW_Lost_Contact": ("device_offline", 3), "EVT_DM_Lost_Contact": ("device_offline", 3),
    "EVT_AP_Connected": ("device_online", 6), "EVT_SW_Connected": ("device_online", 6),
    "EVT_GW_Connected": ("device_online", 6), "EVT_DM_Connected": ("device_online", 6),
    "EVT_AP_Restarted": ("device_restart", 5), "EVT_SW_Restarted": ("device_restart", 5),
    "EVT_AP_RestartedUnknown": ("device_restart", 4), "EVT_SW_RestartedUnknown": ("device_restart", 4),
    "EVT_AP_Upgraded": ("device_upgraded", 6), "EVT_SW_Upgraded": ("device_upgraded", 6),
    "EVT_AP_Isolated": ("device_isolated", 3),
    "EVT_AP_DetectRogueAP": ("rogue_ap", 4), "EVT_SW_DetectRogueDHCP": ("rogue_dhcp", 2),
    "EVT_AP_RadarDetected": ("radar", 5), "EVT_AP_PossibleInterference": ("interference", 5),
    "EVT_AP_ChannelChanged": ("channel_change", 6),
    "EVT_SW_PoeDisconnect": ("poe_disconnect", 4), "EVT_SW_PoeOverload": ("poe_overload", 3),
    "EVT_SW_Overheat": ("overheat", 3), "EVT_SW_StpPortBlocking": ("stp_blocking", 4),
    "EVT_AD_Login": ("login_success", 5), "EVT_IPS_IpsAlert": ("ips_alert", 2),
}


def login_hint(status: int, text: str) -> str:
    if status == 429 or "LIMIT_REACHED" in text:
        return " (too many failed logins - wait a few minutes)"
    if "2fa" in text.lower() or "mfa" in text.lower() or status == 499:
        return " (this account has two-factor authentication - use a local account without it)"
    return " (wrong username / password - it must be a local controller account, not a UI.com / cloud login)"


class UnifiError(Exception):
    def __init__(self, status: int, text: str) -> None:
        super().__init__(f"HTTP {status}: {text}")
        self.status = status


def _num(v: Any) -> float | None:
    try:
        return float(v) if v is not None and v != "" else None
    except (TypeError, ValueError):
        return None


def _ts(value: Any) -> datetime:
    """Epoch seconds or milliseconds, or ISO text."""
    n = _num(value)
    if n is not None:
        return datetime.fromtimestamp(n / 1000 if n > 1e11 else n, tz=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


# ---------------------------------------------------------------- normalising ---
def device_from_legacy(d: dict[str, Any]) -> dict[str, Any]:
    stats = d.get("system-stats") or {}
    up = d.get("uplink") or {}
    state = d.get("state")
    ports = [{"idx": p.get("port_idx"), "name": p.get("name"), "up": bool(p.get("up")), "enabled": p.get("enable", True),
              "speed": p.get("speed"), "uplink": bool(p.get("is_uplink")), "media": p.get("media"),
              "poe_w": _num(p.get("poe_power")), "rx_bytes": p.get("rx_bytes"), "tx_bytes": p.get("tx_bytes"),
              "errors": int((_num(p.get("rx_errors")) or 0) + (_num(p.get("tx_errors")) or 0)),
              "dropped": int((_num(p.get("rx_dropped")) or 0) + (_num(p.get("tx_dropped")) or 0))}
             for p in d.get("port_table") or []]
    radios = [{"radio": RADIOS.get(r.get("radio"), r.get("radio")), "channel": r.get("channel"), "clients": r.get("num_sta"),
               "utilisation": r.get("cu_total"), "satisfaction": r.get("satisfaction"), "tx_power": r.get("tx_power")}
              for r in d.get("radio_table_stats") or []]
    return {
        "mac": (d.get("mac") or "").lower(), "name": d.get("name") or d.get("model") or d.get("mac"),
        "model": d.get("model"), "kind": DEVICE_TYPES.get(d.get("type"), d.get("type") or "device"), "type": d.get("type"),
        "state": DEVICE_STATES.get(state, str(state)) if isinstance(state, int) else str(state or "unknown").lower(),
        "adopted": d.get("adopted", True), "ip": d.get("ip"), "version": d.get("displayable_version") or d.get("version"),
        "upgradable": bool(d.get("upgradable")), "uptime": d.get("uptime"),
        "cpu": _num(stats.get("cpu")), "mem": _num(stats.get("mem")), "temperature": _num(d.get("general_temperature")),
        "clients": d.get("num_sta"), "satisfaction": d.get("satisfaction"),
        # uplink rates in bits/s (the classic API reports bytes/s, the integration API bits/s)
        "tx_bps": _num(up.get("tx_bytes-r")) * 8 if _num(up.get("tx_bytes-r")) is not None else None,
        "rx_bps": _num(up.get("rx_bytes-r")) * 8 if _num(up.get("rx_bytes-r")) is not None else None,
        "uplink_mac": (up.get("uplink_mac") or "").lower() or None, "uplink_port": up.get("uplink_remote_port"),
        "uplink_type": up.get("type"), "ports": ports, "radios": radios,
        "ssids": sorted({v.get("essid") for v in d.get("vap_table") or [] if v.get("essid")}),
        "last_seen": d.get("last_seen"),
    }


def device_from_v1(d: dict[str, Any], stats: dict[str, Any] | None) -> dict[str, Any]:
    feats = d.get("features") or []
    feats = list(feats) if isinstance(feats, (list, dict)) else []
    kind = "access point" if "accessPoint" in feats else "switch" if "switching" in feats else \
        "gateway" if "gateway" in feats else "device"
    s = stats or {}
    up = s.get("uplink") or {}
    return {"mac": (d.get("macAddress") or "").lower(), "name": d.get("name") or d.get("model"), "model": d.get("model"),
            "kind": kind, "type": None, "id": d.get("id"),
            "state": str(d.get("state") or "unknown").lower().replace("_", " "), "adopted": True, "ip": d.get("ipAddress"),
            "version": d.get("firmwareVersion"), "upgradable": bool(d.get("firmwareUpdatable")),
            "uptime": s.get("uptimeSec"), "cpu": _num(s.get("cpuUtilizationPct")), "mem": _num(s.get("memoryUtilizationPct")),
            "temperature": None, "clients": None, "satisfaction": None,
            "tx_bps": _num(up.get("txRateBps")), "rx_bps": _num(up.get("rxRateBps")),
            "uplink_mac": None, "uplink_port": None, "uplink_type": None, "ports": [], "radios": [], "ssids": []}


def client_from_legacy(c: dict[str, Any], devices: dict[str, dict[str, Any]]) -> dict[str, Any]:
    wired = bool(c.get("is_wired"))
    ap = devices.get((c.get("ap_mac") or "").lower()) or {}
    sw = devices.get((c.get("sw_mac") or "").lower()) or {}
    return {
        "mac": (c.get("mac") or "").lower(), "ip": c.get("ip") or c.get("fixed_ip"),
        "alias": real_name(c.get("name")), "hostname": real_name(c.get("hostname")),
        "vendor": c.get("oui"), "wired": wired, "guest": bool(c.get("is_guest")), "blocked": bool(c.get("blocked")),
        "ssid": None if wired else c.get("essid"), "radio": None if wired else RADIOS.get(c.get("radio"), c.get("radio")),
        "channel": c.get("channel"), "signal": _num(c.get("signal")) if not wired else None,
        "satisfaction": _num(c.get("satisfaction")),
        "ap": ap.get("name") if not wired else None, "ap_mac": (c.get("ap_mac") or "").lower() or None,
        "switch": sw.get("name") if wired else None, "port": c.get("sw_port") if wired else None,
        "network": c.get("network"), "vlan": c.get("vlan"),
        "tx_bytes": _num(c.get("tx_bytes") if not wired else c.get("wired-tx_bytes", c.get("tx_bytes"))),
        "rx_bytes": _num(c.get("rx_bytes") if not wired else c.get("wired-rx_bytes", c.get("rx_bytes"))),
        "uptime": c.get("uptime"), "first_seen": c.get("first_seen"), "last_seen": c.get("last_seen"),
    }


def client_from_v1(c: dict[str, Any], devices_by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    wired = c.get("type") == "WIRED"
    up = devices_by_id.get(c.get("uplinkDeviceId") or "") or {}
    # v1 "name" is the alias when one is set, else the device's own host name - so it ranks like a host name
    return {"mac": (c.get("macAddress") or "").lower(), "ip": c.get("ipAddress"), "alias": None,
            "hostname": real_name(c.get("name")), "vendor": None, "wired": wired, "guest": (c.get("access") or {}).get("type") == "GUEST",
            "blocked": False, "ssid": None, "radio": None, "channel": None, "signal": None, "satisfaction": None,
            "ap": up.get("name") if not wired else None, "ap_mac": up.get("mac") if not wired else None,
            "switch": up.get("name") if wired else None, "port": None, "network": None, "vlan": None,
            "tx_bytes": None, "rx_bytes": None, "uptime": None, "first_seen": None, "last_seen": None,
            "connected_at": c.get("connectedAt")}


def where(c: dict[str, Any]) -> str:
    """'AP Living room · Home (5 GHz)' / 'Switch Office port 5'."""
    if c.get("wired"):
        return " ".join(x for x in ("Switch", c.get("switch") or "?", f"port {c['port']}" if c.get("port") else "") if x)
    radio = f" ({c['radio']})" if c.get("radio") else ""
    return f"AP {c.get('ap') or '?'}" + (f" · {c['ssid']}{radio}" if c.get("ssid") else "")


def event_from_legacy(e: dict[str, Any], site: str) -> dict[str, Any]:
    key = e.get("key") or ""
    action, sev = EVENT_KEYS.get(key, ("event", 6))
    mac = (e.get("user") or e.get("guest") or "").lower() or None
    data = {k: e.get(k) for k in ("key", "subsystem", "ap", "ap_name", "ap_from", "ap_to", "sw", "sw_name", "port",
                                  "ssid", "hostname", "channel_from", "channel_to", "radio_from", "radio_to", "duration",
                                  "bytes", "admin", "version_from", "version_to") if e.get(k) not in (None, "")}
    if mac:
        data["mac"] = mac
    # admin logins carry the client address ("ip"): the login rules (brute force, external login) use it
    src = ip_or_none(e.get("ip")) if action in ("login_success", "login_failed") else None
    return event(_ts(e.get("time") or e.get("datetime")), "unifi", host="unifi", program="unifi", severity=sev,
                 action=action, src_ip=src, message=str(e.get("msg") or key)[:2000], username=e.get("admin") or None,
                 domain=e.get("ssid") or None, data=data, uid=f"unifi:{site}:{e.get('_id') or e.get('time')}:{key}")


SYSLOG_ACTIONS = (("connected", "client_connect"), ("disconnected", "client_disconnect"), ("roam", "client_roam"),
                  ("offline", "device_offline"), ("lost contact", "device_offline"), ("adopted", "device_online"),
                  ("online", "device_online"), ("restart", "device_restart"), ("rogue", "rogue_ap"),
                  ("blocked", "client_blocked"), ("threat", "ips_alert"), ("honeypot", "ips_alert"),
                  ("login fail", "login_failed"), ("failed login", "login_failed"), ("login_fail", "login_failed"),
                  ("login", "login_success"), ("poe", "poe_disconnect"))


def event_from_system_log(e: dict[str, Any], site: str) -> dict[str, Any]:
    """Network 11+: v2 system-log entry {id, key, category, subcategory, severity, title_raw, message_raw, parameters}."""
    title = str(e.get("title_raw") or e.get("key") or "")
    msg = str(e.get("message_raw") or title)
    params = e.get("parameters") or {}
    low = f"{e.get('key', '')} {title}".lower()
    action = next((a for word, a in SYSLOG_ACTIONS if word in low), "event")
    sev = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 4, "WARNING": 4, "LOW": 5, "INFO": 6}.get(str(e.get("severity") or "").upper(), 6)
    mac, ip = None, None
    for v in params.values() if isinstance(params, dict) else []:
        if isinstance(v, dict):
            mac = mac or (v.get("client_mac") or (v.get("id") if str(v.get("type", "")).upper() == "CLIENT" else None))
            ip = ip or v.get("ip")
    for name, value in params.items() if isinstance(params, dict) else []:
        if isinstance(value, dict) and value.get("name"):
            msg = msg.replace("{" + name + "}", str(value["name"]))
    data = {"key": e.get("key"), "category": e.get("category"), "subcategory": e.get("subcategory"), "title": title}
    if mac:
        data["mac"] = str(mac).lower()
    return event(_ts(e.get("timestamp")), "unifi", host="unifi", program="unifi", severity=sev, action=action,
                 message=msg[:2000], src_ip=ip_or_none(ip), data=data, uid=f"unifi:{site}:{e.get('id') or e.get('timestamp')}")


# ---------------------------------------------------------------- client ---
class UnifiClient:
    """Finds out which API / login works and talks to the controller."""

    def __init__(self, settings: Settings) -> None:
        self.s = settings
        self.site = (settings.unifi_site or "default").strip()
        headers = {"Accept": "application/json"}
        if settings.unifi_api_key:
            headers["X-API-KEY"] = settings.unifi_api_key
        self.http = httpx.AsyncClient(base_url=settings.unifi_url.rstrip("/"), verify=settings.unifi_verify_ssl,
                                      headers=headers, timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=False)
        self.prefix: str | None = None   # "/proxy/network" (UniFi OS) or "" (self-hosted) for the classic API
        self.v1: str | None = None       # integration API base path, when the API key works there
        self.site_id: str | None = None  # v1 site uuid
        self.legacy = False              # classic API usable
        self.logged_in = False
        self.version: str | None = None
        self.mode = "?"
        self.sites: list[str] = []

    async def close(self) -> None:
        await self.http.aclose()

    async def _req(self, method: str, path: str, **kw: Any) -> Any:
        r = await self.http.request(method, path, **kw)
        if r.status_code == 401 and self.logged_in and self.s.unifi_username:
            self.logged_in = False
            await self._login()
            r = await self.http.request(method, path, **kw)
        if "x-updated-csrf-token" in r.headers:
            self.http.headers["X-CSRF-Token"] = r.headers["x-updated-csrf-token"]
        if r.status_code >= 400:
            raise UnifiError(r.status_code, r.text[:300])
        try:
            return r.json()
        except ValueError as exc:
            raise UnifiError(r.status_code, f"not JSON: {r.text[:120]}") from exc

    async def _unifi_os(self) -> bool | None:
        """UniFi OS consoles answer / themselves; the self-hosted Network Application redirects to /manage."""
        try:
            r = await self.http.get("/")
        except httpx.HTTPError:
            return None
        if r.status_code == 200:
            return True
        if r.is_redirect and "/manage" in r.headers.get("location", ""):
            return False
        return None

    async def _login(self) -> None:
        body = {"username": self.s.unifi_username, "password": self.s.unifi_password, "rememberMe": True, "remember": True}
        attempts = [("/api/auth/login", "/proxy/network"), ("/api/login", "")]
        if await self._unifi_os() is False:
            attempts.reverse()
        last: UnifiError | None = None
        for path, prefix in attempts:
            r = await self.http.post(path, json=body)
            text = r.text[:300]
            # the other kind of controller: 404, or (self-hosted app) "LoginRequired" because /api/auth/* is just a
            # protected path there
            if r.status_code == 404 or (r.status_code == 401 and "LoginRequired" in text):
                last = UnifiError(r.status_code, text)
                continue
            if r.status_code >= 400:
                raise UnifiError(r.status_code, text + login_hint(r.status_code, text))
            if token := r.headers.get("x-csrf-token") or self.http.cookies.get("csrf_token"):
                self.http.headers["X-CSRF-Token"] = token
            self.prefix, self.logged_in = prefix, True
            return
        raise UnifiError(last.status if last else 404, "no UniFi login endpoint accepted the request - check the URL "
                                                       "(UniFi OS: https://<ip>, self-hosted: https://<ip>:8443)")

    async def legacy_get(self, path: str, body: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        url = f"{self.prefix}/api/s/{self.site}/{path}"
        res = await (self._req("POST", url, json=body) if body is not None else self._req("GET", url))
        if isinstance(res, dict) and (res.get("meta") or {}).get("rc") == "error":
            raise UnifiError(400, str((res.get("meta") or {}).get("msg")))
        return res.get("data", []) if isinstance(res, dict) else res

    async def v1_list(self, path: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        offset = 0
        while True:
            res = await self._req("GET", f"{self.v1}/{path}", params={"offset": offset, "limit": 200})
            data = res.get("data", []) if isinstance(res, dict) else []
            out += data
            offset += len(data)
            if not data or offset >= int(res.get("totalCount") or 0):
                return out

    async def connect(self) -> None:
        """Pick the APIs that work with the configured credentials."""
        if self.s.unifi_api_key:
            for base in ("/proxy/network/integration", "/integration"):
                try:
                    info = await self._req("GET", f"{base}/v1/info")
                except (UnifiError, httpx.HTTPError):
                    continue
                self.v1, self.version = f"{base}/v1", info.get("applicationVersion")
                break
            if self.v1:
                sites = await self.v1_list("sites")
                self.sites = [s.get("internalReference") or s.get("name") for s in sites]
                match = next((s for s in sites if self.site in (s.get("internalReference"), s.get("name"), s.get("id"))), None)
                if not match and sites:
                    raise UnifiError(404, f"site '{self.site}' not found; this controller has: {', '.join(map(str, self.sites))}")
                self.site_id = (match or {}).get("id")
                if (match or {}).get("internalReference"):
                    self.site = match["internalReference"]
                self.prefix = "/proxy/network" if self.v1.startswith("/proxy/network") else ""
        if self.s.unifi_username and self.s.unifi_password and not self.logged_in:
            try:
                await self._login()
            except UnifiError:
                if not self.v1:
                    raise
        if self.prefix is None and not self.v1:
            raise UnifiError(401, "the API key was refused on both the UniFi OS and the self-hosted path "
                                  "(self-hosted Network Application: use a local username / password instead)")
        try:  # the classic API: logged in, or the API key on UniFi OS
            sysinfo = await self.legacy_get("stat/sysinfo")
            self.legacy = True
            self.version = (sysinfo[0] if sysinfo else {}).get("version") or self.version
        except (UnifiError, httpx.HTTPError):
            self.legacy = False
        self.mode = ("classic API" if self.legacy else "") + (" + " if self.legacy and self.v1 else "") + \
                    ("integration API" if self.v1 else "")

    @property
    def major(self) -> int:
        try:
            return int(str(self.version).split(".")[0])
        except ValueError:
            return 0


# ---------------------------------------------------------------- poller ---
class UnifiPoller:
    def __init__(self, settings: Settings, writer: EventWriter) -> None:
        self.settings = settings
        self.writer = writer
        self.client = UnifiClient(settings)
        self.status: dict[str, Any] = {"ok": None, "error": None, "last": None, "mode": None, "version": None, "sections": {}}
        self.last_run: dict[str, float] = {}
        self.prev_state: dict[str, str] = {}
        self.events_since = time.time() - 3600
        self.failures = 0

    def due(self, key: str, interval: float) -> bool:
        if time.time() - self.last_run.get(key, 0) >= interval:
            self.last_run[key] = time.time()
            return True
        return False

    async def stop(self) -> None:
        await self.client.close()

    async def run(self) -> None:
        log.info("UniFi poller started for %s (site %s)", self.settings.unifi_url, self.settings.unifi_site)
        while True:
            try:
                if not (self.client.legacy or self.client.v1):
                    await self.client.connect()
                    self.status.update(mode=self.client.mode, version=self.client.version, site=self.client.site)
                    log.info("UniFi: connected (%s, Network %s)", self.client.mode, self.client.version)
                await self.poll()
                self.failures = 0
                self.status.update(ok=True, error=None, last=time.time())
            except (UnifiError, httpx.HTTPError, OSError) as exc:
                self.failures += 1
                self.status.update(ok=False, error=f"{type(exc).__name__}: {exc}", last=time.time())
                log.warning("UniFi: %s", exc)
                if isinstance(exc, UnifiError) and exc.status in (401, 403):
                    self.client.legacy, self.client.v1, self.client.logged_in = False, None, False
                if self.failures == 3:
                    await raise_alert("unifi_unreachable", "medium", "UniFi controller is unreachable", "unifi_down",
                                      description=str(exc))
            await db.set_snapshot("unifi:status", self.status)
            await asyncio.sleep(max(30, self.settings.unifi_poll_interval) if self.failures < 3 else 300)

    async def section(self, name: str, coro) -> Any:
        try:
            out = await coro
            self.status["sections"][name] = {"ok": True}
            return out
        except UnifiError as exc:
            self.status["sections"][name] = {"ok": False, "error": str(exc)[:200]}
            return None

    async def poll(self) -> None:
        c = self.client
        devices: list[dict[str, Any]] = []
        clients: list[dict[str, Any]] = []
        if c.legacy:
            raw = await self.section("devices", c.legacy_get("stat/device")) or []
            devices = [device_from_legacy(d) for d in raw]
            by_mac = {d["mac"]: d for d in devices}
            raw = await self.section("clients", c.legacy_get("stat/sta")) or []
            clients = [client_from_legacy(x, by_mac) for x in raw]
            health = await self.section("health", c.legacy_get("stat/health"))
            if health is not None:
                await db.set_snapshot("unifi:health", health)
            if self.due("sysinfo", 600):
                info = await self.section("sysinfo", c.legacy_get("stat/sysinfo"))
                if info:
                    await db.set_snapshot("unifi:sysinfo", info[0])
        elif c.v1:
            raw = await self.section("devices", c.v1_list(f"sites/{c.site_id}/devices")) or []
            for d in raw:
                stats = None
                try:
                    stats = await c._req("GET", f"{c.v1}/sites/{c.site_id}/devices/{d['id']}/statistics/latest")
                except UnifiError:
                    pass
                devices.append(device_from_v1(d, stats))
            by_id = {d["id"]: d for d in devices}
            raw = await self.section("clients", c.v1_list(f"sites/{c.site_id}/clients")) or []
            clients = [client_from_v1(x, by_id) for x in raw]
            counts: dict[str, int] = {}
            for x in clients:
                key = (x.get("ap_mac") or "") if not x["wired"] else ""
                counts[key] = counts.get(key, 0) + 1
            for d in devices:
                d["clients"] = counts.get(d["mac"], 0) if d["kind"] == "access point" else d["clients"]
        await self.store(devices, clients)
        if c.legacy:  # after store(): they look up own SSIDs / device names / client IPs
            if self.due("rogue", 600):
                await self.poll_rogue()
            if self.settings.unifi_events and self.due("events", 120):
                await self.poll_events(devices, clients)

    async def store(self, devices: list[dict[str, Any]], clients: list[dict[str, Any]]) -> None:
        names = {d["mac"]: d["name"] for d in devices}
        for d in devices:
            d["uplink_name"] = names.get(d.get("uplink_mac") or "")
        await db.set_snapshot("unifi:devices", devices)
        await db.set_snapshot("unifi:clients", clients)
        wifi = [x for x in clients if not x["wired"]]
        rows: list[tuple[str, str, float]] = [
            ("unifi_clients", "wifi", float(len(wifi))), ("unifi_clients", "wired", float(len(clients) - len(wifi))),
            ("unifi_devices_online", "", float(sum(1 for d in devices if d["state"] == "online")))]
        per_ssid: dict[str, int] = {}
        per_ap: dict[str, int] = {}
        for x in wifi:
            per_ssid[x.get("ssid") or "?"] = per_ssid.get(x.get("ssid") or "?", 0) + 1
            per_ap[x.get("ap") or "?"] = per_ap.get(x.get("ap") or "?", 0) + 1
        rows += [("unifi_ssid_clients", k, float(v)) for k, v in per_ssid.items()]
        rows += [("unifi_ap_clients", k, float(v)) for k, v in per_ap.items()]
        for d in devices:
            for metric, key in (("unifi_device_cpu", "cpu"), ("unifi_device_mem", "mem"),
                                ("unifi_device_tx_bps", "tx_bps"), ("unifi_device_rx_bps", "rx_bps")):
                if d.get(key) is not None:
                    rows.append((metric, d["name"], float(d[key])))
        sats = [x["satisfaction"] for x in wifi if x.get("satisfaction") is not None]
        if sats:
            rows.append(("unifi_wifi_satisfaction", "", sum(sats) / len(sats)))
        await db.add_metrics(rows)
        await self.check_devices(devices)
        # the device list: names (UniFi alias first), vendor and where each client is connected
        await track_devices([{
            "mac": x["mac"], "ip": ip_or_none(x.get("ip")), "hostname": x.get("alias") or x.get("hostname"),
            "name_source": "unifi-alias" if x.get("alias") else "unifi", "vendor": x.get("vendor"),
            "online": True, "conn_type": "wired" if x["wired"] else "wifi",
            "conn_where": where(x), "conn_signal": int(x["signal"]) if x.get("signal") is not None else None,
        } for x in clients if x.get("mac")], origin="unifi")

    async def check_devices(self, devices: list[dict[str, Any]]) -> None:
        for d in devices:
            if not d.get("adopted", True):
                continue
            prev = self.prev_state.get(d["mac"])
            self.prev_state[d["mac"]] = d["state"]
            if d["state"] in ("offline", "heartbeat missed", "isolated", "connection interrupted") and prev != d["state"]:
                rating = Rating("high", "a switch is down - everything behind it is offline") if d["kind"] == "switch" else \
                    Rating("medium", f"the clients on this {d['kind']} lose their connection (or roam to another AP)")
                await raise_alert("unifi_device_offline", rating, f"UniFi {d['kind']} {d['name']} is {d['state']}",
                                  f"unifi_dev:{d['mac']}", description=f"{d['model']} {d['mac']} ({d.get('ip') or 'no IP'}) "
                                  f"reports state '{d['state']}'. Clients connected through it lose their connection.",
                                  data={"device": d["name"], "model": d["model"], "mac": d["mac"]},
                                  events={"source": "unifi", "q": d["name"]})

    async def poll_rogue(self) -> None:
        rogue = await self.section("rogue", self.client.legacy_get("stat/rogueap", {"within": 24}))
        if rogue is None:
            return
        devices = await db.get_snapshot("unifi:devices") or []
        own_ssids = {s for d in devices for s in d.get("ssids") or []}
        own_bssids = {d["mac"][:-1] for d in devices}  # BSSIDs share all but the last nibble with the AP MAC (heuristic)
        out = []
        for r in rogue:
            essid, bssid = r.get("essid") or "", (r.get("bssid") or "").lower()
            twin = bool(essid) and essid in own_ssids and bssid[:-1] not in own_bssids and not r.get("is_ubnt")
            out.append({"bssid": bssid, "essid": essid, "channel": r.get("channel"), "band": r.get("band") or r.get("radio"),
                        "signal": r.get("signal") or r.get("rssi"), "security": r.get("security"), "vendor": r.get("oui"),
                        "heard_by": next((d["name"] for d in devices if d["mac"] == (r.get("ap_mac") or "").lower()), r.get("ap_mac")),
                        "rogue": bool(r.get("is_rogue")), "evil_twin": twin, "last_seen": r.get("last_seen")})
            if twin:
                signal = _num(r.get("signal") or r.get("rssi"))
                open_net = str(r.get("security") or "").lower() in ("open", "none", "")
                rating = Rating("medium", "a foreign access point uses one of your Wi-Fi names - often a neighbour with the "
                                          "same name, sometimes an 'evil twin'")
                if open_net:
                    rating.up("it is an OPEN network - the classic trick to catch devices that auto-connect")
                elif signal is not None and signal >= -70:
                    rating.up(f"strong signal ({int(signal)} dBm): it is close by, likely on or next to your premises")
                await raise_alert("unifi_evil_twin", rating, f"Foreign access point broadcasts your Wi-Fi name '{essid}'",
                                  f"unifi_twin:{bssid}",
                                  description=f"BSSID {bssid} ({r.get('oui') or 'unknown vendor'}, channel {r.get('channel')}, "
                                              f"signal {r.get('signal') or r.get('rssi')}) uses the SSID of one of your networks but "
                                              "is not one of your UniFi access points. This can be an 'evil twin' that tries to "
                                              "catch your devices and passwords - or a neighbour/extender with the same name.",
                                  data={"bssid": bssid, "essid": essid}, events={"source": "unifi", "q": essid})
        await db.set_snapshot("unifi:rogue", out)

    async def poll_events(self, devices: list[dict[str, Any]], clients: list[dict[str, Any]]) -> None:
        c = self.client
        since = self.events_since
        evs: list[dict[str, Any]] = []
        if c.major >= 11:
            body = {"pageNumber": 0, "pageSize": 200, "timestampFrom": int(since * 1000), "timestampTo": int(time.time() * 1000)}
            try:
                res = await c._req("POST", f"{c.prefix}/v2/api/site/{c.site}/system-log/all", json=body)
                evs = [event_from_system_log(e, c.site) for e in (res.get("data") or [])]
                self.status["sections"]["events"] = {"ok": True}
            except UnifiError as exc:
                self.status["sections"]["events"] = {"ok": False, "error": str(exc)[:200]}
                return
        else:
            hours = max(1, int((time.time() - since) / 3600) + 1)
            raw = await self.section("events", c.legacy_get("stat/event", {"_sort": "-time", "within": hours, "_limit": 1000}))
            if raw is None:
                return
            evs = [event_from_legacy(e, c.site) for e in raw if _ts(e.get("time")).timestamp() >= since - 60]
        self.events_since = time.time()
        if not evs:
            return
        macs = {e["data"]["mac"] for e in evs if (e.get("data") or {}).get("mac")}
        ips = {}
        if macs:
            for r in await db.pool().fetch("SELECT mac, host(ip) ip FROM devices WHERE mac = ANY($1::text[])", list(macs)):
                ips[r["mac"]] = r["ip"]
        names = {d["mac"]: d["name"] for d in devices}
        names.update({x["mac"]: x.get("alias") or x.get("hostname") for x in clients if x.get("alias") or x.get("hostname")})
        for e in evs:
            mac = (e.get("data") or {}).get("mac")
            if mac and not e.get("src_ip") and ips.get(mac):
                e["src_ip"] = ips[mac]
            e["message"] = readable(e["message"], names)
            self.writer.put(e)
            if e["action"] == "rogue_dhcp":
                await raise_alert("unifi_rogue_dhcp", Rating("high", "a second DHCP server can hand devices a wrong gateway / "
                                                                     "DNS (man-in-the-middle) or break the network", sticky=True),
                                  "Rogue DHCP server detected on your network",
                                  f"unifi_rdhcp:{e['data'].get('sw') or ''}", description=e["message"] +
                                  " - another device hands out IP addresses next to OPNsense. Devices that take its "
                                  "lease can get a wrong gateway / DNS (man-in-the-middle).", events={"source": "unifi", "action": "rogue_dhcp"})


_MAC_REF = re.compile(r"\b(User|Guest|AP|Switch|Gateway|Device|UDM|USW|UAP)\[([0-9a-f:]{17})\]", re.I)


def readable(msg: str, names: dict[str, str]) -> str:
    """'User[aa:..] has connected to AP[f4:..]' -> 'User laptop (aa:..) has connected to AP Living room'."""
    def sub(m: re.Match) -> str:
        mac = m[2].lower()
        name = names.get(mac)
        return f"{m[1]} {name} ({mac})" if name and m[1].lower() in ("user", "guest") else f"{m[1]} {name}" if name else m[0]
    return _MAC_REF.sub(sub, msg)


async def test_connection(settings: Settings) -> dict[str, Any]:
    c = UnifiClient(settings)
    try:
        await c.connect()
        if c.legacy:
            devices = await c.legacy_get("stat/device")
            clients = await c.legacy_get("stat/sta")
        else:
            devices = await c.v1_list(f"sites/{c.site_id}/devices")
            clients = await c.v1_list(f"sites/{c.site_id}/clients")
        note = "" if c.legacy else ("Only the integration API works with this key: no SSID, signal, traffic, switch ports or "
                                    "events. Add a local username / password for those.")
        return {"ok": True, "version": c.version, "mode": c.mode, "site": c.site, "sites": c.sites,
                "devices": len(devices), "clients": len(clients), "note": note}
    except UnifiError as exc:
        return {"ok": False, "error": str(exc)}
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc} - check the URL / port"}
    finally:
        await c.close()
