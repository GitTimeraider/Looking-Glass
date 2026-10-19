"""OPNsense REST API client and the poller that pulls system state, metrics and security logs."""
from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable
from zoneinfo import ZoneInfo

import httpx

from . import db
from .config import Settings
from .ingest import STATS, EventWriter
from .parsers import filterlog
from .parsers import nginx as nginx_parser
from .parsers.common import event, ip_or_none, real_name
from .parsers.security import (crowdsec_alert_from_api, crowdsec_decision_from_api, ids_from_api,
                               unbound_from_api)
from .parsers.syslog import parse_iso

log = logging.getLogger(__name__)


def opnsense_utc_offset(text: Any, now: datetime | None = None) -> int | None:
    """'Mon Oct 19 14:58:06 CEST 2026' (diagnostics/system/systemTime, PHP date 'D M j G:i:s T Y') -> 7200.
    The wall clock minus the real UTC time, rounded to 15 minutes (works for any zone, daylight saving included)."""
    parts = str(text or "").split()
    if len(parts) != 6:
        return None
    try:
        local = datetime.strptime(" ".join(parts[1:4] + parts[5:]), "%b %d %H:%M:%S %Y")
    except ValueError:
        return None
    now = (now or datetime.now(timezone.utc)).replace(tzinfo=None)
    off = round((local - now).total_seconds() / 900) * 900
    return off if abs(off) <= 14 * 3600 else None


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


class OPNsenseClient:
    def __init__(self, settings: Settings) -> None:
        verify: Any = settings.opnsense_verify_ssl
        if settings.opnsense_ca_pem:
            verify = ssl.create_default_context(cadata=settings.opnsense_ca_pem)
        self.client = httpx.AsyncClient(
            base_url=settings.opnsense_url.rstrip("/"),
            auth=(settings.opnsense_api_key, settings.opnsense_api_secret),
            verify=verify, timeout=httpx.Timeout(30.0, connect=10.0),
            headers={"Accept": "application/json"},
        )

    async def get(self, path: str, **params: Any) -> Any:
        r = await self.client.get(f"/api/{path.lstrip('/')}", params=params or None)
        return self._result(r)

    async def post(self, path: str, payload: dict[str, Any] | None = None) -> Any:
        r = await self.client.post(f"/api/{path.lstrip('/')}", json=payload or {})
        return self._result(r)

    async def search(self, path: str, rows: int = 500, sort: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """Call a ``search*`` endpoint (bootgrid style) and return its rows; ``sort`` e.g. {"timestamp": "desc"}."""
        try:
            res = await self.post(path, {"current": 1, "rowCount": rows, "searchPhrase": "", "sort": sort or {}})
        except ApiError as exc:
            if exc.status != 405:
                raise
            params = {f"sort[{k}]": v for k, v in (sort or {}).items()}
            res = await self.get(path, current=1, rowCount=rows, **params)
        if isinstance(res, dict):
            return res.get("rows") or []
        return res if isinstance(res, list) else []

    @staticmethod
    def _result(r: httpx.Response) -> Any:
        if r.status_code >= 400:
            raise ApiError(r.status_code, r.text[:300])
        try:
            return r.json()
        except ValueError as exc:
            raise ApiError(r.status_code, f"invalid JSON: {r.text[:200]}") from exc

    async def close(self) -> None:
        await self.client.aclose()


def _num(value: Any) -> float | None:
    """'1.2 ms' / '0.0 %' / '45.0' / 12 -> float."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip().split()[0].rstrip("%"))
    except (ValueError, IndexError):
        return None


class Poller:
    """Runs a set of periodic jobs against the OPNsense API."""

    def __init__(self, settings: Settings, writer: EventWriter) -> None:
        self.settings = settings
        self.writer = writer
        self.api = OPNsenseClient(settings)
        self.status: dict[str, dict[str, Any]] = {}
        self._fw_digest = ""
        self.utc_offset: int | None = None  # OPNsense's current UTC offset in seconds (from its wall clock)
        self._vpn_state: dict[str, str] = {}
        self._static_names: dict[str, str] = {}  # MAC or IP -> host name from dnsmasq "Hosts" entries
        self._dns_ip_names: dict[str, str] = {}  # IP -> host name Unbound reports for a client
        self._prev_if: dict[str, tuple[float, float, float]] = {}
        p = max(15, settings.poll_interval)
        self.jobs: list[tuple[str, int, Callable[[], Awaitable[None]]]] = [
            ("system", p, self.poll_system),
            ("gateways", p, self.poll_gateways),
            ("interfaces", p, self.poll_interfaces),
            ("services", 300, self.poll_services),
            ("firmware", 6 * 3600, self.poll_firmware),
            ("rule_labels", 600, self.poll_rule_labels),
            ("arp", 120, self.poll_arp),
            ("leases", 300, self.poll_leases),
            ("activity", p, self.poll_activity),
            ("firewall_log", 15, self.poll_firewall_log),
        ]
        if settings.unbound_query_pull:
            self.jobs += [("unbound_queries", 60, self.poll_unbound), ("unbound_totals", 300, self.poll_unbound_totals)]
        if settings.crowdsec_pull:
            self.jobs.append(("crowdsec", 120, self.poll_crowdsec))
        if settings.qfeeds_pull:
            self.jobs.append(("qfeeds", 300, self.poll_qfeeds))  # expensive on OPNsense (log crawl), see poll_qfeeds
        if settings.ids_pull:
            self.jobs.append(("ids", 60, self.poll_ids))
        if settings.nginx_pull:
            self.jobs.append(("nginx_logs", 60, self.poll_nginx))
        if settings.vpn_pull:
            self.jobs.append(("vpn", p, self.poll_vpn))
        self._next: dict[str, float] = {}
        self._running: set[str] = set()
        self._tasks: set[asyncio.Task] = set()

    async def run(self) -> None:
        log.info("OPNsense poller started for %s", self.settings.opnsense_url)
        while True:
            now = time.monotonic()
            for name, interval, fn in self.jobs:
                if name in self._running or self._next.get(name, 0) > now:
                    continue
                self._running.add(name)
                task = asyncio.create_task(self._run_job(name, interval, fn))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
            await asyncio.sleep(1)

    async def stop(self) -> None:
        for t in list(self._tasks):
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.api.close()

    async def _run_job(self, name: str, interval: int, fn: Callable[[], Awaitable[None]]) -> None:
        st = self.status.setdefault(name, {"ok": None, "last": None, "error": None, "unsupported": False})
        try:
            await fn()
            st.update(ok=True, last=time.time(), error=None, unsupported=False, forbidden=False)
            self._next[name] = time.monotonic() + interval
        except ApiError as exc:
            # 404/400 usually means the plugin is not installed or the endpoint does not exist on this version
            unsupported = exc.status in (400, 404, 403)
            st.update(ok=False, last=time.time(), error=str(exc), unsupported=unsupported, forbidden=exc.status in (401, 403))
            self._next[name] = time.monotonic() + (3600 if unsupported else interval)
            log.log(logging.DEBUG if unsupported else logging.WARNING, "poll %s failed: %s", name, exc)
        except (httpx.HTTPError, OSError) as exc:
            st.update(ok=False, last=time.time(), error=f"{type(exc).__name__}: {exc}")
            self._next[name] = time.monotonic() + interval
            log.warning("poll %s failed: %s", name, exc)
        except Exception as exc:  # noqa: BLE001
            st.update(ok=False, last=time.time(), error=f"{type(exc).__name__}: {exc}")
            self._next[name] = time.monotonic() + interval
            log.exception("poll %s crashed", name)
        finally:
            self._running.discard(name)
            await db.set_snapshot("poller_status", self.status)

    # ------------------------------------------------------------ system ---
    async def _try(self, path: str, method: str = "get") -> Any:
        try:
            return await (self.api.get(path) if method == "get" else self.api.post(path))
        except (ApiError, httpx.HTTPError):
            return None

    async def poll_system(self) -> None:
        results = await asyncio.gather(
            self.api.get("diagnostics/system/systemResources"),
            self._try("diagnostics/system/systemInformation"),
            self._try("diagnostics/system/systemTime"),
            self._try("diagnostics/system/systemDisk"),
            self._try("diagnostics/system/systemTemperature"),
            self._try("diagnostics/system/systemSwap"),
            self._try("diagnostics/system/systemMbuf"),
            self._try("diagnostics/firewall/pf_states"),
            self._try("core/system/status"),
            self._try("diagnostics/cpu_usage/getCPUType"),
        )
        resources, info, systime, disk, temp, swap, mbuf, states, status, cpu_type = results
        snap = {"resources": resources, "information": info, "time": systime, "disk": disk, "temperature": temp,
                "swap": swap, "mbuf": mbuf, "pf_states": states, "status": status,
                "cpu_type": cpu_type[0] if isinstance(cpu_type, list) and cpu_type else cpu_type}
        await db.set_snapshot("system", snap)

        metrics: list[tuple[str, str, float]] = []
        mem = (resources or {}).get("memory") or {}
        total, used = _num(mem.get("total")), _num(mem.get("used"))
        if total and used is not None:
            metrics.append(("memory_used_pct", "", round(used / total * 100, 2)))
        if isinstance(systime, dict) and (off := opnsense_utc_offset(systime.get("datetime"))) is not None:
            self.utc_offset = off
        if isinstance(systime, dict) and systime.get("loadavg"):
            parts = [p.strip() for p in str(systime["loadavg"]).split(",")]
            if parts and _num(parts[0]) is not None:
                metrics.append(("load1", "", _num(parts[0])))
        if isinstance(states, dict) and _num(states.get("current")) is not None:
            metrics.append(("pf_states", "", _num(states["current"])))
            if _num(states.get("limit")):
                metrics.append(("pf_states_pct", "", round(_num(states["current"]) / _num(states["limit"]) * 100, 2)))
        for d in (disk or {}).get("devices", []) if isinstance(disk, dict) else []:
            pct = _num(d.get("used_pct") or d.get("capacity"))
            if pct is not None:
                metrics.append(("disk_used_pct", d.get("mountpoint", ""), pct))
        swaps = (swap or {}).get("swap", []) if isinstance(swap, dict) else []
        sw_total = sum(_num(x.get("total")) or 0 for x in swaps if isinstance(x, dict))
        sw_used = sum(_num(x.get("used")) or 0 for x in swaps if isinstance(x, dict))
        if sw_total:
            metrics.append(("swap_used_pct", "", round(sw_used / sw_total * 100, 2)))
        if _num(mem.get("arc")) is not None and total:
            metrics.append(("zfs_arc_pct", "", round(_num(mem["arc"]) / total * 100, 2)))
        for t in temp if isinstance(temp, list) else []:
            v = _num(t.get("temperature"))
            if v is not None:
                metrics.append(("temperature", t.get("device", ""), v))
        await db.add_metrics(metrics)

    async def poll_gateways(self) -> None:
        res = await self.api.get("routes/gateway/status")
        items = (res or {}).get("items", [])
        await db.set_snapshot("gateways", items)
        metrics = []
        for gw in items:
            name = gw.get("name", "")
            if _num(gw.get("delay")) is not None:
                metrics.append(("gateway_delay_ms", name, _num(gw["delay"])))
            if _num(gw.get("loss")) is not None:
                metrics.append(("gateway_loss_pct", name, _num(gw["loss"])))
        await db.add_metrics(metrics)

    async def poll_interfaces(self) -> None:
        res = await self.api.get("diagnostics/interface/getInterfaceStatistics")
        stats = (res or {}).get("statistics", res) or {}
        await db.set_snapshot("interfaces", stats)
        now = time.time()
        # several entries exist per interface (link level + one per address); keep the largest counters
        counters: dict[str, dict[str, Any]] = {}
        for key, v in stats.items() if isinstance(stats, dict) else []:
            if not isinstance(v, dict) or _num(v.get("received-bytes")) is None:
                continue
            name = v.get("name") or key
            if name not in counters or _num(v["received-bytes"]) > _num(counters[name]["received-bytes"]):
                counters[name] = v
        metrics = []
        for name, v in counters.items():
            rx, tx = _num(v.get("received-bytes")), _num(v.get("sent-bytes")) or 0.0
            prev = self._prev_if.get(name)
            self._prev_if[name] = (now, rx, tx)
            if prev and now > prev[0] and rx >= prev[1] and tx >= prev[2]:
                dt = now - prev[0]
                metrics.append(("if_rx_bps", name, round((rx - prev[1]) * 8 / dt, 1)))
                metrics.append(("if_tx_bps", name, round((tx - prev[2]) * 8 / dt, 1)))
            for err in ("received-errors", "send-errors", "dropped-packets"):
                if _num(v.get(err)) is not None:
                    metrics.append((f"if_{err.replace('-', '_')}", name, _num(v[err])))
        await db.add_metrics(metrics)

    async def poll_services(self) -> None:
        rows = await self.api.search("core/service/search", rows=500)
        await db.set_snapshot("services", rows)

    async def poll_firmware(self) -> None:
        res = await self.api.get("core/firmware/status")
        await db.set_snapshot("firmware", res)

    async def poll_rule_labels(self) -> None:
        res = await self.api.get("diagnostics/firewall/list_rule_ids")
        items = (res or {}).get("items", [])
        labels = {i["id"]: i.get("descr", "") for i in items if isinstance(i, dict) and i.get("id")}
        filterlog.RULE_LABELS.clear()
        filterlog.RULE_LABELS.update(labels)
        await db.set_snapshot("rule_labels", labels)

    async def poll_arp(self) -> None:
        rows = await self.api.get("diagnostics/interface/getArp")
        rows = rows if isinstance(rows, list) else (rows or {}).get("rows", [])
        await db.set_snapshot("arp", rows)
        devices = []
        for r in rows:
            mac = (r.get("mac") or "").lower()
            if not mac or mac == "(incomplete)" or r.get("expired"):
                continue
            devices.append(self._named({"mac": mac, "ip": ip_or_none(r.get("ip")), "hostname": r.get("hostname") or None,
                                        "vendor": r.get("manufacturer") or None,
                                        "interface": r.get("intf_description") or r.get("intf"), "online": True}))
        from .detections import track_devices  # local import to avoid a cycle
        await track_devices(devices, origin="arp", mark_online=True)

    async def poll_leases(self) -> None:
        """DHCP leases from whichever DHCP server is in use: Kea, dnsmasq or ISC dhcpd (plugin)."""
        from .detections import track_devices

        await self._load_static_names()
        found = False
        for path, kind in (("kea/leases4/search", "kea"), ("dnsmasq/leases/search", "dnsmasq"),
                           ("dhcpv4/leases/search_lease", "isc")):
            try:
                rows = await self.api.search(path, rows=5000)
            except ApiError:
                continue
            found = True
            await db.set_snapshot(f"leases_{kind}", rows)
            devices = []
            for r in rows:
                mac = (r.get("hwaddr") or r.get("mac") or "").lower()
                if not mac:
                    continue
                devices.append(self._named({
                    "mac": mac, "ip": ip_or_none(r.get("address")), "hostname": r.get("hostname") or None,
                    "vendor": r.get("mac_info") or r.get("man") or None, "interface": r.get("if_descr") or r.get("if"),
                    "lease_type": r.get("lease_type") or r.get("type"),
                    "lease_expires": str(r.get("expire") or r.get("ends") or "") or None,
                    "online": str(r.get("status", "")).lower() == "online"}))
            await track_devices(devices, origin=f"dhcp-{kind}")
        if not found:
            raise ApiError(404, "no DHCP lease API found (Kea, dnsmasq or ISC DHCP)")

    async def _load_static_names(self) -> None:
        """Names from dnsmasq "Hosts" entries (Services > Dnsmasq DNS & DHCP > Hosts): static DHCP reservations
        and local DNS names, keyed by MAC and by IP. Kept from the last good read when the call fails."""
        try:
            rows = await self.api.search("dnsmasq/settings/search_host", rows=5000)
        except (ApiError, httpx.HTTPError, ValueError):
            return
        names: dict[str, str] = {}
        for r in rows:
            name = real_name(r.get("host")) or real_name(r.get("descr"))
            if not name:
                continue
            for key in ("hwaddr", "ip"):
                vals = r.get(key) or []
                for v in vals if isinstance(vals, list) else str(vals).split(","):
                    v = v.strip().lower()
                    if v and (key == "hwaddr" or ip_or_none(v)):
                        names.setdefault(v, name)
        self._static_names = names

    def _named(self, d: dict[str, Any]) -> dict[str, Any]:
        """Best known name: dnsmasq Hosts entry > name from the lease / ARP table > the name Unbound shows for the IP.
        Placeholders such as "*" (dnsmasq: client sent no name) and "-" / "?" (ARP) count as no name."""
        static = self._static_names.get(d["mac"]) or (d.get("ip") and self._static_names.get(d["ip"]))
        if static:
            d.update(hostname=static, name_source="dnsmasq-static")
        elif not real_name(d.get("hostname")) and d.get("ip") in self._dns_ip_names:
            d.update(hostname=self._dns_ip_names[d["ip"]], name_source="dns")
        return d

    async def poll_activity(self) -> None:
        """CPU usage and top processes from the 'top' based activity endpoint."""
        res = await self.api.get("diagnostics/activity/getActivity")
        headers = (res or {}).get("headers", []) if isinstance(res, dict) else []
        details = (res or {}).get("details", []) if isinstance(res, dict) else []
        await db.set_snapshot("activity", {"headers": headers, "details": details[:40]})
        metrics = []
        for line in headers:
            if line.startswith("CPU:"):
                parts = {kv.split("%")[1].strip().rstrip(","): _num(kv.split("%")[0]) for kv in line[4:].split(",") if "%" in kv}
                if parts.get("idle") is not None:
                    metrics.append(("cpu_used_pct", "", round(100 - parts["idle"], 2)))
                for k in ("user", "system", "interrupt"):
                    if parts.get(k) is not None:
                        metrics.append((f"cpu_{k}_pct", "", parts[k]))
        await db.add_metrics(metrics)

    # ------------------------------------------------------------- logs ---
    async def poll_firewall_log(self) -> None:
        mode = self.settings.firewall_log_pull.lower()
        if mode == "never":
            return
        if mode == "auto":
            last = STATS.last_by_source.get("firewall", 0)
            if time.time() - last < 300:
                return  # filterlog arrives through syslog, no need to pull
        params: dict[str, Any] = {"limit": 1000}
        if self._fw_digest:
            params["digest"] = self._fw_digest
        rows = await self.api.get("diagnostics/firewall/log", **params)
        if not isinstance(rows, list) or not rows:
            return
        if self.utc_offset is None:  # needed to read the zone-less time stamps below
            try:
                self.utc_offset = opnsense_utc_offset((await self.api.get("diagnostics/system/systemTime") or {}).get("datetime"))
            except (ApiError, httpx.HTTPError, AttributeError):
                pass
        # newest first
        self._fw_digest = rows[0].get("__digest__", self._fw_digest)
        for row in rows:
            # OPNsense strips the zone from this time stamp (read_log.py: split('+')[0]) - it is local time
            ts = self.local_ts(str(row.get("__timestamp__", "")).replace(" ", "T")) or datetime.now(timezone.utc)
            ev = filterlog.from_api(row, ts)
            if ev:
                self.writer.put(ev)

    async def _dns_names(self) -> dict[str, str]:
        """hostname -> IP, so queries whose client Unbound reports as a hostname keep their IP.
        Sources: Unbound's own per-client statistics, then the device list (DHCP leases / ARP)."""
        names: dict[str, str] = {}
        try:
            for r in await db.pool().fetch("SELECT DISTINCT ON (hostname) hostname, host(ip) ip FROM devices "
                                           "WHERE hostname IS NOT NULL AND ip IS NOT NULL ORDER BY hostname, last_seen DESC"):
                names[r["hostname"].lower()] = r["ip"]
        except Exception:  # noqa: BLE001
            pass
        try:
            rolling = await self.api.get("unbound/overview/Rolling/1/1")
            for per_ts in (rolling or {}).values() if isinstance(rolling, dict) else []:
                for ip, info in (per_ts or {}).items() if isinstance(per_ts, dict) else []:
                    host = (info or {}).get("hostname") if isinstance(info, dict) else None
                    if host and ip_or_none(ip):
                        names[str(host).lower()] = ip
                        self._dns_ip_names[ip] = str(host)
        except (ApiError, httpx.HTTPError, ValueError):
            pass
        for name, ip in list(names.items()):
            names.setdefault(name.split(".")[0], ip)
        return names

    async def poll_unbound(self) -> None:
        rows = await self.api.get("unbound/overview/searchQueries")
        if isinstance(rows, dict):
            rows = rows.get("rows", [])
        names = await self._dns_names() if any(r.get("client") and not ip_or_none(str(r.get("client"))) for r in rows or []) else {}
        for row in rows or []:
            ev = unbound_from_api(row, names)
            if ev:
                self.writer.put(ev)

    # ------------------------------------------------------------ nginx ---
    def local_tz(self):
        """OPNsense's local time zone: measured from its clock, else the Looking Glass time zone setting."""
        if self.utc_offset is not None:
            return timezone(timedelta(seconds=self.utc_offset))
        try:
            return ZoneInfo(self.settings.timezone or "UTC")
        except Exception:  # noqa: BLE001
            return timezone.utc

    def local_ts(self, value: str) -> datetime | None:
        """A time stamp written in OPNsense local time; one that carries its own zone is kept as it is."""
        try:
            dt = datetime.fromisoformat(value.strip())
        except ValueError:
            return parse_iso(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=self.local_tz()).astimezone(timezone.utc)

    async def poll_nginx(self) -> None:
        """os-nginx access / error / stream logs via its log API: OPNsense remote syslog only forwards nginx's
        global error log, the per-server access logs exist as files only (/var/log/nginx/<server>.access.log)."""
        tz = self.local_tz()  # nginx error log times are OPNsense local time without zone
        now = datetime.now(timezone.utc)
        kinds = (("accesses", nginx_parser.access_from_api), ("errors", nginx_parser.error_from_api),
                 ("streamaccesses", nginx_parser.stream_from_api))
        for kind, convert in kinds:
            try:
                servers = await self.api.get(f"nginx/logs/{kind}")
            except ApiError as exc:
                if exc.status in (400, 404) and kind != "accesses":
                    continue
                raise
            for srv in servers if isinstance(servers, list) else []:
                sid = str(srv.get("id") or "")
                if not sid or sid == "perm_ban":
                    continue
                name = srv.get("server_name") or (f"port {srv['port']}" if srv.get("port") else sid)
                # newest file (-1); read the first and the last page so either sort order is covered
                first = await self.api.get(f"nginx/logs/{kind}/{sid}/-1/1/1000")
                if not isinstance(first, dict) or first.get("error"):
                    continue
                lines = list(first.get("lines") or [])
                pages = int(first.get("pages") or 1)
                if pages > 1:
                    last = await self.api.get(f"nginx/logs/{kind}/{sid}/-1/{pages}/1000")
                    lines += (last or {}).get("lines") or [] if isinstance(last, dict) else []
                for line in lines:
                    if not isinstance(line, dict):
                        continue
                    ev = convert(line, name, now, None, tz) if kind == "errors" else convert(line, name, now)
                    if ev:
                        ev["uid"] = "ngx:" + hashlib.sha1(f"{kind}|{sid}|{json.dumps(line, sort_keys=True)}".encode()).hexdigest()
                        self.writer.put(ev)

    # -------------------------------------------------------------- VPN ---
    async def poll_vpn(self) -> None:
        """WireGuard / OpenVPN / IPsec live status. WireGuard does not log handshakes, so peer state changes
        are turned into events here."""
        out: dict[str, Any] = {"errors": {}}
        try:
            wg = await self.api.get("wireguard/service/show")
            rows = wg.get("rows", []) if isinstance(wg, dict) else wg or []
            peers = [r for r in rows if r.get("type") == "peer"]
            out["wireguard"] = {"interfaces": [r for r in rows if r.get("type") == "interface"], "peers": peers}
            rx_rows = []
            for p in peers:
                key = f'{p.get("if")}:{p.get("public-key")}'
                name = p.get("name") or (p.get("public-key") or "")[:10]
                status = p.get("peer-status") or ("online" if (p.get("latest-handshake-age") or 1e9) <= 300 else "offline")
                prev = self._vpn_state.get(key)
                if prev is not None and prev != status and status in ("online", "offline", "stale"):
                    ep = str(p.get("endpoint") or "")
                    ep_ip = ip_or_none(ep.rsplit(":", 1)[0].strip("[]")) if ep and ep != "(none)" else None
                    self.writer.put(event(datetime.now(timezone.utc), "vpn", program="wireguard", severity=5,
                                          action="vpn_connect" if status == "online" else "vpn_disconnect",
                                          src_ip=ep_ip, username=name,
                                          message=f"WireGuard peer {name} on {p.get('ifname') or p.get('if')} is {status}"
                                                  + (f" (endpoint {ep})" if ep_ip else ""),
                                          data={"peer": name, "interface": p.get("if"), "endpoint": ep, "status": status,
                                                "allowed_ips": p.get("allowed-ips")}))
                self._vpn_state[key] = status
                for direction, k in (("rx", "transfer-rx"), ("tx", "transfer-tx")):
                    v = _num(p.get(k))
                    if v is not None:
                        rx_rows.append((f"wg_peer_{direction}_bytes", f"{p.get('if')}:{name}", v))
            out["wireguard"]["online"] = sum(1 for p in peers if p.get("peer-status") == "online")
            await db.add_metrics(rx_rows + [("wg_peers_online", "", float(out["wireguard"]["online"]))])
        except ApiError as exc:
            if exc.status not in (400, 403, 404):
                raise
            out["errors"]["wireguard"] = exc.status
        try:
            out["openvpn"] = await self.api.search("openvpn/service/search_sessions", rows=500)
        except ApiError as exc:
            if exc.status not in (400, 403, 404):
                raise
            out["errors"]["openvpn"] = exc.status
        try:
            out["ipsec"] = await self.api.search("ipsec/sessions/search_phase1", rows=500)
        except ApiError as exc:
            if exc.status not in (400, 403, 404):
                raise
            out["errors"]["ipsec"] = exc.status
        await db.set_snapshot("vpn", out)

    async def poll_unbound_totals(self) -> None:
        res = await self.api.get("unbound/overview/totals/25")
        await db.set_snapshot("unbound_totals", res)

    async def poll_crowdsec(self) -> None:
        # cscli lists every alert ever: ask for the newest ones (the default order is not guaranteed)
        alerts = await self.api.search("crowdsec/alerts/search", rows=500, sort={"created": "desc"})
        for row in alerts:
            ev = crowdsec_alert_from_api(row)
            if ev:
                self.writer.put(ev)
        decisions = await self.api.search("crowdsec/decisions/search", rows=5000)
        await db.set_snapshot("crowdsec_decisions", decisions[:5000])
        for row in decisions:
            ev = crowdsec_decision_from_api(row)
            if ev:
                self.writer.put(ev)

    async def poll_qfeeds(self) -> None:
        # Q-Feeds has no event store: every call re-reads the firewall log files on OPNsense, oldest line of a file
        # first - so ask for the newest rows explicitly (unsorted, the first rows are the oldest of the day)
        rows = await self.api.search("q_feeds/settings/search_events", rows=1000, sort={"timestamp": "desc"})
        for r in rows:
            ts = self.local_ts(str(r.get("timestamp", ""))) or datetime.now(timezone.utc)
            src, dst = r.get("source"), r.get("destination")
            self.writer.put(event(
                ts, "qfeeds", program="qfeeds", severity=4, action="block", src_ip=src, dst_ip=dst,
                src_port=r.get("source_port"), dst_port=r.get("destination_port"), interface=r.get("interface"),
                direction=r.get("direction"),
                message=f'Q-Feeds threat-intel match {r.get("direction", "")} on {r.get("interface", "")}: '
                        f'{src}:{r.get("source_port", "")} -> {dst}:{r.get("destination_port", "")}',
                uid=f'qf:{r.get("timestamp")}:{src}:{dst}:{r.get("source_port")}:{r.get("destination_port")}',
            ))
        try:
            await db.set_snapshot("qfeeds_stats", await self.api.get("q_feeds/settings/stats"))
        except ApiError:
            pass

    async def poll_ids(self) -> None:
        res = await self.api.post("ids/service/queryAlerts", {"rowCount": 500, "current": 1, "searchPhrase": ""})
        for row in (res or {}).get("rows", []) if isinstance(res, dict) else []:
            ev = ids_from_api(row)
            if ev:
                self.writer.put(ev)
