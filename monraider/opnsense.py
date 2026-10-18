"""OPNsense REST API client and the poller that pulls system state, metrics and security logs."""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

import httpx

from . import db
from .config import Settings
from .ingest import STATS, EventWriter
from .parsers import filterlog
from .parsers.common import event, ip_or_none
from .parsers.security import (crowdsec_alert_from_api, crowdsec_decision_from_api, ids_from_api,
                               unbound_from_api)
from .parsers.syslog import parse_iso

log = logging.getLogger(__name__)


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


class OPNsenseClient:
    def __init__(self, settings: Settings) -> None:
        verify: Any = settings.opnsense_verify_ssl
        if settings.opnsense_ca_file:
            verify = settings.opnsense_ca_file
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

    async def search(self, path: str, rows: int = 500) -> list[dict[str, Any]]:
        """Call a ``search*`` endpoint (bootgrid style) and return its rows."""
        try:
            res = await self.post(path, {"current": 1, "rowCount": rows, "searchPhrase": "", "sort": {}})
        except ApiError as exc:
            if exc.status != 405:
                raise
            res = await self.get(path, current=1, rowCount=rows)
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
        self._prev_if: dict[str, tuple[float, float, float]] = {}
        p = max(15, settings.poll_interval)
        self.jobs: list[tuple[str, int, Callable[[], Awaitable[None]]]] = [
            ("system", p, self.poll_system),
            ("gateways", p, self.poll_gateways),
            ("interfaces", p, self.poll_interfaces),
            ("services", 300, self.poll_services),
            ("firmware", 6 * 3600, self.poll_firmware),
            ("rule_labels", 600, self.poll_rule_labels),
            ("arp", 300, self.poll_arp),
            ("firewall_log", 15, self.poll_firewall_log),
        ]
        if settings.unbound_query_pull:
            self.jobs += [("unbound_queries", 60, self.poll_unbound), ("unbound_totals", 300, self.poll_unbound_totals)]
        if settings.crowdsec_pull:
            self.jobs.append(("crowdsec", 120, self.poll_crowdsec))
        if settings.qfeeds_pull:
            self.jobs.append(("qfeeds", 120, self.poll_qfeeds))
        if settings.ids_pull:
            self.jobs.append(("ids", 60, self.poll_ids))
        self._next: dict[str, float] = {}
        self._running: set[str] = set()

    async def run(self) -> None:
        log.info("OPNsense poller started for %s", self.settings.opnsense_url)
        while True:
            now = time.monotonic()
            for name, interval, fn in self.jobs:
                if name in self._running or self._next.get(name, 0) > now:
                    continue
                self._running.add(name)
                asyncio.create_task(self._run_job(name, interval, fn))
            await asyncio.sleep(1)

    async def _run_job(self, name: str, interval: int, fn: Callable[[], Awaitable[None]]) -> None:
        st = self.status.setdefault(name, {"ok": None, "last": None, "error": None, "unsupported": False})
        try:
            await fn()
            st.update(ok=True, last=time.time(), error=None, unsupported=False)
            self._next[name] = time.monotonic() + interval
        except ApiError as exc:
            # 404/400 usually means the plugin is not installed or the endpoint does not exist on this version
            unsupported = exc.status in (400, 404, 403)
            st.update(ok=False, last=time.time(), error=str(exc), unsupported=unsupported)
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
        )
        resources, info, systime, disk, temp, swap, mbuf, states, status = results
        snap = {"resources": resources, "information": info, "time": systime, "disk": disk, "temperature": temp,
                "swap": swap, "mbuf": mbuf, "pf_states": states, "status": status}
        await db.set_snapshot("system", snap)

        metrics: list[tuple[str, str, float]] = []
        mem = (resources or {}).get("memory") or {}
        total, used = _num(mem.get("total")), _num(mem.get("used"))
        if total and used is not None:
            metrics.append(("memory_used_pct", "", round(used / total * 100, 2)))
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
            if not mac or mac == "(incomplete)":
                continue
            devices.append({"mac": mac, "ip": ip_or_none(r.get("ip")), "hostname": r.get("hostname") or None,
                            "manufacturer": r.get("manufacturer"), "intf": r.get("intf_description") or r.get("intf")})
        from .detections import track_devices  # local import to avoid a cycle
        await track_devices(devices, origin="arp")

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
        # newest first
        self._fw_digest = rows[0].get("__digest__", self._fw_digest)
        for row in rows:
            ts = parse_iso(str(row.get("__timestamp__", "")).replace(" ", "T")) or datetime.now(timezone.utc)
            ev = filterlog.from_api(row, ts)
            if ev:
                self.writer.put(ev)

    async def poll_unbound(self) -> None:
        rows = await self.api.get("unbound/overview/searchQueries")
        if isinstance(rows, dict):
            rows = rows.get("rows", [])
        for row in rows or []:
            ev = unbound_from_api(row)
            if ev:
                self.writer.put(ev)

    async def poll_unbound_totals(self) -> None:
        res = await self.api.get("unbound/overview/totals/25")
        await db.set_snapshot("unbound_totals", res)

    async def poll_crowdsec(self) -> None:
        alerts = await self.api.search("crowdsec/alerts/search", rows=1000)
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
        rows = await self.api.search("q_feeds/settings/search_events", rows=5000)
        for r in rows:
            ts = parse_iso(str(r.get("timestamp", ""))) or datetime.now(timezone.utc)
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
