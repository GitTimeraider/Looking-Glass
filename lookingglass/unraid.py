"""Unraid servers: hardware, array/disks, Docker containers (+ logs), VMs, UPS and notifications.

Uses the official Unraid API (GraphQL at ``<url>/graphql``, header ``x-api-key``), built into Unraid 7.2+
and available for older 6.12/7.x releases through the Unraid Connect plugin. Every section is fetched with
its own query so that fields missing on older API versions only disable that section.

Optionally a read-only Docker API endpoint (docker-socket-proxy) adds per-container CPU / memory / network
statistics and a log fallback.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import struct
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from . import db
from .config import Settings
from .detections import raise_alert
from .ingest import EventWriter
from .parsers import parse_line
from .parsers.common import event
from .parsers.syslog import parse_iso

log = logging.getLogger(__name__)

DISK_FIELDS = "id idx name device size status rotational temp numReads numWrites numErrors fsSize fsFree fsUsed type warning critical fsType isSpinning color"

QUERIES: dict[str, str] = {
    "info": """{ info {
        os { hostname distro release kernel arch uptime uefi }
        cpu { manufacturer brand cores threads speed speedmax socket packages { temp totalPower } }
        system { manufacturer model virtual }
        baseboard { manufacturer model memMax memSlots }
        versions { core { unraid api kernel } }
        memory { layout { size type clockSpeed manufacturer } }
    } }""",
    "metrics": """{ metrics {
        cpu { percentTotal cpus { percentTotal } }
        memory { total used available percentTotal swapTotal swapUsed percentSwapTotal }
        temperature { sensors { name type current { value status } warning critical } }
        network { name operstate rxSec txSec receiveErrors transmitErrors }
    } }""",
    "metrics_basic": """{ metrics { cpu { percentTotal cpus { percentTotal } } memory { total used available percentTotal swapTotal swapUsed percentSwapTotal } } }""",
    "array": """{ array {
        state
        capacity { kilobytes { free used total } disks { free used total } }
        parityCheckStatus { status progress errors running paused speed date duration }
        parities { %s } disks { %s } caches { %s } boot { %s }
    } }""" % (DISK_FIELDS, DISK_FIELDS, DISK_FIELDS, DISK_FIELDS),
    "docker": """{ docker { containers {
        id names image state status autoStart isUpdateAvailable webUiUrl iconUrl created
        ports { ip privatePort publicPort type }
    } } }""",
    "docker_basic": """{ docker { containers { id names image state status autoStart created } } }""",
    "notifications": """{ notifications {
        overview { unread { info warning alert total } archive { total } }
        list(filter: { type: UNREAD, offset: 0, limit: 100 }) { id title subject description importance timestamp link }
    } }""",
    "vms": """{ vms { domains { id name state } } }""",
    "ups": """{ upsDevices { id name model status battery { chargeLevel estimatedRuntime health } power { loadPercentage currentPower inputVoltage outputVoltage } } }""",
    "shares": """{ shares { name free used size comment cache } }""",
    "disks": """{ disks { id device name vendor size type interfaceType smartStatus temperature isSpinning serialNum firmwareRevision } }""",
}


class GraphQLError(Exception):
    pass


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


class UnraidClient:
    def __init__(self, server: dict[str, Any]) -> None:
        self.server = server
        self.http = httpx.AsyncClient(base_url=server["url"].rstrip("/"), verify=server["verify_ssl"],
                                      headers={"x-api-key": server["api_key"], "Content-Type": "application/json",
                                               "Accept": "application/json"},
                                      timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=True)
        self.docker = None
        if server.get("docker_url"):
            self.docker = httpx.AsyncClient(base_url=server["docker_url"].rstrip("/"), timeout=httpx.Timeout(20.0, connect=5.0))

    async def query(self, q: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        r = await self.http.post("/graphql", json={"query": q, "variables": variables or {}})
        if r.status_code >= 400:
            raise GraphQLError(f"HTTP {r.status_code}: {r.text[:300]}")
        body = r.json()
        if body.get("errors") and not body.get("data"):
            raise GraphQLError("; ".join(e.get("message", "?") for e in body["errors"])[:500])
        return body.get("data") or {}

    async def close(self) -> None:
        await self.http.aclose()
        if self.docker:
            await self.docker.aclose()


class UnraidServerPoller:
    def __init__(self, server: dict[str, Any], settings: Settings, writer: EventWriter) -> None:
        self.server = server
        self.sid = server["id"]
        self.name = server["name"]
        self.settings = settings
        self.writer = writer
        self.client = UnraidClient(server)
        self.status: dict[str, Any] = {"ok": None, "error": None, "last": None, "sections": {}}
        self.failures = 0
        self.seen_notifications: set[str] = set()
        self.log_cursors: dict[str, str] = {}
        self.syslog_line = 0
        self.last_run: dict[str, float] = {}

    def due(self, key: str, interval: int) -> bool:
        if time.time() - self.last_run.get(key, 0) >= interval:
            self.last_run[key] = time.time()
            return True
        return False

    async def snap(self, key: str, data: Any) -> None:
        await db.set_snapshot(f"unraid:{self.sid}:{key}", data)

    async def section(self, key: str, *query_names: str) -> dict[str, Any] | None:
        """Run the first query variant that works (newer schema first, basic fallback after)."""
        err = None
        for qn in query_names:
            try:
                data = await self.client.query(QUERIES[qn])
                self.status["sections"][key] = {"ok": True, "variant": qn}
                return data
            except GraphQLError as exc:
                err = str(exc)
        self.status["sections"][key] = {"ok": False, "error": err}
        return None

    async def poll(self) -> None:
        p = max(20, self.settings.poll_interval)
        try:
            if self.due("info", 600):
                d = await self.section("info", "info")
                if d:
                    await self.snap("info", d.get("info"))
            await self.poll_metrics()
            if self.due("array", p):
                await self.poll_array()
            if self.due("docker", p):
                await self.poll_docker()
            if self.due("notifications", 120):
                await self.poll_notifications()
            if self.due("misc", 300):
                for key in ("vms", "ups", "shares", "disks"):
                    d = await self.section(key, key)
                    if d is not None:
                        await self.snap(key, d.get({"ups": "upsDevices"}.get(key, key)))
                await self.check_ups()
            if self.server.get("collect_logs") and self.due("logs", 120):
                await self.poll_container_logs()
                await self.poll_syslog()
            if self.client.docker and self.due("docker_stats", p):
                await self.poll_docker_stats()
            self.failures = 0
            self.status.update(ok=True, error=None, last=time.time())
        except (httpx.HTTPError, OSError, GraphQLError) as exc:
            self.failures += 1
            self.status.update(ok=False, error=f"{type(exc).__name__}: {exc}", last=time.time())
            log.warning("unraid %s: %s", self.name, exc)
            if self.failures == 3:
                await raise_alert("unraid_unreachable", "medium", f"Unraid server {self.name} is unreachable",
                                  f"unraid_down:{self.sid}", description=str(exc))

    # ------------------------------------------------------------ sections ---
    async def poll_metrics(self) -> None:
        d = await self.section("metrics", "metrics", "metrics_basic")
        if not d:
            return
        m = d.get("metrics") or {}
        await self.snap("metrics", m)
        sid = str(self.sid)
        rows: list[tuple[str, str, float]] = []
        cpu, mem = m.get("cpu") or {}, m.get("memory") or {}
        if _num(cpu.get("percentTotal")) is not None:
            rows.append(("unraid_cpu_pct", sid, round(_num(cpu["percentTotal"]), 2)))
        for i, c in enumerate(cpu.get("cpus") or []):
            if _num(c.get("percentTotal")) is not None:
                rows.append(("unraid_core_pct", f"{sid}:{i}", round(_num(c["percentTotal"]), 2)))
        if _num(mem.get("percentTotal")) is not None:
            rows.append(("unraid_mem_pct", sid, round(_num(mem["percentTotal"]), 2)))
        if _num(mem.get("percentSwapTotal")) is not None:
            rows.append(("unraid_swap_pct", sid, round(_num(mem["percentSwapTotal"]), 2)))
        for s in ((m.get("temperature") or {}).get("sensors") or []):
            v = _num((s.get("current") or {}).get("value"))
            if v is not None:
                rows.append(("unraid_temp", f"{sid}:{s.get('name')}", v))
                crit = _num(s.get("critical"))
                if crit and v >= crit:
                    await raise_alert("unraid_temp", "high", f"{self.name}: sensor {s.get('name')} at {v:.0f}°C",
                                      f"unraid_temp:{self.sid}:{s.get('name')}", description="Temperature above critical threshold.")
        for n in m.get("network") or []:
            if n.get("name") and _num(n.get("rxSec")) is not None:
                rows.append(("unraid_net_rx_bps", f"{sid}:{n['name']}", round(_num(n["rxSec"]) * 8, 1)))
                rows.append(("unraid_net_tx_bps", f"{sid}:{n['name']}", round(_num(n.get("txSec")) * 8, 1)))
        await db.add_metrics(rows)

    async def poll_array(self) -> None:
        d = await self.section("array", "array")
        if not d:
            return
        arr = d.get("array") or {}
        await self.snap("array", arr)
        sid = str(self.sid)
        rows: list[tuple[str, str, float]] = []
        kb = ((arr.get("capacity") or {}).get("kilobytes") or {})
        total, used = _num(kb.get("total")), _num(kb.get("used"))
        if total:
            rows.append(("unraid_array_used_pct", sid, round((used or 0) / total * 100, 2)))
        if arr.get("state") and arr["state"] != "STARTED":
            await raise_alert("unraid_array", "high", f"{self.name}: array state {arr['state']}", f"unraid_array:{self.sid}",
                              description="The Unraid array is not started.")
        pc = arr.get("parityCheckStatus") or {}
        if (pc.get("errors") or 0) > 0:
            await raise_alert("unraid_parity", "medium", f"{self.name}: parity check found {pc['errors']} errors",
                              f"unraid_parity:{self.sid}", description=str(pc))
        for group in ("parities", "disks", "caches"):
            for disk in arr.get(group) or []:
                name = disk.get("name") or disk.get("device") or "?"
                temp = _num(disk.get("temp"))
                if temp is not None:
                    rows.append(("unraid_disk_temp", f"{sid}:{name}", temp))
                    crit, warn = _num(disk.get("critical")) or 55, _num(disk.get("warning")) or 50
                    if temp >= crit or temp >= warn:
                        await raise_alert("unraid_disk_temp", "high" if temp >= crit else "medium",
                                          f"{self.name}: disk {name} at {temp:.0f}°C", f"unraid_dtemp:{self.sid}:{name}",
                                          description=f"Disk temperature above {'critical' if temp >= crit else 'warning'} threshold.")
                if disk.get("fsSize"):
                    rows.append(("unraid_disk_used_pct", f"{sid}:{name}",
                                 round((_num(disk.get("fsUsed")) or 0) / _num(disk["fsSize"]) * 100, 2)))
                status = disk.get("status")
                if status and status not in ("DISK_OK", "DISK_NP"):
                    await raise_alert("unraid_disk", "high", f"{self.name}: disk {name} status {status}",
                                      f"unraid_disk:{self.sid}:{name}", description=str(disk))
                if (_num(disk.get("numErrors")) or 0) > 0:
                    await raise_alert("unraid_disk_errors", "medium", f"{self.name}: disk {name} has {disk['numErrors']} I/O errors",
                                      f"unraid_derr:{self.sid}:{name}", description="Check SMART data and cables.")
        await db.add_metrics(rows)

    async def poll_docker(self) -> None:
        d = await self.section("docker", "docker", "docker_basic")
        if not d:
            return
        containers = (d.get("docker") or {}).get("containers") or []
        await self.snap("docker", containers)
        running = sum(1 for c in containers if c.get("state") == "RUNNING")
        await db.add_metrics([("unraid_containers_running", str(self.sid), running),
                              ("unraid_containers_total", str(self.sid), len(containers))])
        for c in containers:
            name = (c.get("names") or ["?"])[0].lstrip("/")
            if c.get("autoStart") and c.get("state") == "EXITED":
                await raise_alert("unraid_container_down", "medium", f"{self.name}: container {name} is stopped",
                                  f"unraid_ctr:{self.sid}:{name}",
                                  description=f"Container is set to autostart but its state is EXITED ({c.get('status')}).")

    async def poll_notifications(self) -> None:
        d = await self.section("notifications", "notifications")
        if not d:
            return
        n = d.get("notifications") or {}
        items = n.get("list") or []
        await self.snap("notifications", {"overview": n.get("overview"), "list": items})
        for it in items:
            nid = str(it.get("id"))
            if nid in self.seen_notifications:
                continue
            self.seen_notifications.add(nid)
            importance = str(it.get("importance") or "INFO").upper()
            ts = _parse_ts(it.get("timestamp"))
            self.writer.put(event(ts, "unraid", host=self.name, program="notification",
                                  severity={"ALERT": 2, "WARNING": 4}.get(importance, 6), action="notification",
                                  message=f"[{importance}] {it.get('title', '')}: {it.get('subject', '')} - {it.get('description', '')}"[:4000],
                                  data={"server_id": self.sid, "importance": importance, "title": it.get("title"),
                                        "subject": it.get("subject"), "link": it.get("link")},
                                  uid=f"unraid-notif:{self.sid}:{nid}"))
            if importance in ("ALERT", "WARNING"):
                await raise_alert("unraid_notification", "high" if importance == "ALERT" else "medium",
                                  f"{self.name}: {it.get('subject') or it.get('title')}",
                                  f"unraid_notif:{self.sid}:{it.get('title')}:{it.get('subject')}",
                                  description=str(it.get("description") or ""))

    async def check_ups(self) -> None:
        ups = await db.get_snapshot(f"unraid:{self.sid}:ups") or []
        for u in ups if isinstance(ups, list) else []:
            status = str(u.get("status") or "")
            if status and "online" not in status.lower():
                await raise_alert("unraid_ups", "high", f"{self.name}: UPS {u.get('name')} {status}",
                                  f"unraid_ups:{self.sid}:{u.get('name')}", description=str(u))
            charge = (u.get("battery") or {}).get("chargeLevel")
            if charge is not None:
                await db.add_metrics([("unraid_ups_charge", f"{self.sid}:{u.get('name')}", charge),
                                      ("unraid_ups_load", f"{self.sid}:{u.get('name')}", (u.get("power") or {}).get("loadPercentage") or 0)])

    # ---------------------------------------------------------------- logs ---
    async def poll_container_logs(self) -> None:
        containers = await db.get_snapshot(f"unraid:{self.sid}:docker") or []
        sem = asyncio.Semaphore(4)

        async def one(c: dict[str, Any]) -> None:
            if c.get("state") != "RUNNING":
                return
            name = (c.get("names") or ["?"])[0].lstrip("/")
            since = self.log_cursors.get(c["id"])
            async with sem:
                try:
                    q = ("query($id: PrefixedID!, $since: DateTime, $tail: Int) { docker { logs(id: $id, since: $since, tail: $tail) "
                         "{ cursor lines { timestamp message } } } }")
                    d = await self.client.query(q, {"id": c["id"], "since": since, "tail": 200 if since is None else 1000})
                    logs = (d.get("docker") or {}).get("logs") or {}
                    lines = [(ln.get("timestamp"), ln.get("message", "")) for ln in logs.get("lines") or []]
                    if logs.get("cursor"):
                        self.log_cursors[c["id"]] = logs["cursor"]
                except GraphQLError:
                    if not self.client.docker:
                        return
                    lines = await self.docker_logs(c, since)
            for ts_s, msg in lines:
                self.put_container_line(name, ts_s, msg)

        await asyncio.gather(*(one(c) for c in containers if isinstance(c, dict)))

    def put_container_line(self, container: str, ts_s: Any, msg: str) -> None:
        msg = (msg or "").rstrip()
        if not msg:
            return
        low = msg.lower()
        sev = 3 if any(w in low for w in ("error", "fatal", "panic", "exception", "traceback", "critical")) else \
            4 if "warn" in low else 6
        ts = _parse_ts(ts_s)
        uid = hashlib.sha1(f"{self.sid}|{container}|{ts_s}|{msg}".encode()).hexdigest()
        self.writer.put(event(ts, "docker", host=self.name, program=container, severity=sev,
                              action="container_log", message=msg[:4000], data={"server_id": self.sid, "container": container},
                              uid=f"ctr:{uid}"))

    async def docker_logs(self, c: dict[str, Any], since: str | None) -> list[tuple[str, str]]:
        """Fallback: logs through the Docker API (multiplexed stream unless the container has a TTY)."""
        name = (c.get("names") or ["?"])[0].lstrip("/")
        params: dict[str, Any] = {"stdout": 1, "stderr": 1, "timestamps": 1}
        params["since" if since else "tail"] = int(parse_iso(since).timestamp()) if since and parse_iso(since) else 200
        try:
            r = await self.client.docker.get(f"/containers/{name}/logs", params=params)
        except httpx.HTTPError:
            return []
        if r.status_code != 200:
            return []
        raw, out, i = r.content, [], 0
        text_chunks = []
        while i + 8 <= len(raw) and raw[i] in (0, 1, 2) and raw[i + 1:i + 4] == b"\x00\x00\x00":
            size = struct.unpack(">I", raw[i + 4:i + 8])[0]
            text_chunks.append(raw[i + 8:i + 8 + size])
            i += 8 + size
        text = (b"".join(text_chunks) if text_chunks else raw).decode("utf-8", errors="replace")
        last_ts = since
        for line in text.splitlines():
            ts_s, _, msg = line.partition(" ")
            out.append((ts_s, msg))
            last_ts = ts_s
        if last_ts:
            self.log_cursors[c["id"]] = last_ts
        return out

    async def poll_syslog(self) -> None:
        q = "query($path: String!, $lines: Int, $start: Int) { logFile(path: $path, lines: $lines, startLine: $start) { totalLines startLine content } }"
        try:
            head = await self.client.query(q, {"path": "/var/log/syslog", "lines": 1, "start": None})
        except GraphQLError as exc:
            self.status["sections"]["syslog"] = {"ok": False, "error": str(exc)}
            return
        total = int(((head.get("logFile") or {}).get("totalLines")) or 0)
        if total < self.syslog_line:  # rotated
            self.syslog_line = 0
        start = self.syslog_line + 1 if self.syslog_line else max(1, total - 300)
        if start > total:
            self.status["sections"]["syslog"] = {"ok": True}
            return
        d = await self.client.query(q, {"path": "/var/log/syslog", "lines": min(2000, total - start + 1), "start": start})
        content = ((d.get("logFile") or {}).get("content")) or ""
        tz = _local_tz(self.settings.timezone)
        for offset, line in enumerate(content.splitlines()):
            if not line.strip():
                continue
            ev = parse_line(f"<14>{line}", sender=self.name, local_tz=tz)
            if not ev:
                continue
            if ev["source"] in ("system",):
                ev["source"] = "unraid"
            ev["host"] = self.name
            ev["uid"] = "usys:" + hashlib.sha1(f"{self.sid}|{start + offset}|{line}".encode()).hexdigest()
            self.writer.put(ev)
        self.syslog_line = start + len(content.splitlines()) - 1
        self.status["sections"]["syslog"] = {"ok": True}

    # ----------------------------------------------------- docker statistics ---
    async def poll_docker_stats(self) -> None:
        r = await self.client.docker.get("/containers/json")
        r.raise_for_status()
        containers = r.json()
        sem = asyncio.Semaphore(6)
        stats: list[dict[str, Any]] = []

        async def one(c: dict[str, Any]) -> None:
            name = (c.get("Names") or ["?"])[0].lstrip("/")
            async with sem:
                try:
                    s = (await self.client.docker.get(f"/containers/{c['Id']}/stats", params={"stream": "false"})).json()
                except (httpx.HTTPError, ValueError):
                    return
            cpu, pre = s.get("cpu_stats") or {}, s.get("precpu_stats") or {}
            cpu_delta = (cpu.get("cpu_usage") or {}).get("total_usage", 0) - (pre.get("cpu_usage") or {}).get("total_usage", 0)
            sys_delta = (cpu.get("system_cpu_usage") or 0) - (pre.get("system_cpu_usage") or 0)
            ncpu = cpu.get("online_cpus") or len((cpu.get("cpu_usage") or {}).get("percpu_usage") or []) or 1
            cpu_pct = cpu_delta / sys_delta * ncpu * 100 if sys_delta > 0 and cpu_delta >= 0 else 0.0
            mem = s.get("memory_stats") or {}
            mem_used = (mem.get("usage") or 0) - ((mem.get("stats") or {}).get("inactive_file") or (mem.get("stats") or {}).get("cache") or 0)
            nets = s.get("networks") or {}
            stats.append({"name": name, "image": c.get("Image"), "state": c.get("State"), "status": c.get("Status"),
                          "cpu_pct": round(cpu_pct, 2), "mem_bytes": max(0, mem_used), "mem_limit": mem.get("limit"),
                          "rx_bytes": sum(n.get("rx_bytes", 0) for n in nets.values()),
                          "tx_bytes": sum(n.get("tx_bytes", 0) for n in nets.values()),
                          "pids": (s.get("pids_stats") or {}).get("current")})

        await asyncio.gather(*(one(c) for c in containers))
        stats.sort(key=lambda x: -x["cpu_pct"])
        await self.snap("docker_stats", stats)
        rows = []
        for st in stats:
            rows.append(("container_cpu_pct", f"{self.sid}:{st['name']}", st["cpu_pct"]))
            rows.append(("container_mem_bytes", f"{self.sid}:{st['name']}", float(st["mem_bytes"])))
        await db.add_metrics(rows)
        self.status["sections"]["docker_stats"] = {"ok": True}


def _parse_ts(value: Any) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000 if value > 1e11 else value, tz=timezone.utc)
    s = str(value)
    if s.isdigit():
        return _parse_ts(int(s))
    return parse_iso(s) or datetime.now(timezone.utc)


def _local_tz(name: str):
    from zoneinfo import ZoneInfo
    try:
        return ZoneInfo(name)
    except Exception:  # noqa: BLE001
        return timezone.utc


class UnraidManager:
    """Keeps one poller per configured (enabled) Unraid server, re-reading the list from the database."""

    def __init__(self, settings: Settings, writer: EventWriter) -> None:
        self.settings = settings
        self.writer = writer
        self.pollers: dict[int, UnraidServerPoller] = {}
        self.signatures: dict[int, tuple] = {}

    async def bootstrap_from_env(self) -> None:
        s = self.settings
        if s.unraid_url and s.unraid_api_key:
            exists = await db.pool().fetchval("SELECT count(*) FROM unraid_servers WHERE url = $1", s.unraid_url)
            if not exists:
                await db.pool().execute(
                    "INSERT INTO unraid_servers (name, url, api_key, verify_ssl, docker_url) VALUES ($1, $2, $3, $4, $5)",
                    s.unraid_name or "Unraid", s.unraid_url, s.unraid_api_key, s.unraid_verify_ssl, s.unraid_docker_url or None)
                log.info("added Unraid server %s from environment", s.unraid_url)

    async def run(self) -> None:
        await self.bootstrap_from_env()
        while True:
            try:
                rows = await db.pool().fetch("SELECT * FROM unraid_servers WHERE enabled ORDER BY id")
                wanted = {r["id"]: dict(r) for r in rows}
                for sid in list(self.pollers):
                    if sid not in wanted or self.signatures[sid] != _sig(wanted[sid]):
                        await self.pollers.pop(sid).client.close()
                for sid, srv in wanted.items():
                    if sid not in self.pollers:
                        self.pollers[sid] = UnraidServerPoller(srv, self.settings, self.writer)
                        self.signatures[sid] = _sig(srv)
                await asyncio.gather(*(p.poll() for p in self.pollers.values()), return_exceptions=True)
                await db.set_snapshot("unraid_status", {str(sid): {"name": p.name, **p.status} for sid, p in self.pollers.items()})
            except Exception:  # noqa: BLE001
                log.exception("unraid manager loop failed")
            await asyncio.sleep(15)


def _sig(s: dict[str, Any]) -> tuple:
    return (s["url"], s["api_key"], s["verify_ssl"], s.get("docker_url"), s.get("collect_logs"), s["name"])


async def test_connection(url: str, api_key: str, verify_ssl: bool, docker_url: str | None) -> dict[str, Any]:
    client = UnraidClient({"url": url, "api_key": api_key, "verify_ssl": verify_ssl, "docker_url": docker_url})
    out: dict[str, Any] = {}
    try:
        d = await client.query("{ info { os { hostname release } versions { core { unraid api } } } }")
        out["graphql"] = {"ok": True, "info": d.get("info")}
    except (GraphQLError, httpx.HTTPError, OSError) as exc:
        out["graphql"] = {"ok": False, "error": str(exc)}
    if client.docker:
        try:
            r = await client.docker.get("/version")
            out["docker"] = {"ok": r.status_code == 200, "version": r.json().get("Version") if r.status_code == 200 else r.text[:200]}
        except (httpx.HTTPError, OSError, ValueError) as exc:
            out["docker"] = {"ok": False, "error": str(exc)}
    await client.close()
    return out
