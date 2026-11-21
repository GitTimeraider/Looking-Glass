"""CrowdSec running in Docker (e.g. next to SWAG): alerts, decisions and metrics from its Local API (LAPI).

Read only, three optional parts (Settings › SWAG & CrowdSec):

* machine login (``cscli machines add lookingglass --password …``): ``POST /v1/watchers/login`` gives a JWT, then
  ``GET /v1/alerts?include_capi=false`` - every alert with scenario, source (IP, range, AS, country), the events that
  triggered it (meta: target URI, host, user agent, status, AppSec rule …) and its decisions. Each alert becomes a
  ``crowdsec`` event (program ``crowdsec-lapi``, action ``alert``) and each of its decisions one more (``ban`` /
  ``captcha``), exactly like the OPNsense CrowdSec plugin's - so the CrowdSec detection, the Threats page and the
  reports treat both alike. The active decisions are those of the alerts with ``has_active_decision=true``.
* bouncer key (``cscli bouncers add lookingglass``): ``GET /v1/decisions`` - every active decision including the
  community blocklist (CAPI) and subscribed lists, counted per origin; used for the decisions when there is no
  machine login.
* metrics (``http://crowdsec:6060/metrics``, Prometheus): which log files CrowdSec reads and how many lines it
  parses, which scenarios overflow, what AppSec (the WAF) inspected and blocked, and which bouncers ask for decisions
  (is SWAG's bouncer alive?).
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from . import db
from .bichon import parse_prometheus
from .config import Settings
from .detections import close_alerts, offline_for, raise_alert
from .parsers.common import event, ip_or_none
from .parsers.syslog import parse_iso

log = logging.getLogger("lookingglass.crowdsec_lapi")

PROGRAM = "crowdsec-lapi"
HOST = "CrowdSec"
STATUS_KEY = "crowdsec_lapi:status"
DECISIONS_KEY = "crowdsec_lapi_decisions"
METRICS_KEY = "crowdsec_lapi_metrics"
COMMUNITY_ORIGINS = {"capi", "lists"}
# meta keys of an alert's events worth keeping (CrowdSec's http / appsec / ssh parsers)
META_KEYS = ("target_fqdn", "target_uri", "http_verb", "http_status", "http_path", "http_user_agent", "user_agent",
             "rule_name", "rule_ids", "matched_zones", "appsec_action", "service", "log_type", "target_user",
             "source_ip", "datasource_path", "datasource_type", "message")
UNREACHABLE_GRACE = 600  # seconds before a "CrowdSec unreachable" alert


class LapiError(Exception):
    def __init__(self, status: int, text: str, hint: str = "") -> None:
        super().__init__(f"HTTP {status}: {text[:200]}{hint}")
        self.status = status


def _ts(value: Any) -> datetime | None:
    """CrowdSec times: RFC 3339, sometimes with nanoseconds (more digits than Python reads)."""
    v = str(value or "").strip()
    if not v or v.startswith("0001-"):
        return None
    if "." in v:
        head, _, frac = v.partition(".")
        digits = "".join(c for c in frac if c.isdigit())
        zone = frac[len(digits):]
        v = f"{head}.{digits[:6]}{zone}"
    return parse_iso(v)


def is_appsec(scenario: str | None) -> bool:
    s = (scenario or "").lower()
    return "appsec" in s or "vpatch" in s or s.startswith("crowdsecurity/crs")


def alert_meta(alert: dict[str, Any]) -> dict[str, list[str]]:
    """The interesting meta values of an alert's events (and the alert's own meta), de-duplicated, at most 10 each."""
    out: dict[str, list[str]] = {}
    sources = [alert.get("meta") or []] + [(e or {}).get("meta") or [] for e in (alert.get("events") or [])[:100]]
    for metas in sources:
        for m in metas if isinstance(metas, list) else []:
            k, v = (m or {}).get("key"), (m or {}).get("value")
            if k in META_KEYS and v not in (None, ""):
                vals = out.setdefault(k, [])
                for one in (str(v).strip('[]"').split('","') if str(v).startswith("[") else [str(v)]):
                    if one and one not in vals and len(vals) < 10:
                        vals.append(one[:300])
    return out


def alert_events(alert: dict[str, Any], seen: set[str] | None = None) -> list[dict[str, Any]]:
    """One LAPI alert -> its ``crowdsec`` events: the alert and every decision in it."""
    src = alert.get("source") or {}
    scenario = alert.get("scenario") or ""
    ts = _ts(alert.get("start_at")) or _ts(alert.get("created_at")) or datetime.now(timezone.utc)
    ip = ip_or_none(src.get("ip")) or ip_or_none(str(src.get("value") or "").split("/")[0])
    meta = alert_meta(alert)
    decisions = [d for d in alert.get("decisions") or [] if isinstance(d, dict)]
    appsec = is_appsec(scenario)
    data: dict[str, Any] = {
        "id": alert.get("id"), "scenario": scenario, "scenario_version": alert.get("scenario_version"),
        "events_count": alert.get("events_count"), "message": alert.get("message"), "machine_id": alert.get("machine_id"),
        "as": src.get("as_name"), "as_number": src.get("as_number"), "range": src.get("range"), "country": src.get("cn"),
        "scope": src.get("scope"), "value": src.get("value"), "simulated": alert.get("simulated") or None,
        "remediation": alert.get("remediation"), "capacity": alert.get("capacity"), "leakspeed": alert.get("leakspeed"),
        "stop_at": alert.get("stop_at"), "appsec": appsec or None, "meta": meta or None,
        "decisions": [{k: d.get(k) for k in ("type", "duration", "origin", "scope", "value") if d.get(k)} for d in decisions[:10]] or None,
        "labels": alert.get("labels") or None,
    }
    uid = alert.get("uuid") or alert.get("id")
    domain = (meta.get("target_fqdn") or [None])[0]
    uri = (meta.get("target_uri") or meta.get("http_path") or [None])[0]
    what = f" on {domain}" if domain else ""
    what += f" ({uri})" if uri else ""
    out = []
    if not seen or f"a:{uid}" not in seen:
        out.append(event(ts, "crowdsec", host=HOST, program=PROGRAM, severity=4, action="alert", src_ip=ip,
                         src_country=src.get("cn"), domain=domain,
                         message=f"{scenario} from {src.get('value') or ip} ({alert.get('events_count', '?')} events){what}"
                                 + (f" - {', '.join(sorted({str(d.get('type')) for d in decisions}))}" if decisions else ""),
                         data={k: v for k, v in data.items() if v not in (None, "", [], {})},
                         uid=f"csl-alert:{uid}"))
    for d in decisions:
        if seen and f"d:{d.get('id')}" in seen:
            continue
        out.append(decision_event(d, ts, src, alert.get("id"), scenario))
    return out


def decision_event(d: dict[str, Any], ts: datetime | None = None, src: dict[str, Any] | None = None,
                   alert_id: Any = None, scenario: str | None = None) -> dict[str, Any]:
    src = src or {}
    value = str(d.get("value") or "")
    scope = d.get("scope") or "Ip"
    ip = ip_or_none(value.split("/")[0]) if scope.lower() in ("ip", "range") else None
    dtype = str(d.get("type") or "ban").lower()
    return event(ts or datetime.now(timezone.utc), "crowdsec", host=HOST, program=PROGRAM, severity=4, action=dtype,
                 src_ip=ip, src_country=src.get("cn"),
                 message=f"decision {dtype} on {scope} {value} ({d.get('scenario') or scenario or ''}), origin "
                         f"{d.get('origin', '')}, for {d.get('duration', '?')}",
                 data={k: v for k, v in {"id": d.get("id"), "scope": scope, "value": value, "origin": d.get("origin"),
                                         "scenario": d.get("scenario") or scenario, "duration": d.get("duration"),
                                         "until": d.get("until"), "simulated": d.get("simulated") or None,
                                         "alert_id": alert_id, "as": src.get("as_name"), "country": src.get("cn"),
                                         "appsec": is_appsec(d.get("scenario") or scenario) or None}.items()
                       if v not in (None, "")},
                 uid=f"csl-dec:{d.get('id')}")


def active_from_alerts(alerts: list[dict[str, Any]], now: datetime | None = None) -> list[dict[str, Any]]:
    """The decisions in force, from alerts read with has_active_decision=true (with the source's country / AS)."""
    now = now or datetime.now(timezone.utc)
    out = []
    for a in alerts:
        src = a.get("source") or {}
        for d in a.get("decisions") or []:
            until = _ts(d.get("until"))
            if until and until < now:
                continue
            out.append({"id": d.get("id"), "type": d.get("type"), "scope": d.get("scope"), "value": d.get("value"),
                        "origin": d.get("origin"), "scenario": d.get("scenario") or a.get("scenario"),
                        "duration": d.get("duration"), "until": d.get("until"), "country": src.get("cn"),
                        "as": src.get("as_name"), "alert_id": a.get("id"), "created": a.get("created_at")})
    return out


def metrics_summary(text: str) -> dict[str, Any]:
    """CrowdSec's Prometheus metrics -> what Looking Glass shows (acquisition, parsers, scenarios, AppSec, bouncers)."""
    m = parse_prometheus(text)
    acq: dict[str, dict[str, Any]] = {}
    for name, rows in m.items():
        if name.endswith("source_hits_total") and name.startswith("cs_"):
            for labels, v in rows:
                key = labels.get("source") or labels.get("container_name") or labels.get("name") or name
                a = acq.setdefault(key, {"source": key, "type": name[3:-len("source_hits_total")].rstrip("_") or labels.get("type"),
                                         "read": 0, "parsed": 0, "unparsed": 0})
                a["read"] += v
    for name, field in (("cs_parser_hits_ok_total", "parsed"), ("cs_parser_hits_ko_total", "unparsed")):
        for labels, v in m.get(name, []):
            key = labels.get("source")
            if key in acq:
                acq[key][field] += v

    def by(metric: str, label: str) -> dict[str, float]:
        out: dict[str, float] = {}
        for labels, v in m.get(metric, []):
            k = labels.get(label) or "?"
            out[k] = out.get(k, 0) + v
        return out

    version = next((labels.get("version") for labels, _ in m.get("cs_info", [])), None)
    return {
        "version": version,
        "acquisition": sorted(acq.values(), key=lambda a: -a["read"]),
        "overflows": dict(sorted(by("cs_bucket_overflowed_total", "name").items(), key=lambda kv: -kv[1])[:30]),
        "appsec": {"requests": sum(v for _, v in m.get("cs_appsec_reqs_total", [])),
                   "blocked": sum(v for _, v in m.get("cs_appsec_block_total", [])),
                   "rules": dict(sorted(by("cs_appsec_rule_hits", "rule_name").items(), key=lambda kv: -kv[1])[:30])},
        "bouncers": by("cs_lapi_bouncer_requests_total", "bouncer"),
        "machines": by("cs_lapi_machine_requests_total", "machine"),
        "decisions": by("cs_active_decisions", "origin"),
    }


class LapiClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.http = httpx.AsyncClient(base_url=settings.crowdsec_lapi_url.rstrip("/"), verify=settings.crowdsec_lapi_verify_ssl,
                                      timeout=httpx.Timeout(30.0, connect=10.0),
                                      headers={"User-Agent": "looking-glass"})
        self.token: str | None = None
        self.token_until = 0.0

    async def close(self) -> None:
        await self.http.aclose()

    @property
    def machine(self) -> str:
        return (self.settings.crowdsec_lapi_machine or "").strip()

    @property
    def password(self) -> str:
        return (self.settings.crowdsec_lapi_password or "").strip()

    @property
    def bouncer_key(self) -> str:
        return (self.settings.crowdsec_lapi_bouncer_key or "").strip()

    @property
    def has_machine(self) -> bool:
        return bool(self.machine and self.password)

    async def login(self) -> None:
        # pasted values often carry a space or line break at the end: never part of a machine name / cscli password
        machine, password = self.machine, self.password
        r = await self.http.post("/v1/watchers/login", json={"machine_id": machine, "password": password, "scenarios": []})
        if r.status_code != 200:
            hint = ""
            if r.status_code in (401, 403):
                hint = (f" - sent machine '{machine}' with a {len(password)}-character password. CrowdSec knows the "
                        "machine but the password does not match: set it again with single quotes around it "
                        "(docker exec crowdsec cscli machines add " + machine + " --password '<password>' --force "
                        "-f /dev/null), then enter the same password here and Save"
                        if "incorrect" in (r.text or "").lower() else
                        " - the machine is not validated: docker exec crowdsec cscli machines validate " + machine)
            raise LapiError(r.status_code, r.text or "login failed", hint)
        body = r.json()
        self.token = body.get("token")
        exp = _ts(body.get("expire"))
        self.token_until = (exp.timestamp() - 120) if exp else time.time() + 1800

    async def machine_get(self, path: str, params: dict[str, Any]) -> Any:
        for attempt in range(2):
            if not self.token or time.time() > self.token_until:
                await self.login()
            r = await self.http.get(path, params=params, headers={"Authorization": f"Bearer {self.token}"})
            if r.status_code == 401 and attempt == 0:
                self.token = None
                continue
            if r.status_code != 200:
                raise LapiError(r.status_code, r.text)
            return r.json()
        return None

    async def alerts(self, since: str, limit: int = 500, active: bool = False) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"include_capi": "false", "limit": limit}
        if active:
            params["has_active_decision"] = "true"
        else:
            params["since"] = since
        return await self.machine_get("/v1/alerts", params) or []

    async def decisions(self) -> list[dict[str, Any]]:
        r = await self.http.get("/v1/decisions", headers={"X-Api-Key": self.bouncer_key})
        if r.status_code in (401, 403):
            raise LapiError(r.status_code, "bouncer key refused (cscli bouncers list)")
        if r.status_code != 200:
            raise LapiError(r.status_code, r.text)
        return r.json() or []

    async def metrics(self) -> str:
        async with httpx.AsyncClient(verify=self.settings.crowdsec_lapi_verify_ssl, timeout=20.0) as c:
            r = await c.get(self.settings.crowdsec_lapi_metrics_url)
            r.raise_for_status()
            return r.text


class LapiPoller:
    """Polls the CrowdSec Local API while Settings › SWAG & CrowdSec has its URL and a login."""

    def __init__(self, settings: Settings, writer: Any) -> None:
        self.settings = settings
        self.writer = writer
        self.client = LapiClient(settings)
        self.seen: set[str] = set()
        self.first = True
        self.status: dict[str, Any] = {"ok": None, "error": None, "last": None, "url": settings.crowdsec_lapi_url}
        self.down_since: float | None = None

    async def stop(self) -> None:
        await self.client.close()

    async def run(self) -> None:
        log.info("CrowdSec Local API poller started for %s", self.settings.crowdsec_lapi_url)
        while True:
            try:
                await self.poll()
                self.status.update(ok=True, error=None, last=time.time())
                await self.reachable()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - report, never crash-loop
                if not isinstance(exc, (LapiError, httpx.HTTPError, OSError)):
                    log.exception("CrowdSec poll failed")
                else:
                    log.warning("CrowdSec Local API: %s", exc)
                self.status.update(ok=False, error=f"{type(exc).__name__}: {exc}"[:800], last=time.time())
                if isinstance(exc, (httpx.HTTPError, OSError)):
                    await self.unreachable(str(exc) or type(exc).__name__)
            await db.set_snapshot(STATUS_KEY, self.status)
            await asyncio.sleep(max(15, self.settings.crowdsec_lapi_poll_interval))

    async def poll(self) -> None:
        parts: dict[str, Any] = {}
        active: list[dict[str, Any]] | None = None
        if self.client.has_machine:
            # the first poll reaches back a week; afterwards a few hours (alerts are de-duplicated by their id)
            alerts = await self.client.alerts("168h" if self.first else "6h", limit=2000 if self.first else 500)
            n = 0
            for a in alerts:
                for ev in alert_events(a, self.seen):
                    self.writer.put(ev)
                    n += 1
                self.seen.add(f"a:{a.get('uuid') or a.get('id')}")
                self.seen.update(f"d:{d.get('id')}" for d in a.get("decisions") or [])
            if len(self.seen) > 50_000:
                self.seen = set(list(self.seen)[-20_000:])
            self.first = False
            act = await self.client.alerts("", limit=5000, active=True)
            active = active_from_alerts(act)
            parts["machine"] = {"ok": True, "alerts": len(alerts), "new_events": n}
        if self.settings.crowdsec_lapi_bouncer_key:
            try:
                decs = await self.client.decisions()
                origins: dict[str, int] = {}
                for d in decs:
                    o = str(d.get("origin") or "?")
                    origins[o] = origins.get(o, 0) + 1
                parts["bouncer"] = {"ok": True, "decisions": len(decs), "origins": origins}
                if active is None:
                    active = [{k: d.get(k) for k in ("id", "type", "scope", "value", "origin", "scenario", "duration", "until")}
                              for d in decs if str(d.get("origin") or "").lower() not in COMMUNITY_ORIGINS]
                    for d in active:
                        if f"d:{d.get('id')}" not in self.seen:
                            self.writer.put(decision_event(d))
                            self.seen.add(f"d:{d.get('id')}")
            except LapiError as exc:
                parts["bouncer"] = {"ok": False, "error": str(exc)}
        if active is not None:
            await db.set_snapshot(DECISIONS_KEY, active[:5000])
        if self.settings.crowdsec_lapi_metrics_url:
            try:
                summary = metrics_summary(await self.client.metrics())
                await db.set_snapshot(METRICS_KEY, summary)
                parts["metrics"] = {"ok": True, "version": summary.get("version")}
            except (httpx.HTTPError, OSError) as exc:
                parts["metrics"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300]}
        self.status["parts"] = parts
        self.status["active_decisions"] = len(active) if active is not None else None

    async def unreachable(self, error: str) -> None:
        now = time.time()
        self.down_since = self.down_since or now
        if now - self.down_since >= UNREACHABLE_GRACE:
            await raise_alert("crowdsec_unreachable", "medium", "CrowdSec Local API unreachable", "crowdsec_lapi:down",
                              description=f"{self.settings.crowdsec_lapi_url} has not answered for "
                                          f"{offline_for(now - self.down_since)}: {error}. While CrowdSec is down "
                                          "nothing is detected or blocked by it (the bouncers keep their last list).",
                              mode="max", events={"source": "crowdsec"})

    async def reachable(self) -> None:
        if self.down_since is not None:
            self.down_since = None
            await close_alerts("crowdsec_unreachable", ["crowdsec_lapi:down"], "the CrowdSec Local API answers again")


async def test_connection(settings: Settings) -> list[dict[str, Any]]:
    """Settings › SWAG & CrowdSec › Test connection: the CrowdSec parts."""
    if not settings.crowdsec_lapi_url:
        return []
    out: list[dict[str, Any]] = []
    client = LapiClient(settings)
    try:
        if client.has_machine:
            try:
                alerts = await client.alerts("24h", limit=200)
                out.append({"ok": True, "text": f"CrowdSec machine login works: {len(alerts)} alert(s) in the last 24 hours."})
            except (LapiError, httpx.HTTPError, OSError) as exc:
                out.append({"ok": False, "text": f"CrowdSec machine login: {type(exc).__name__}: {exc}"})
        elif settings.crowdsec_lapi_machine or settings.crowdsec_lapi_password:
            out.append({"ok": False, "text": "CrowdSec: enter both the machine name and its password (alerts)."})
        if settings.crowdsec_lapi_bouncer_key:
            try:
                decs = await client.decisions()
                community = sum(1 for d in decs if str(d.get("origin") or "").lower() in COMMUNITY_ORIGINS)
                out.append({"ok": True, "text": f"CrowdSec bouncer key works: {len(decs)} active decision(s), "
                                                f"{community} of them from the community blocklist / lists."})
            except (LapiError, httpx.HTTPError, OSError) as exc:
                out.append({"ok": False, "text": f"CrowdSec bouncer key: {type(exc).__name__}: {exc}"})
        if not client.has_machine and not settings.crowdsec_lapi_bouncer_key:
            out.append({"ok": False, "text": "CrowdSec: a machine login (alerts) and/or a bouncer key (decisions) is needed."})
        if settings.crowdsec_lapi_metrics_url:
            try:
                s = metrics_summary(await client.metrics())
                files = ", ".join(a["source"] for a in s["acquisition"][:6]) or "none"
                out.append({"ok": True, "text": f"CrowdSec metrics{(' (' + s['version'] + ')') if s.get('version') else ''}: "
                                                f"reads {files}; bouncers: {', '.join(s['bouncers']) or 'none seen yet'}."})
            except (httpx.HTTPError, OSError) as exc:
                out.append({"ok": False, "text": f"CrowdSec metrics: {type(exc).__name__}: {exc} (prometheus listen_addr "
                                                 "must be 0.0.0.0 in CrowdSec's config.yaml)"})
    finally:
        await client.close()
    return out
