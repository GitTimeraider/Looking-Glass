"""WAN quality (Infrastructure › OPNsense › WAN quality): how every OPNsense gateway does over days, weeks and months.

OPNsense's gateway monitor (dpinger) measures latency, jitter (stddev) and loss; the poller stores them as metrics
every poll (gateway_delay_ms, gateway_stddev_ms, gateway_loss_pct, gateway_up). Here they are summed up per gateway
and local day in ``wan_daily`` (kept for two years, longer than the metrics), and two alerts watch for slow
degradation that "down / degraded right now" misses:
* wan_latency - the median latency of the last 24 hours is far above the median of the 7 days before,
* wan_loss    - the average packet loss over the last 24 hours is above the limit.
Both close by themselves when the line is fine again.
"""
from __future__ import annotations

import asyncio
import logging
import statistics
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

from . import db
from .config import Settings

log = logging.getLogger(__name__)

NAMES = ("gateway_delay_ms", "gateway_stddev_ms", "gateway_loss_pct", "gateway_up")
KEEP_DAYS = 730
MIN_SAMPLES = 30          # samples in the last 24 hours before the alerts look at a gateway
MIN_BASELINE_DAYS = 3     # days of history before a latency alert is possible


def tz_name(s: Settings) -> str:
    try:
        ZoneInfo(s.timezone or "UTC")
        return s.timezone or "UTC"
    except Exception:  # noqa: BLE001
        return "UTC"


ROLLUP_SQL = """
INSERT INTO wan_daily (gateway, day, samples, delay_avg, delay_p50, delay_p95, delay_max, stddev_avg, loss_avg,
                       loss_max, down_samples, up_samples, updated_at)
SELECT labels, (ts AT TIME ZONE $2)::date AS day,
       greatest(count(*) FILTER (WHERE name = 'gateway_delay_ms'), count(*) FILTER (WHERE name = 'gateway_loss_pct')),
       avg(value) FILTER (WHERE name = 'gateway_delay_ms'),
       percentile_cont(0.5) WITHIN GROUP (ORDER BY value) FILTER (WHERE name = 'gateway_delay_ms'),
       percentile_cont(0.95) WITHIN GROUP (ORDER BY value) FILTER (WHERE name = 'gateway_delay_ms'),
       max(value) FILTER (WHERE name = 'gateway_delay_ms'),
       avg(value) FILTER (WHERE name = 'gateway_stddev_ms'),
       avg(value) FILTER (WHERE name = 'gateway_loss_pct'),
       max(value) FILTER (WHERE name = 'gateway_loss_pct'),
       count(*) FILTER (WHERE name = 'gateway_up' AND value < 0.5),
       count(*) FILTER (WHERE name = 'gateway_up' AND value >= 0.5),
       now()
FROM metrics
WHERE name = ANY($3::text[]) AND labels <> '' AND ts >= $1
GROUP BY 1, 2
ON CONFLICT (gateway, day) DO UPDATE SET samples = EXCLUDED.samples, delay_avg = EXCLUDED.delay_avg,
    delay_p50 = EXCLUDED.delay_p50, delay_p95 = EXCLUDED.delay_p95, delay_max = EXCLUDED.delay_max,
    stddev_avg = EXCLUDED.stddev_avg, loss_avg = EXCLUDED.loss_avg, loss_max = EXCLUDED.loss_max,
    down_samples = EXCLUDED.down_samples, up_samples = EXCLUDED.up_samples, updated_at = now()
"""


async def rollup(s: Settings, full: bool = False) -> int:
    """Sum up the metrics per gateway and local day: today and yesterday, or (``full``) everything still stored."""
    tz = tz_name(s)
    pool = db.pool()
    if full:
        since = await pool.fetchval("SELECT min(ts) FROM metrics WHERE name = ANY($1::text[])", list(NAMES))
        if since is None:
            return 0
    else:
        # from the start of yesterday (local): yesterday's last samples may have arrived after midnight
        since = await pool.fetchval("SELECT ((now() AT TIME ZONE $1)::date - 1)::timestamp AT TIME ZONE $1", tz)
    # a day that starts before ``since`` would be summed from only part of its samples: start at a day boundary
    since = await pool.fetchval("SELECT ($1::timestamptz AT TIME ZONE $2)::date::timestamp AT TIME ZONE $2", since, tz)
    res = await pool.execute(ROLLUP_SQL, since, tz, list(NAMES))
    await pool.execute("DELETE FROM wan_daily WHERE day < current_date - $1::int", KEEP_DAYS)
    return int(res.split()[-1]) if res and res.split()[-1].isdigit() else 0


async def loop(s: Settings) -> None:
    await asyncio.sleep(90)
    if not await db.kv_get("wan_backfill"):
        try:
            n = await rollup(s, full=True)
            await db.kv_set("wan_backfill", datetime.now(timezone.utc).isoformat())
            log.info("WAN quality: %d gateway-days summed up from the stored metrics", n)
        except Exception:  # noqa: BLE001
            log.exception("WAN quality backfill failed")
    while True:
        try:
            await rollup(s)
        except Exception:  # noqa: BLE001
            log.exception("WAN quality rollup failed")
        await asyncio.sleep(900)


# ------------------------------------------------------- gateway choices ---
# WAN quality › per gateway: the order on the page, "hidden" (collected and alerted, not shown) and "ignored" (not
# collected any more and never alerted: unused gateways). Stored in kv, cached a minute (the poller reads it).
PREFS_KEY = "wan_gateways"
_prefs_cache: dict[str, Any] = {"at": 0.0, "value": None}


def clean_prefs(payload: dict[str, Any]) -> dict[str, list[str]]:
    def names(key: str) -> list[str]:
        v = payload.get(key) or []
        if not isinstance(v, list) or len(v) > 200:
            raise ValueError(f"{key}: a list of gateway names")
        return list(dict.fromkeys(str(x).strip()[:100] for x in v if str(x).strip()))
    order, hidden, ignored = names("order"), names("hidden"), names("ignored")
    return {"order": order, "hidden": [g for g in hidden if g not in ignored], "ignored": ignored}


async def prefs(fresh: bool = False) -> dict[str, list[str]]:
    import time
    if fresh or _prefs_cache["value"] is None or time.monotonic() - _prefs_cache["at"] > 60:
        v = await db.kv_get(PREFS_KEY) or {}
        try:
            _prefs_cache["value"] = clean_prefs(v if isinstance(v, dict) else {})
        except ValueError:
            _prefs_cache["value"] = {"order": [], "hidden": [], "ignored": []}
        _prefs_cache["at"] = time.monotonic()
    return _prefs_cache["value"]


async def save_prefs(payload: dict[str, Any]) -> dict[str, list[str]]:
    """Store the choices; alerts of gateways that are now ignored are closed."""
    from .detections import close_alerts

    p = clean_prefs(payload)
    await db.kv_set(PREFS_KEY, p)
    _prefs_cache.update(at=0.0, value=None)
    for rule, prefix in (("gateway_down", "gw:"), ("gateway_degraded", "gwdeg:"), ("wan_latency", "wanlat:"),
                         ("wan_loss", "wanloss:")):
        if p["ignored"]:
            await close_alerts(rule, [prefix + g for g in p["ignored"]], "the gateway is ignored (WAN quality)")
    return p


# ------------------------------------------------------------------ checks ---
async def last_day(gateway: str | None = None) -> dict[str, dict[str, Any]]:
    """Per gateway: median / p95 latency, average loss and samples over the last 24 hours (from the metrics)."""
    rows = await db.pool().fetch(
        "SELECT labels gw, count(*) FILTER (WHERE name = 'gateway_delay_ms') n_delay, "
        "count(*) FILTER (WHERE name = 'gateway_loss_pct') n_loss, "
        "percentile_cont(0.5) WITHIN GROUP (ORDER BY value) FILTER (WHERE name = 'gateway_delay_ms') p50, "
        "percentile_cont(0.95) WITHIN GROUP (ORDER BY value) FILTER (WHERE name = 'gateway_delay_ms') p95, "
        "avg(value) FILTER (WHERE name = 'gateway_stddev_ms') jitter, "
        "avg(value) FILTER (WHERE name = 'gateway_loss_pct') loss, "
        "count(*) FILTER (WHERE name = 'gateway_up' AND value < 0.5) down, "
        "count(*) FILTER (WHERE name = 'gateway_up') up_n "
        "FROM metrics WHERE name = ANY($1::text[]) AND ts > now() - interval '24 hours' AND labels <> '' "
        "AND ($2::text IS NULL OR labels = $2) GROUP BY 1", list(NAMES), gateway)
    return {r["gw"]: dict(r) for r in rows}


async def baseline(gateway: str, tz: str) -> tuple[float | None, int]:
    """Median of the daily median latency over the 7 complete local days before today, and how many days that is."""
    rows = await db.pool().fetch(
        "SELECT delay_p50 FROM wan_daily WHERE gateway = $1 AND delay_p50 IS NOT NULL AND samples >= 30 "
        "AND day < (now() AT TIME ZONE $2)::date - 1 AND day >= (now() AT TIME ZONE $2)::date - 8 ORDER BY day",
        gateway, tz)
    vals = [r["delay_p50"] for r in rows]
    return (statistics.median(vals) if vals else None), len(vals)


def judge(s: Settings, cur: dict[str, Any], base: float | None, base_days: int) -> dict[str, Any]:
    """What is wrong with one gateway: {"latency": text | None, "loss": text | None} (pure, for tests)."""
    out: dict[str, Any] = {"latency": None, "loss": None, "loss_severity": "low"}
    if (cur.get("n_delay") or 0) >= MIN_SAMPLES and cur.get("p50") is not None and base and base_days >= MIN_BASELINE_DAYS:
        p50 = cur["p50"]
        if p50 >= base * s.wan_latency_factor / 100 and p50 - base >= s.wan_latency_min_ms:
            out["latency"] = (f"median latency over the last 24 hours {p50:.1f} ms, normally {base:.1f} ms "
                              f"(median of the {base_days} days before) - {p50 / base:.1f}× slower")
    loss = cur.get("loss")
    if s.wan_loss_pct > 0 and (cur.get("n_loss") or 0) >= MIN_SAMPLES and loss is not None and loss >= s.wan_loss_pct:
        out["loss"] = f"average packet loss over the last 24 hours {loss:.1f} % (limit {s.wan_loss_pct} %)"
        out["loss_severity"] = "medium" if loss >= max(10, s.wan_loss_pct * 3) else "low"
    return out


async def check(s: Settings) -> None:
    """Raise / close the WAN quality alerts (called by the detection engine every 15 minutes)."""
    from .detections import Rating, close_alerts, raise_alert

    if not s.wan_alerts:
        return
    tz = tz_name(s)
    fine_lat, fine_loss = [], []
    ignored = set((await prefs())["ignored"])
    for gw, cur in (await last_day()).items():
        if gw in ignored:
            continue
        base, n = await baseline(gw, tz)
        v = judge(s, cur, base, n)
        if v["latency"]:
            await raise_alert("wan_latency", Rating("low", "the internet line is much slower than it normally is - a "
                                                           "provider problem, a saturated line or a failing modem"),
                              f"WAN {gw}: latency far above normal", f"wanlat:{gw}", mode="max",
                              description=f"Gateway {gw}: {v['latency']}. Details: Infrastructure › OPNsense › WAN quality.",
                              data={"gateway": gw, "p50": cur["p50"], "baseline": base})
        else:
            fine_lat.append(f"wanlat:{gw}")
        if v["loss"]:
            await raise_alert("wan_loss", Rating(v["loss_severity"], "packet loss makes everything slow and calls "
                                                                     "break up; often the line or the modem"),
                              f"WAN {gw}: packet loss", f"wanloss:{gw}", mode="max",
                              description=f"Gateway {gw}: {v['loss']}. Details: Infrastructure › OPNsense › WAN quality.",
                              data={"gateway": gw, "loss": cur["loss"]})
        else:
            fine_loss.append(f"wanloss:{gw}")
    if fine_lat:
        await close_alerts("wan_latency", fine_lat, "the latency is back to normal")
    if fine_loss:
        await close_alerts("wan_loss", fine_loss, "the packet loss is gone")


# --------------------------------------------------------------------- page ---
def monitored(gw: dict[str, Any]) -> bool:
    """dpinger measures this gateway: it reports a latency or loss (an unmonitored one shows "~")."""
    from .opnsense import _num, gateway_is_down
    return _num(gw.get("delay")) is not None or _num(gw.get("loss")) is not None or gateway_is_down(gw)


async def overview(s: Settings, days: int = 90) -> dict[str, Any]:
    tz = tz_name(s)
    pool = db.pool()
    snap = await db.get_snapshot("gateways") or []
    now_rows = {str(g.get("name")): g for g in snap if isinstance(g, dict)}
    rows = db.records(await pool.fetch(
        "SELECT * FROM wan_daily WHERE day >= (now() AT TIME ZONE $1)::date - $2::int ORDER BY gateway, day", tz, days))
    per: dict[str, list] = {}
    for r in rows:
        r.pop("updated_at", None)
        total = (r["down_samples"] or 0) + (r["up_samples"] or 0)
        r["availability"] = round(100 * r["up_samples"] / total, 3) if total else None
        per.setdefault(r["gateway"], []).append(r)
    cur = await last_day()
    pr = await prefs(fresh=True)
    rank = {g: i for i, g in enumerate(pr["order"])}
    out = []
    for name in sorted(set(per) | set(now_rows) | set(cur), key=lambda g: (rank.get(g, len(rank)), g.lower())):
        base, n = await baseline(name, tz)
        days_ = per.get(name, [])

        def period(k: int) -> dict[str, Any]:
            sel = days_[-k:]
            if not sel:
                return {}
            d = [x["delay_p50"] for x in sel if x["delay_p50"] is not None]
            loss = [x["loss_avg"] for x in sel if x["loss_avg"] is not None]
            up = sum(x["up_samples"] or 0 for x in sel)
            tot = up + sum(x["down_samples"] or 0 for x in sel)
            return {"days": len(sel), "delay_p50": statistics.median(d) if d else None,
                    "loss_avg": sum(loss) / len(loss) if loss else None,
                    "availability": round(100 * up / tot, 3) if tot else None}
        g = now_rows.get(name) or {}
        c = cur.get(name) or {}
        out.append({"name": name, "now": {k: g.get(k) for k in ("status", "status_translated", "delay", "stddev", "loss",
                                                                "address", "monitor", "descr") if k in g},
                    "last24": {k: c.get(k) for k in ("p50", "p95", "jitter", "loss", "down", "up_n")} if c else {},
                    "baseline": base, "baseline_days": n, "p7": period(7), "p30": period(30), "p90": period(90),
                    "days": days_, "hidden": name in pr["hidden"], "ignored": name in pr["ignored"],
                    # OPNsense measures nothing for it: monitoring off, or the monitor IP does not answer pings
                    "unmonitored": bool(g) and not monitored(g) and not c.get("n_delay")})
    return {"gateways": out, "timezone": tz, "prefs": pr,
            "limits": {"factor": s.wan_latency_factor, "min_ms": s.wan_latency_min_ms, "loss": s.wan_loss_pct,
                       "alerts": s.wan_alerts}}
