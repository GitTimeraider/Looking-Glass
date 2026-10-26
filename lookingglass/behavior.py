"""Behaviour & anomaly detection: what is normal for each device, and what is new or unusual.

* Profiles (device_profile): per device (MAC, or IP when unknown) the countries, ports, domains, TLS programs
  (JA3/JA4) and hours it uses. A value appearing for the first time on a *predictable* device (one that rarely picked
  up anything new while learning) is alerted - unless similar devices (same vendor) do it too.
* Hourly features (device_hourly): connections, destinations, ports, countries, DNS lookups, failed lookups, blocks
  and upload per device and hour. Used for volume spikes and a machine learning model (Isolation Forest on feature
  pairs, see mlforest.py) that finds hours unlike the device's own history.
* Hour-of-week baselines (hourly_stats): network-wide totals compared to the same hour in previous weeks.
* Risk score per address: all alerts add points that fade over time.
* Feedback: alerts closed as "false positive" become suggestions (or automatic severity rules).

Everything is configurable under Settings › Behaviour & ML, including devices never to analyse.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import random
import statistics
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from . import alert_filters, db
from .config import Settings, local_time
from .detections import (ALLOWED_ROW, LATERAL_PORTS, SUSPICIOUS_OUT_PORTS, SEVERITIES, Rating, corroborate, evidence,
                         raise_alert, registered_domain)
from .mlforest import SubspaceForest
from .parsers.common import INTERNAL_NETS, parse_networks

log = logging.getLogger(__name__)

KINDS = {"country": "country", "port": "port / protocol", "domain": "domain", "tls": "TLS program (JA3/JA4)"}
FEATURES = ["connections", "destinations", "ports", "countries", "dns", "failed_lookups", "blocked", "upload_mb"]
FEATURE_LABEL = {"connections": "connections", "destinations": "destinations", "ports": "ports", "countries": "countries",
                 "dns": "DNS lookups", "failed_lookups": "failed lookups", "blocked": "blocked connections",
                 "upload_mb": "MB uploaded"}
# an increase only counts when it is also meaningful in absolute terms (5 failed lookups instead of 0 is not news)
MIN_INCREASE = {"connections": 200, "destinations": 30, "ports": 10, "countries": 5, "dns": 200, "failed_lookups": 50,
                "blocked": 50, "upload_mb": 100}
ML_LEVELS = {"low": (0.9995, 4.0), "medium": (0.998, 3.5), "high": (0.995, 3.0)}  # training percentile, deviation
RISK_POINTS = {"info": 1, "low": 3, "medium": 8, "high": 20, "critical": 40}


class Matcher:
    """A comma separated list of IPs, CIDRs and MAC addresses (exclusion settings)."""

    def __init__(self, csv: str) -> None:
        parts = [p.strip().lower() for p in (csv or "").replace(";", ",").replace("\n", ",").split(",") if p.strip()]
        self.macs = {p for p in parts if p.count(":") == 5 and all(len(x) == 2 for x in p.split(":"))}
        self.nets = parse_networks(",".join(p for p in parts if p not in self.macs))

    def __bool__(self) -> bool:
        return bool(self.macs or self.nets)

    def match(self, *values: Any) -> bool:
        for v in values:
            if not v:
                continue
            s = str(v).lower()
            if s in self.macs:
                return True
            try:
                ip = ipaddress.ip_address(s)
            except ValueError:
                continue
            if any(ip.version == n.version and ip in n for n in self.nets):
                return True
        return False


def internal_cidrs(s: Settings) -> list[str]:
    return [str(n) for n in INTERNAL_NETS] + [str(n) for n in parse_networks(s.internal_networks)]


def robust(values: list[float], floor: float = 1.0, rel: float = 0.1) -> tuple[float, float]:
    """Median and a robust spread (1.4826 × MAD, at least ``rel`` × the median and ``floor``)."""
    med = statistics.median(values)
    mad = statistics.median(abs(v - med) for v in values) * 1.4826
    return med, max(mad, rel * abs(med), floor)


class Behavior:
    def __init__(self, settings: Settings, internal) -> None:
        self.s = settings
        self.internal = internal  # DetectionEngine.internal
        self._ran: dict[str, float] = {}

    # ------------------------------------------------------------ helpers ---
    def excluded(self) -> Matcher:
        return Matcher(self.s.behavior_exclude)

    async def ip_to_mac(self) -> dict[str, dict[str, Any]]:
        # every address of a device (OPNsense: a port and its VLANs); a device with a MAC wins over an ip: entry
        rows = await db.pool().fetch(
            "SELECT host(x) ip, mac, vendor, hostname FROM devices, unnest(coalesce(ips, '{}'::inet[]) || ip) x "
            "WHERE x IS NOT NULL ORDER BY mac NOT LIKE 'ip:%', last_seen")
        return {r["ip"]: dict(r) for r in rows}

    @staticmethod
    def key_of(ip: str, macs: dict[str, dict[str, Any]]) -> str:
        return (macs.get(ip) or {}).get("mac") or ip

    # ----------------------------------------------------------- profiles ---
    async def update_profiles(self) -> None:
        """Fold new events into the profiles; alert on firsts of predictable devices."""
        if not self.s.behavior_enabled:
            return
        pool = db.pool()
        current = await pool.fetchval("SELECT COALESCE(max(id), 0) FROM events")
        last = await db.kv_get("wm:profile")
        if last is None:
            last = await pool.fetchval("SELECT COALESCE(min(id), 1) - 1 FROM events WHERE ts > now() - make_interval(days => $1)",
                                       self.s.behavior_learn_days) or 0
        last = int(last)
        upto = min(current, last + 500_000)  # catch up in steps after a long pause
        if upto <= last:
            return
        nets = internal_cidrs(self.s)
        macs = await self.ip_to_mac()
        excl = self.excluded()
        agg: dict[tuple[str, str, str], list[Any]] = {}
        ips: dict[str, str] = {}

        def add(ip: str, kind: str, value: Any, n: int, first: datetime, lastts: datetime) -> None:
            if value in (None, "") or not self.internal(ip) or excl.match(ip, (macs.get(ip) or {}).get("mac")):
                return
            key = self.key_of(ip, macs)
            ips[key] = ip
            cur = agg.get((key, kind, str(value)))
            if cur:
                cur[0] += n
                cur[1] = min(cur[1], first)
                cur[2] = max(cur[2], lastts)
            else:
                agg[(key, kind, str(value))] = [n, first, lastts]

        conns = await pool.fetch(
            "SELECT host(src_ip) ip, dst_country, coalesce(proto, 'ip') proto, dst_port, count(*) n, min(ts) f, max(ts) l "
            "FROM events WHERE id > $1 AND id <= $2 AND source IN ('firewall', 'zenarmor') "
            f"AND {ALLOWED_ROW} AND src_ip IS NOT NULL AND dst_ip IS NOT NULL AND NOT (dst_ip <<= ANY($3::inet[])) "
            "GROUP BY 1, 2, 3, 4", last, upto, nets)
        for r in conns:
            add(r["ip"], "country", r["dst_country"], r["n"], r["f"], r["l"])
            if r["dst_port"]:
                add(r["ip"], "port", f"{r['proto']}/{r['dst_port']}", r["n"], r["f"], r["l"])
        dns = await pool.fetch(
            "SELECT host(src_ip) ip, domain, count(*) n, min(ts) f, max(ts) l FROM events WHERE id > $1 AND id <= $2 "
            "AND (source = 'unbound' OR (source = 'zenarmor' AND data->>'family' = 'dns')) AND src_ip IS NOT NULL "
            "AND domain IS NOT NULL GROUP BY 1, 2", last, upto)
        for r in dns:
            add(r["ip"], "domain", registered_domain(r["domain"].lower().rstrip(".")), r["n"], r["f"], r["l"])
        tls = await pool.fetch(
            "SELECT host(src_ip) ip, coalesce(data->>'ja4', data->>'ja3', data->>'ja3_hash') fp, count(*) n, min(ts) f, "
            "max(ts) l FROM events WHERE id > $1 AND id <= $2 AND source IN ('suricata', 'zenarmor') AND src_ip IS NOT NULL "
            "AND coalesce(data->>'ja4', data->>'ja3', data->>'ja3_hash') IS NOT NULL GROUP BY 1, 2", last, upto)
        for r in tls:
            add(r["ip"], "tls", r["fp"], r["n"], r["f"], r["l"])
        tz = self.s.timezone or "UTC"
        hours = await pool.fetch(
            "SELECT host(src_ip) ip, extract(hour FROM ts AT TIME ZONE $3)::int h, count(*) n, min(ts) f, max(ts) l FROM events "
            "WHERE id > $1 AND id <= $2 AND source IN ('firewall', 'zenarmor', 'unbound') AND src_ip IS NOT NULL GROUP BY 1, 2",
            last, upto, tz)
        for r in hours:
            add(r["ip"], "hour", r["h"], r["n"], r["f"], r["l"])

        new: list[dict[str, Any]] = []
        if agg:
            keys, kinds, values, firsts, lasts, hits = zip(*((k, kd, v, a[1], a[2], a[0]) for (k, kd, v), a in agg.items()))
            rows = await pool.fetch(
                "INSERT INTO device_profile (key, kind, value, first_seen, last_seen, hits) "
                "SELECT * FROM unnest($1::text[], $2::text[], $3::text[], $4::timestamptz[], $5::timestamptz[], $6::bigint[]) "
                "ON CONFLICT (key, kind, value) DO UPDATE SET last_seen = greatest(device_profile.last_seen, EXCLUDED.last_seen), "
                "hits = device_profile.hits + EXCLUDED.hits RETURNING key, kind, value, hits, (xmax = 0) AS inserted",
                list(keys), list(kinds), list(values), list(firsts), list(lasts), list(hits))
            new = [dict(r) for r in rows if r["inserted"]]
        await db.kv_set("wm:profile", upto)
        if new:
            await self._novelties(new, ips, macs)

    async def _novelties(self, new: list[dict[str, Any]], ips: dict[str, str], macs: dict[str, dict[str, Any]]) -> None:
        pool = db.pool()
        s = self.s
        enabled = {"country": s.behavior_new_country, "port": s.behavior_new_port, "domain": s.behavior_new_domain,
                   "tls": s.behavior_new_tls, "hour": s.behavior_odd_hours}
        by_key: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
        for n in new:
            if enabled.get(n["kind"]):
                by_key[n["key"]][n["kind"]].append(n)
        if not by_key:
            return
        ages = {r["key"]: r for r in await pool.fetch(
            "SELECT key, min(first_seen) AS since FROM device_profile WHERE key = ANY($1::text[]) GROUP BY key", list(by_key))}
        mac_info = {m["mac"]: m for m in macs.values()}
        now = datetime.now(timezone.utc)
        for key, kinds in by_key.items():
            since = ages.get(key, {}).get("since") if key in ages else None
            if not since or now - since < timedelta(days=s.behavior_min_days):
                continue  # still learning this device
            ip = ips.get(key)
            dev = mac_info.get(key) or {}
            vendor = dev.get("vendor")
            peers = [m for m, d in mac_info.items() if vendor and d.get("vendor") == vendor and m != key]
            label = f"{dev.get('hostname')} ({ip})" if dev.get("hostname") else ip
            for kind, items in kinds.items():
                if kind == "hour":
                    await self._odd_hour(key, ip, label, items, since)
                    continue
                if s.behavior_stable_max and await self._new_per_day(key, kind, since) > s.behavior_stable_max:
                    continue  # this device always picks up new things of this kind (PC, phone): not predictable
                values = [i["value"] for i in items]
                common: set[str] = set()
                rating = Rating("low", f"this device never used this {KINDS[kind]} before and normally sticks to the same "
                                       "ones", sticky=True)
                if s.behavior_peers and len(peers) >= 2:
                    common = {r["value"] for r in await pool.fetch(
                        "SELECT DISTINCT value FROM device_profile WHERE kind = $1 AND value = ANY($2::text[]) "
                        "AND key = ANY($3::text[])", kind, values, peers)}
                    values = [v for v in values if v not in common]
                    if not values:
                        continue  # other devices of this vendor do it too: normal for this kind of device
                    rating.up(f"none of the other {len(peers)} {vendor} devices does this")
                if kind == "port" and any(int(v.split("/")[-1]) in SUSPICIOUS_OUT_PORTS or int(v.split("/")[-1]) in LATERAL_PORTS
                                          for v in values if v.split("/")[-1].isdigit()):
                    rating.up("and it is a port malware / remote access uses")
                corroborate(rating, await evidence(ip, "new_behavior"), 1)
                day = now.strftime("%Y-%m-%d")
                today = [r["value"] for r in await pool.fetch(
                    "SELECT value FROM device_profile WHERE key = $1 AND kind = $2 AND first_seen > now() - interval '24 hours' "
                    "ORDER BY first_seen LIMIT 30", key, kind)]
                shown = sorted(set(values) | (set(today) - common))[:12]
                await raise_alert(
                    "new_behavior", rating, f"{label}: new {KINDS[kind]}: {', '.join(shown[:4])}"
                                            + (f" +{len(shown) - 4}" if len(shown) > 4 else ""),
                    f"newbeh:{key}:{kind}:{day}", src_ip=ip, events={"ip": ip}, count=len(values),
                    data={"key": key, "kind": kind, "values": shown},
                    description=f"First time in at least {s.behavior_learn_days} days that {label} uses these "
                                f"{KINDS[kind]}s: {', '.join(shown)}. Expected (an update, a new app)? Then nothing to do: "
                                "it is now part of the device's normal behaviour. Tune under Settings › Behaviour & ML.")

    async def _new_per_day(self, key: str, kind: str, since: datetime) -> float:
        """How many new values of this kind the device picked up per day, after its first day."""
        row = await db.pool().fetchrow(
            "SELECT count(*) n FROM device_profile WHERE key = $1 AND kind = $2 AND first_seen > $3::timestamptz + interval '1 day' "
            "AND first_seen < now() - interval '1 hour'", key, kind, since)
        days = max(1.0, (datetime.now(timezone.utc) - since).total_seconds() / 86400 - 1)
        return (row["n"] if row else 0) / days

    async def _odd_hour(self, key: str, ip: str | None, label: str, items: list[dict[str, Any]], since: datetime) -> None:
        busy = [i for i in items if i["hits"] >= 20]
        if not busy:
            return
        hrs = ", ".join(f"{int(i['value']):02d}:00" for i in busy)
        await raise_alert(
            "odd_hours", corroborate(Rating("low", "active at an hour this device has never been active", sticky=True),
                                     await evidence(ip, "odd_hours"), 1),
            f"{label} active at an unusual hour ({hrs})", f"oddhour:{key}:{busy[0]['value']}", src_ip=ip,
            events={"ip": ip}, count=sum(i["hits"] for i in busy),
            description=f"{label} made {sum(i['hits'] for i in busy)} connections / lookups around {hrs} "
                        f"({self.s.timezone or 'UTC'}), an hour it has not been active in since "
                        f"{local_time(self.s, since, date=True)}. Scheduled updates or backups do this too.")

    async def cleanup(self) -> None:
        """Forget what a device has not done for longer than the learning period (it counts as new again)."""
        await db.pool().execute("DELETE FROM device_profile WHERE last_seen < now() - make_interval(days => $1)",
                                self.s.behavior_learn_days)
        await db.pool().execute("DELETE FROM device_hourly WHERE hour < now() - make_interval(days => $1)",
                                self.s.behavior_learn_days + 1)
        await db.pool().execute("DELETE FROM hourly_stats WHERE hour < now() - interval '70 days'")

    # ------------------------------------------------- hourly aggregation ---
    async def hourly(self) -> None:
        """Compute the per-device and network-wide totals of finished hours; check the newest one."""
        if not (self.s.behavior_enabled or self.s.seasonal_enabled):
            return
        now = datetime.now(timezone.utc)
        latest = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
        done = await db.kv_get("beh:hour")
        start = datetime.fromisoformat(done) + timedelta(hours=1) if done else latest - timedelta(days=self.s.behavior_learn_days)
        start = max(start, latest - timedelta(days=self.s.behavior_learn_days))
        hour = start
        steps = 0
        while hour <= latest and steps < 48:  # back-fill in steps
            await self._aggregate(hour)
            await db.kv_set("beh:hour", hour.isoformat())
            if hour == latest:
                await self.check_hour(hour)
            hour += timedelta(hours=1)
            steps += 1

    async def _aggregate(self, hour: datetime) -> None:
        pool = db.pool()
        end = hour + timedelta(hours=1)
        nets = internal_cidrs(self.s)
        up = "greatest(coalesce((data->>'src_nbytes')::numeric, 0), coalesce((data->>'src_pbytes')::numeric, 0))"
        conns = await pool.fetch(
            "SELECT host(src_ip) ip, count(*) c, count(DISTINCT dst_ip) d, count(DISTINCT dst_port) p, "
            f"count(DISTINCT dst_country) k, count(*) FILTER (WHERE action IN ('block', 'drop')) b, coalesce(sum({up}), 0) u "
            "FROM events WHERE ts >= $1 AND ts < $2 AND source IN ('firewall', 'zenarmor') AND src_ip <<= ANY($3::inet[]) "
            "AND coalesce(data->>'family', 'conn') = 'conn' GROUP BY 1", hour, end, nets)
        dns = await pool.fetch(
            "SELECT host(src_ip) ip, count(*) q, count(*) FILTER (WHERE upper(coalesce(data->>'rcode', '')) = 'NXDOMAIN' "
            "OR action = 'nxdomain') nx FROM events WHERE ts >= $1 AND ts < $2 AND source = 'unbound' "
            "AND src_ip <<= ANY($3::inet[]) GROUP BY 1", hour, end, nets)
        if self.s.behavior_enabled:
            macs = await self.ip_to_mac()
            excl = self.excluded()
            feats: dict[str, dict[str, float]] = defaultdict(lambda: dict.fromkeys(FEATURES, 0.0))
            for r in conns:
                f = feats[r["ip"]]
                f.update(connections=r["c"], destinations=r["d"], ports=r["p"], countries=r["k"], blocked=r["b"],
                         upload_mb=round(float(r["u"]) / 1048576, 2))
            for r in dns:
                feats[r["ip"]].update(dns=r["q"], failed_lookups=r["nx"])
            rows = [(self.key_of(ip, macs), hour, ip, f) for ip, f in feats.items()
                    if not excl.match(ip, (macs.get(ip) or {}).get("mac"))]
            if rows:
                await pool.executemany(
                    "INSERT INTO device_hourly (key, hour, ip, features) VALUES ($1, $2, $3::inet, $4) "
                    "ON CONFLICT (key, hour) DO UPDATE SET features = EXCLUDED.features, ip = EXCLUDED.ip", rows)
        if self.s.seasonal_enabled:
            tot = await pool.fetchrow(
                "SELECT count(*) FILTER (WHERE action IN ('block', 'drop')) blocks, "
                "count(*) FILTER (WHERE action = 'login_failed') login_failed, count(*) FILTER (WHERE source = 'unbound') dns, "
                "count(*) FILTER (WHERE source = 'unbound' AND (upper(coalesce(data->>'rcode', '')) = 'NXDOMAIN' "
                "OR action = 'nxdomain')) nxdomain FROM events WHERE ts >= $1 AND ts < $2", hour, end)
            per_src = await pool.fetch("SELECT source, count(*) n FROM events WHERE ts >= $1 AND ts < $2 GROUP BY 1", hour, end)
            stats = {k: float(v) for k, v in dict(tot).items()} if tot else {}
            stats.update({f"source:{r['source']}": float(r["n"]) for r in per_src})
            await pool.executemany("INSERT INTO hourly_stats (metric, hour, value) VALUES ($1, $2, $3) "
                                   "ON CONFLICT (metric, hour) DO UPDATE SET value = EXCLUDED.value",
                                   [(m, hour, v) for m, v in stats.items()])

    async def check_hour(self, hour: datetime) -> None:
        for check in (self.volume, self.ml, self.seasonal):
            try:
                await check(hour)
            except Exception:  # noqa: BLE001
                log.exception("behaviour check %s failed", check.__name__)

    async def _history(self, hour: datetime) -> dict[str, list[dict[str, Any]]]:
        rows = await db.pool().fetch(
            "SELECT key, hour, host(ip) ip, features FROM device_hourly WHERE hour > $1::timestamptz - make_interval(days => $2) "
            "AND hour <= $1 ORDER BY hour", hour, self.s.behavior_learn_days)
        out: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in rows:
            out[r["key"]].append(dict(r))
        return out

    async def volume(self, hour: datetime) -> None:
        """Connections, DNS lookups or upload of one device far above its own normal."""
        factor = self.s.behavior_volume_factor
        if not self.s.behavior_enabled or not factor:
            return
        floors = {"connections": 500, "dns": 500, "upload_mb": 200}
        for key, rows in (await self._history(hour)).items():
            cur = rows[-1] if rows and rows[-1]["hour"] == hour else None
            hist = [r["features"] for r in rows if r["hour"] != hour]
            if not cur or len(hist) < 24 * min(self.s.behavior_min_days, 3):
                continue
            ip = cur["ip"]
            spikes = []
            for f, floor in floors.items():
                med = statistics.median(h.get(f, 0) for h in hist)
                v = cur["features"].get(f, 0)
                if v >= floor and v >= factor * max(med, floor / factor):
                    spikes.append(f"{FEATURE_LABEL[f]} {v:,.0f} (normally ~{med:,.0f})")
            if spikes:
                await raise_alert(
                    "volume_spike", corroborate(Rating("low", f"{factor}× or more above this device's normal hour"),
                                                await evidence(ip, "volume_spike"), 1),
                    f"Traffic spike from {ip}: {spikes[0]}", f"volume:{key}:{hour:%Y%m%d%H}", src_ip=ip, events={"ip": ip},
                    description=f"Between {local_time(self.s, hour)} and {local_time(self.s, hour + timedelta(hours=1))}: "
                                f"{'; '.join(spikes)}. Factor and on/off: Settings › Behaviour & ML.")

    async def ml(self, hour: datetime) -> None:
        """Isolation Forest on each device's deviations from its own normal: hours unlike any normal hour."""
        if not (self.s.behavior_enabled and self.s.anomaly_ml_enabled):
            return
        history = await self._history(hour)
        train: list[list[float]] = []
        current: list[tuple[str, dict[str, Any], list[float], list[float]]] = []
        for key, rows in history.items():
            hist = [r for r in rows if r["hour"] != hour]
            if len(hist) < 48:
                continue  # too little history for this device
            logs = {f: [math.log1p(float(r["features"].get(f, 0))) for r in hist] for f in FEATURES}
            # log scale: a spread floor of 0.25 is a factor of ~1.3, so tiny-but-steady features don't explode
            norm = {f: robust(v, floor=0.25, rel=0) for f, v in logs.items()}

            def vec(feat: dict[str, Any]) -> list[float]:
                return [(math.log1p(float(feat.get(f, 0))) - norm[f][0]) / norm[f][1] for f in FEATURES]
            train += [vec(r["features"]) for r in hist]
            if rows[-1]["hour"] == hour:
                v = vec(rows[-1]["features"])
                med_raw = [statistics.median(float(r["features"].get(f, 0)) for r in hist) for f in FEATURES]
                current.append((key, rows[-1], v, med_raw))
        if len(train) < 500 or not current:
            return
        q, z = ML_LEVELS.get(self.s.anomaly_ml_sensitivity, ML_LEVELS["medium"])

        def run() -> tuple[float, list[float]]:
            rnd = random.Random(7)
            forest = SubspaceForest().fit(train)
            sample = rnd.sample(train, min(len(train), 3000))
            ref = sorted(forest.score(x) for x in sample)
            cut = ref[min(len(ref) - 1, int(q * len(ref)))]
            return cut, [forest.score(c[2]) for c in current]
        cut, scores = await asyncio.to_thread(run)
        for (key, row, v, med_raw), score in zip(current, scores):
            dev = [(v[i], f) for i, f in enumerate(FEATURES)
                   if v[i] >= z and float(row["features"].get(f, 0)) - med_raw[i] >= MIN_INCREASE[f]]
            # the forest finds unusual combinations; it cannot score values beyond everything it has seen higher than
            # the most extreme training point, so a feature far outside the device's range always counts too
            if not dev or (score < cut and max(d for d, _ in dev) < 2 * z):
                continue
            ip = row["ip"]
            parts = [f"{FEATURE_LABEL[f]} {float(row['features'].get(f, 0)):,.0f} (normally ~{med_raw[FEATURES.index(f)]:,.0f})"
                     for _, f in sorted(dev, reverse=True)]
            await raise_alert(
                "ml_anomaly", corroborate(Rating("low", "this hour is unlike the device's normal hours (machine learning)"),
                                          await evidence(ip, "ml_anomaly"), 1),
                f"Unusual activity of {ip} (machine learning): {parts[0]}", f"ml:{key}:{hour:%Y%m%d%H}", src_ip=ip,
                events={"ip": ip}, data={"score": round(score, 3), "cut": round(cut, 3)},
                description=f"Between {local_time(self.s, hour)} and {local_time(self.s, hour + timedelta(hours=1))} this "
                            f"device behaved unlike its last {self.s.behavior_learn_days} days: {'; '.join(parts)}. "
                            f"Anomaly score {score:.2f} (alert from {cut:.2f}). Sensitivity: Settings › Behaviour & ML.")

    async def seasonal(self, hour: datetime) -> None:
        """Network-wide totals of this hour against the same hour of the week before (or the same hour of day)."""
        if not self.s.seasonal_enabled:
            return
        ignore = {p.strip() for p in (self.s.seasonal_ignore or "").split(",") if p.strip()}
        pool = db.pool()
        cur = {r["metric"]: r["value"] for r in await pool.fetch("SELECT metric, value FROM hourly_stats WHERE hour = $1", hour)}
        k = self.s.seasonal_sensitivity
        for metric, value in cur.items():
            if metric in ignore or value < 30:
                continue
            weekly = [r["value"] for r in await pool.fetch(
                "SELECT value FROM hourly_stats WHERE metric = $1 AND hour = ANY($2::timestamptz[])",
                metric, [hour - timedelta(days=7 * w) for w in range(1, 9)])]
            base = weekly if len(weekly) >= 3 else [r["value"] for r in await pool.fetch(
                "SELECT value FROM hourly_stats WHERE metric = $1 AND hour = ANY($2::timestamptz[])",
                metric, [hour - timedelta(days=d) for d in range(1, 15)])]
            if len(base) < (3 if base is weekly else 7):
                continue
            med, spread = robust(base)
            limit = med + k * max(spread, 3)
            if value <= limit:
                continue
            sev = "medium" if value > 2 * limit and metric in ("blocks", "login_failed", "nxdomain") else "low"
            when = f"{local_time(self.s, hour)}-{local_time(self.s, hour + timedelta(hours=1))}"
            ref = "the same hour in previous weeks" if base is weekly else "the same hour on previous days"
            await raise_alert(
                "unusual_volume", Rating(sev, f"far above {ref}"),
                f"Unusual {metric_label(metric)}: {value:,.0f} between {when} (normally ~{med:,.0f})",
                f"season:{metric}:{hour:%Y%m%d%H}", data={"metric": metric, "value": value, "median": med},
                events=metric_events(metric),
                description=f"{value:,.0f} {metric_label(metric)} between {when} - normally ~{med:,.0f} at {ref}. "
                            f"Ignore this metric: add '{metric}' under Settings › Behaviour & ML › Hour of the week: ignore.")

    # ----------------------------------------------------------- risk score ---
    async def risk(self) -> None:
        if not self.s.risk_enabled:
            return
        pool = db.pool()
        rows = await pool.fetch(
            "SELECT host(coalesce(src_ip, dst_ip)) ent, rule, severity, last_seen FROM alerts WHERE status <> 'closed' "
            "AND last_seen > now() - interval '7 days' AND coalesce(src_ip, dst_ip) IS NOT NULL "
            "AND rule NOT IN ('risk_score')")
        excl, never = Matcher(self.s.risk_exclude), self.excluded()
        half = max(1, self.s.risk_half_life) * 3600
        now = datetime.now(timezone.utc)
        best: dict[str, dict[str, tuple[float, str]]] = defaultdict(dict)
        for r in rows:
            if excl.match(r["ent"]) or never.match(r["ent"]):
                continue
            pts = RISK_POINTS.get(r["severity"], 1) * 0.5 ** ((now - r["last_seen"]).total_seconds() / half)
            if pts > best[r["ent"]].get(r["rule"], (0, ""))[0]:
                best[r["ent"]][r["rule"]] = (pts, r["severity"])
        scores = {e: (sum(p for p, _ in parts.values()), parts) for e, parts in best.items()}
        await pool.execute("DELETE FROM risk_scores WHERE NOT (entity = ANY($1::text[]))", list(scores))
        for ent, (score, parts) in scores.items():
            detail = sorted(((round(p, 1), rule, sev) for rule, (p, sev) in parts.items()), reverse=True)
            await pool.execute(
                "INSERT INTO risk_scores (entity, score, parts, updated) VALUES ($1, $2, $3, now()) "
                "ON CONFLICT (entity) DO UPDATE SET score = EXCLUDED.score, parts = EXCLUDED.parts, updated = now()",
                ent, round(score, 1), [{"points": p, "rule": r, "severity": s} for p, r, s in detail])
            internal = self.internal(ent)
            if score >= self.s.risk_threshold and internal:  # internet addresses collect points too, but alerting on
                # every busy scanner would be noise - they only add context (attack chains, the AI analyst)
                await raise_alert(
                    "risk_score", Rating("high" if score < 2 * self.s.risk_threshold else "critical",
                                         f"many signals add up (risk score {score:.0f}, alert from {self.s.risk_threshold})"),
                    f"High risk score for {ent}: {score:.0f} ({len(detail)} alert types)", f"risk:{ent}", src_ip=ent,
                    events={"ip": ent}, data={"score": round(score, 1), "parts": detail[:15]},
                    description=f"{'This device' if internal else 'This address'} collected: "
                                + ", ".join(f"{r} ({s}, {p:.0f} pts)" for p, r, s in detail[:10])
                                + ". Points fade with a half-life of "
                                f"{self.s.risk_half_life} h. Tune: Settings › Behaviour & ML › Risk score.")

    # ------------------------------------------------------------- feedback ---
    async def feedback(self) -> list[dict[str, Any]]:
        """Patterns closed as false positive often enough: suggestions (and, in auto mode, severity rules)."""
        if self.s.feedback_mode == "off":
            return []
        rows = await db.pool().fetch(
            "SELECT rule, host(src_ip) ip, count(*) n, max(title) example FROM alerts WHERE close_reason = 'false_positive' "
            "AND last_seen > now() - interval '30 days' GROUP BY 1, 2 HAVING count(*) >= $1 ORDER BY 3 DESC",
            self.s.feedback_min)
        dismissed = set(await db.kv_get("feedback:dismissed", []) or [])
        filters = await db.pool().fetch("SELECT rules, networks, action, set_severity FROM alert_filters WHERE enabled")
        out = []
        for r in rows:
            pid = f"{r['rule']}|{r['ip'] or ''}"
            if pid in dismissed or any(r["rule"] in (f["rules"] or []) and (not r["ip"] or r["ip"] in (f["networks"] or ""))
                                       for f in filters):
                continue
            out.append({"id": pid, "rule": r["rule"], "ip": r["ip"], "count": r["n"], "example": r["example"],
                        "label": alert_filters.RULE_LABELS.get(r["rule"], r["rule"])})
        if self.s.feedback_mode == "auto":
            for sug in out:
                payload = {"name": f"Learned: {sug['label']}" + (f" from {sug['ip']}" if sug["ip"] else ""),
                           "rules": [sug["rule"]], "networks": sug["ip"] or "", "action": "severity", "set_severity": "info"}
                f = alert_filters.clean(payload)
                await db.pool().execute(
                    "INSERT INTO alert_filters (name, enabled, max_severity, rules, contains, networks, action, match_mode, "
                    "text_mode, set_severity, src_ports, dst_ports) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                    *f.values())
                log.info("feedback: created rule %s", payload["name"])
            if out:
                alert_filters.invalidate()
            return []
        return out


def metric_label(metric: str) -> str:
    if metric.startswith("source:"):
        return f"{metric.split(':', 1)[1]} events"
    return {"blocks": "firewall blocks", "login_failed": "failed logins", "dns": "DNS lookups",
            "nxdomain": "failed DNS lookups (NXDOMAIN)"}.get(metric, metric)


def metric_events(metric: str) -> dict[str, Any]:
    if metric.startswith("source:"):
        return {"source": metric.split(":", 1)[1]}
    return {"blocks": {"action": "block"}, "login_failed": {"action": "login_failed"}, "dns": {"source": "unbound"},
            "nxdomain": {"source": "unbound", "d_rcode": "NXDOMAIN"}}.get(metric, {})


__all__ = ["Behavior", "Matcher", "SEVERITIES"]
