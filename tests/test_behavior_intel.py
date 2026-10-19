import asyncio
import os
import random
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from lookingglass import db
from lookingglass.behavior import Behavior, Matcher
from lookingglass.config import Settings
from lookingglass.detections import DetectionEngine
from lookingglass.intel import (Intel, describe_rule, exposure_changes, opens_inbound, parse_canaries, parse_feed)
from lookingglass.mlforest import SubspaceForest
from lookingglass.parsers.common import event

DSN = os.environ.get("TEST_DATABASE_URL")
NOW = datetime.now(timezone.utc)
needs_db = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")


# ------------------------------------------------------------------ units ---
def test_subspace_forest_finds_single_feature_and_combination_outliers():
    r = random.Random(3)
    rows = [[r.gauss(0, 1) for _ in range(8)] for _ in range(2000)]
    f = SubspaceForest().fit(rows)
    ref = sorted(f.score(x) for x in rows)
    cut = ref[int(0.998 * len(ref))]
    # (one feature far beyond the training range only scores like the most extreme training points - the forest
    # saturates there; behavior.ml therefore also accepts a large deviation on its own)
    assert f.score([5, -5, 0, 0, 0, 0, 0, 0]) > cut      # an odd combination
    assert f.score([0.1] * 8) < cut
    assert set(f.explain([0, 0, 0, 0, 0, 12, 0, 0])) & {5}


def test_matcher_and_canaries():
    m = Matcher("192.168.1.10, 10.0.0.0/8; AA:BB:CC:DD:EE:FF\n2001:db8::/32")
    assert m.match("192.168.1.10") and m.match("10.1.2.3") and m.match("aa:bb:cc:dd:ee:ff") and m.match("2001:db8::1")
    assert not m.match("192.168.1.11", None, "not-an-ip")
    c = parse_canaries("192.168.1.1:23\n192.168.20.0/30, [2001:db8::5]:445, junk")
    assert [(str(n), p) for n, p in c] == [("192.168.1.1/32", 23), ("192.168.20.0/30", None), ("2001:db8::5/128", 445)]


def test_feed_parsers():
    assert parse_feed("urlhaus", "# c\n127.0.0.1\tbad.example\n127.0.0.1\tEvil.Example.\n") == \
        [("domain", "bad.example", "malware download site"), ("domain", "evil.example", "malware download site")]
    tf = ('# header\n"2026-10-01 10:00:00", "1", "c2.example.net", "domain", "botnet_cc", "win.x", "None", "AgentTesla", '
          '"", "100"\n"2026-10-01 10:00:00", "2", "203.0.113.66:443", "ip:port", "botnet_cc", "win.y", "None", "Cobalt Strike"\n')
    assert parse_feed("threatfox", tf) == [("domain", "c2.example.net", "AgentTesla / botnet cc"),
                                           ("ip", "203.0.113.66", "Cobalt Strike / botnet cc")]
    assert parse_feed("feodo", "# x\n198.51.100.7\n") == [("ip", "198.51.100.7", "botnet command & control server")]
    assert parse_feed("sslbl_ja3", "# ja3_md5,Firstseen,Lastseen,Listingreason\n"
                                   "e7d705a3286e19ea42f587b344ee6865,2019-01-01,2026-01-01,Tofsee\n")[0] == \
        ("ja3", "e7d705a3286e19ea42f587b344ee6865", "Tofsee")
    tor = parse_feed("tor_relay", '{"relays": [{"n": "x", "a": ["192.0.2.9", "[2001:db8::9]"]}]}')
    assert {v for _, v, _ in tor} == {"192.0.2.9", "2001:db8::9"}


def test_exposure_diff():
    fwd = describe_rule({"uuid": "1", "interface": "wan", "protocol": "TCP", "destination_port": "443",
                         "target": "192.168.1.10", "local-port": "443", "description": "web"})
    rule = describe_rule({"action": "pass", "interface": "wan", "source_net": "any", "destination_net": "192.168.1.20",
                          "destination_port": "22"})
    assert "⇒ 192.168.1.10:443" in fwd and opens_inbound(fwd) and opens_inbound(rule)
    assert not opens_inbound(describe_rule({"action": "block", "interface": "lan"}))
    added, changed, removed = exposure_changes({"a": "x", "b": "y"}, {"a": "x2", "c": "z"})
    assert (added, removed) == (["z"], ["y"]) and changed == ["x  →  x2"]


# ------------------------------------------------------------------- DB ---
async def reset(pool):
    await pool.execute("TRUNCATE events, alerts, devices, device_profile, device_hourly, hourly_stats, intel_indicators, "
                       "seen_domains, risk_scores, alert_filters")
    await pool.execute("DELETE FROM kv WHERE key LIKE 'wm:%' OR key LIKE 'beh:%' OR key LIKE 'feedback:%' OR key LIKE 'intel:%' "
                       "OR key LIKE 'nod:%'")
    from lookingglass import alert_filters
    alert_filters.invalidate()


async def rules(pool, rule):
    return [dict(r) for r in await pool.fetch("SELECT title, severity, host(src_ip) ip, data, description FROM alerts "
                                               "WHERE rule = $1 ORDER BY id", rule)]


def run(coro_fn):
    async def main():
        await db.connect(DSN)
        try:
            await reset(db.pool())
            await coro_fn(db.pool())
            await reset(db.pool())
        finally:
            await db.close()
    asyncio.run(main())


@needs_db
def test_new_behavior_respects_learning_peers_and_predictability():
    async def body(pool):
        old = NOW - timedelta(days=10)
        cams = {"aa:00:00:00:00:01": "192.168.30.11", "aa:00:00:00:00:02": "192.168.30.12", "aa:00:00:00:00:03": "192.168.30.13"}
        for mac, ip in cams.items():
            await pool.execute("INSERT INTO devices (mac, ip, vendor, hostname) VALUES ($1, $2::inet, 'Reolink', $3)", mac, ip,
                               f"cam{ip[-1]}")
            await pool.execute("INSERT INTO device_profile (key, kind, value, first_seen, last_seen, hits) VALUES "
                               "($1, 'country', 'NL', $2, $2, 50), ($1, 'port', 'tcp/443', $2, $2, 50)", mac, old)
        # the other two cameras also use the US: normal for this vendor; nobody uses RU or SSH
        for mac in list(cams)[1:]:
            await pool.execute("INSERT INTO device_profile (key, kind, value, first_seen, last_seen, hits) VALUES "
                               "($1, 'country', 'US', $2, $2, 5)", mac, old)
        evs = [event(NOW - timedelta(minutes=1), "firewall", severity=6, action="pass", src_ip="192.168.30.11",
                     dst_ip="198.51.100.1", dst_port=443, proto="tcp", dst_country="US"),
               event(NOW - timedelta(minutes=1), "firewall", severity=6, action="pass", src_ip="192.168.30.11",
                     dst_ip="203.0.113.1", dst_port=22, proto="tcp", dst_country="RU")]
        await db.copy_events(evs)
        await db.kv_set("wm:profile", 0)
        await Behavior(Settings(), DetectionEngine(Settings()).internal).update_profiles()
        alerts = await rules(pool, "new_behavior")
        titles = " | ".join(a["title"] for a in alerts)
        assert "new country: RU" in titles and "US" not in titles          # the US is normal for Reolink cameras
        assert "new port / protocol: tcp/22" in titles
        port = next(a for a in alerts if "tcp/22" in a["title"])
        assert port["severity"] == "high"  # low + no peer does it + SSH
        assert "cam1 (192.168.30.11)" in port["title"]
        # a device that is still learning: nothing
        await pool.execute("INSERT INTO devices (mac, ip, vendor) VALUES ('bb:00:00:00:00:01', '192.168.30.50', 'X')")
        await pool.execute("INSERT INTO device_profile (key, kind, value, first_seen) VALUES ('bb:00:00:00:00:01', 'country', 'NL', now())")
        await db.copy_events([event(NOW, "firewall", severity=6, action="pass", src_ip="192.168.30.50", dst_ip="203.0.113.2",
                                    dst_port=443, proto="tcp", dst_country="CN")])
        before = len(await rules(pool, "new_behavior"))
        await Behavior(Settings(), DetectionEngine(Settings()).internal).update_profiles()
        assert len(await rules(pool, "new_behavior")) == before
        # excluded devices are never analysed
        await db.copy_events([event(NOW, "firewall", severity=6, action="pass", src_ip="192.168.30.12", dst_ip="203.0.113.3",
                                    dst_port=3389, proto="tcp", dst_country="KP")])
        s = Settings(behavior_exclude="aa:00:00:00:00:02")
        await Behavior(s, DetectionEngine(s).internal).update_profiles()
        assert not [a for a in await rules(pool, "new_behavior") if "KP" in a["title"] or "3389" in a["title"]]
    run(body)


@needs_db
def test_volume_ml_and_hour_of_week():
    async def body(pool):
        hour = NOW.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
        r = random.Random(5)
        rows = []
        for i in range(1, 7 * 24):
            for d in range(4):
                f = {"connections": 100 + r.randint(-20, 20), "destinations": 20 + r.randint(-3, 3), "ports": 3,
                     "countries": 2, "dns": 200 + r.randint(-30, 30), "failed_lookups": r.randint(0, 2), "blocked": r.randint(0, 3),
                     "upload_mb": 5 + r.random()}
                rows.append((f"dev{d}", hour - timedelta(hours=i), f"192.168.1.{20 + d}", f))
        rows.append(("dev0", hour, "192.168.1.20", {"connections": 9000, "destinations": 900, "ports": 40, "countries": 25,
                                                   "dns": 210, "failed_lookups": 1, "blocked": 2, "upload_mb": 6}))
        rows.append(("dev1", hour, "192.168.1.21", {"connections": 105, "destinations": 21, "ports": 3, "countries": 2,
                                                   "dns": 190, "failed_lookups": 1, "blocked": 1, "upload_mb": 5.5}))
        await pool.executemany("INSERT INTO device_hourly (key, hour, ip, features) VALUES ($1, $2, $3::inet, $4)", rows)
        b = Behavior(Settings(), DetectionEngine(Settings()).internal)
        await b.volume(hour)
        vol = await rules(pool, "volume_spike")
        assert [a["ip"] for a in vol] == ["192.168.1.20"] and "connections 9,000" in vol[0]["title"]
        await b.ml(hour)
        ml = await rules(pool, "ml_anomaly")
        assert [a["ip"] for a in ml] == ["192.168.1.20"] and "normally ~" in ml[0]["description"]
        # hour of the week: 3 earlier weeks with ~50 blocks, now 900
        await pool.executemany("INSERT INTO hourly_stats (metric, hour, value) VALUES ($1, $2, $3)",
                               [("blocks", hour - timedelta(days=7 * w), 50 + w) for w in (1, 2, 3)]
                               + [("blocks", hour, 900), ("dns", hour, 40)]
                               + [("dns", hour - timedelta(days=7 * w), 41) for w in (1, 2, 3)])
        await b.seasonal(hour)
        season = await rules(pool, "unusual_volume")
        assert len(season) == 1 and "firewall blocks: 900" in season[0]["title"] and season[0]["severity"] == "medium"
        s2 = Settings(seasonal_ignore="blocks")
        await pool.execute("DELETE FROM alerts")
        await Behavior(s2, DetectionEngine(s2).internal).seasonal(hour)
        assert not await rules(pool, "unusual_volume")
    run(body)


@needs_db
def test_risk_score_and_feedback():
    async def body(pool):
        await pool.execute(
            "INSERT INTO alerts (rule, severity, title, fingerprint, src_ip, last_seen) VALUES "
            "('beaconing', 'medium', 'b', 'r1', '192.168.1.50', now()), ('lateral_movement', 'high', 'l', 'r2', '192.168.1.50', now()), "
            "('dns_bypass', 'high', 'd', 'r3', '192.168.1.50', now()), ('port_scan', 'high', 'p', 'r4', '192.168.1.50', now()), "
            "('port_scan', 'low', 'p', 'r5', '192.168.1.51', now() - interval '3 days')")
        b = Behavior(Settings(), DetectionEngine(Settings()).internal)
        await b.risk()
        score = await pool.fetchval("SELECT score FROM risk_scores WHERE entity = '192.168.1.50'")
        assert 60 <= score <= 69  # 8 + 20 + 20 + 20 (port_scan counted once, highest)
        assert await pool.fetchval("SELECT score FROM risk_scores WHERE entity = '192.168.1.51'") < 0.5  # 3 pts, 3 half-lives
        assert [a["ip"] for a in await rules(pool, "risk_score")] == ["192.168.1.50"]
        s = Settings(risk_exclude="192.168.1.50")
        await pool.execute("DELETE FROM alerts WHERE rule = 'risk_score'")
        await Behavior(s, DetectionEngine(s).internal).risk()
        assert not await rules(pool, "risk_score")
        # three false positives for the same rule + address -> suggestion; auto mode -> severity rule
        await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint, src_ip, status, close_reason) "
                           "SELECT 'beaconing', 'low', 'b' || i, 'fp' || i, '192.168.1.60', 'closed', 'false_positive' "
                           "FROM generate_series(1, 3) i")
        sug = await b.feedback()
        assert [(x["rule"], x["ip"], x["count"]) for x in sug] == [("beaconing", "192.168.1.60", 3)]
        await db.kv_set("feedback:dismissed", [sug[0]["id"]])
        assert await b.feedback() == []
        await db.kv_set("feedback:dismissed", [])
        auto = Settings(feedback_mode="auto")
        await Behavior(auto, DetectionEngine(auto).internal).feedback()
        f = await pool.fetchrow("SELECT name, action, set_severity, networks FROM alert_filters")
        assert f["action"] == "severity" and f["set_severity"] == "info" and "192.168.1.60" in f["networks"]
        assert f["name"].startswith("Learned:")
        assert await b.feedback() == []  # covered by the rule now
    run(body)


@needs_db
def test_threat_intel_canary_and_arp():
    async def body(pool):
        await pool.executemany("INSERT INTO intel_indicators (kind, value, feed, info) VALUES ($1, $2, $3, $4)", [
            ("domain", "evil.example", "urlhaus", "malware download site"),
            ("ip", "203.0.113.66", "feodo", "botnet command & control server"),
            ("ip", "198.51.100.9", "tor_relay", "Tor relay"),
            ("ja3", "e7d705a3286e19ea42f587b344ee6865", "sslbl_ja3", "Tofsee")])
        await db.kv_set("intel:version", 1)
        t = NOW - timedelta(minutes=1)
        await db.copy_events([
            event(t, "unbound", severity=6, src_ip="192.168.1.30", domain="cdn.evil.example", action="pass"),
            event(t, "unbound", severity=6, src_ip="192.168.1.31", domain="pool.supportxmr.com", action="pass"),
            event(t, "firewall", severity=6, action="pass", src_ip="192.168.1.32", dst_ip="203.0.113.66", dst_port=443),
            event(t, "firewall", severity=6, action="pass", src_ip="192.168.1.33", dst_ip="198.51.100.9", dst_port=9001),
            event(t, "firewall", severity=6, action="pass", src_ip="192.168.1.34", dst_ip="198.51.100.9", dst_port=9001),
            event(t, "suricata", severity=6, action="tls", src_ip="192.168.1.35", dst_ip="192.0.2.1", domain="x.example",
                  data={"ja3": "e7d705a3286e19ea42f587b344ee6865"}),
            event(t, "firewall", severity=6, action="block", src_ip="192.168.1.40", dst_ip="192.168.1.1", dst_port=23),
            event(t, "firewall", severity=6, action="block", src_ip="192.168.1.41", dst_ip="192.168.1.1", dst_port=443),
            event(t, "firewall", severity=6, action="block", src_ip="192.168.1.42", dst_ip="192.168.1.1", dst_port=23),
            *[event(t, "arp", severity=4, action="arp_move", src_ip="192.168.1.77", data={"to": f"aa:aa:aa:aa:aa:0{i % 2}"})
              for i in range(4)],
            event(t, "arp", severity=2, action="arp_conflict", src_ip="192.168.1.1", data={"mac": "de:ad:be:ef:00:01"}),
        ])
        s = Settings(intel_tor_allow="192.168.1.34", canary_targets="192.168.1.1:23", canary_exclude="192.168.1.42")
        eng = DetectionEngine(s)
        for rule in (eng.threat_intel, eng.canary, eng.arp_spoofing):
            await rule()
        feed = {a["ip"]: a for a in await rules(pool, "threat_feed")}
        assert feed["192.168.1.30"]["severity"] == "high" and "evil.example" in feed["192.168.1.30"]["title"]
        assert feed["192.168.1.32"]["severity"] == "critical"   # allowed connection to a botnet C2
        assert [a["ip"] for a in await rules(pool, "crypto_mining")] == ["192.168.1.31"]
        assert [a["ip"] for a in await rules(pool, "tor")] == ["192.168.1.33"]  # .34 is allowed to use Tor
        assert "Tofsee" in (await rules(pool, "malicious_tls"))[0]["title"]
        assert [a["ip"] for a in await rules(pool, "canary")] == ["192.168.1.40"]  # .41: other port, .42: excluded
        arp = await rules(pool, "arp_spoofing")
        assert {a["title"].split(" ")[0] for a in arp} == {"Device", "192.168.1.77"}
        # allow-list: no more alerts for evil.example
        await pool.execute("DELETE FROM alerts")
        await pool.execute("DELETE FROM kv WHERE key = 'wm:intel'")
        await db.kv_set("wm:intel", 0)
        allow = Settings(intel_allow="evil.example, 203.0.113.66", intel_mining=False, intel_tor="off")
        await DetectionEngine(allow).threat_intel()
        assert not await rules(pool, "threat_feed") and not await rules(pool, "crypto_mining") and not await rules(pool, "tor")
        assert await pool.fetchval("SELECT count(*) FROM seen_domains") >= 2  # newly seen domains are tracked
    run(body)


@needs_db
def test_feed_download_and_rdap(monkeypatch):
    responses = {
        "urlhaus.abuse.ch": httpx.Response(200, text="127.0.0.1\tbad.example\n"),
        "threatfox.abuse.ch": httpx.Response(401, text="unauthorized"),
        "feodotracker.abuse.ch": httpx.Response(200, text="198.51.100.7\n"),
        "sslbl.abuse.ch": httpx.Response(200, text="e7d705a3286e19ea42f587b344ee6865,a,b,Tofsee\n"),
        "onionoo.torproject.org": httpx.Response(200, json={"relays": [{"a": ["192.0.2.9"]}]}),
        "check.torproject.org": httpx.Response(200, text="192.0.2.10\n"),
        "rdap.org": httpx.Response(200, json={"events": [{"eventAction": "registration",
                                                          "eventDate": (NOW - timedelta(days=3)).isoformat()}]}),
    }
    seen = []

    async def fake_get(self, url, **kw):
        seen.append((url, (kw.get("headers") or {}).get("Auth-Key")))
        resp = responses[httpx.URL(url).host]
        resp.request = httpx.Request("GET", url)
        return resp
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    async def body(pool):
        st = await Intel(Settings(abusech_auth_key="k3y")).update(force=True)
        assert st["urlhaus"]["ok"] and st["urlhaus"]["count"] == 1 and st["tor_relay"]["count"] == 1
        assert st["threatfox"]["ok"] is False and "Auth-Key" in st["threatfox"]["error"]
        assert ("https://urlhaus.abuse.ch/downloads/hostfile/", "k3y") in seen
        assert ("https://check.torproject.org/torbulkexitlist", None) in seen  # the key only goes to abuse.ch
        assert await pool.fetchval("SELECT count(*) FROM intel_indicators") == 5
        # RDAP: a 3-day-old domain looked up after the 2-day warm-up
        await pool.execute("INSERT INTO seen_domains (domain, first_client) VALUES ('fresh.example', '192.168.1.5')")
        await db.kv_set("nod:since", NOW.timestamp() - 5 * 86400)
        s = Settings(nod_rdap=True)
        await Intel(s).rdap(DetectionEngine(s).internal)
        young = await rules(pool, "young_domain")
        assert young and "3-day-old domain: fresh.example" in young[0]["title"]
    run(body)


@needs_db
def test_ml_ignores_small_absolute_changes():
    async def body(pool):
        hour = NOW.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
        base = {"connections": 100, "destinations": 20, "ports": 3, "countries": 2, "dns": 200, "failed_lookups": 0,
                "blocked": 0, "upload_mb": 5}
        rows = [(f"dev{d}", hour - timedelta(hours=i), f"192.168.1.{20 + d}", base) for i in range(1, 150) for d in range(4)]
        rows.append(("dev0", hour, "192.168.1.20", {**base, "failed_lookups": 12, "blocked": 9}))  # tiny, but "infinitely" more
        await pool.executemany("INSERT INTO device_hourly (key, hour, ip, features) VALUES ($1, $2, $3::inet, $4)", rows)
        await Behavior(Settings(), DetectionEngine(Settings()).internal).ml(hour)
        assert not await rules(pool, "ml_anomaly")
    run(body)


@needs_db
def test_exposure_watch_alerts_on_new_port_forward():
    from lookingglass.opnsense import ApiError, Poller

    class FakeApi:
        def __init__(self):
            self.nat = [{"uuid": "n1", "enabled": "1", "interface": "wan", "protocol": "TCP", "destination_port": "443",
                         "target": "192.168.1.10", "local-port": "443", "description": "web"}]

        async def search(self, path, rows=500):
            if path == "firewall/d_nat/search_rule":
                return self.nat
            raise ApiError(404, "not found")

    async def body(pool):
        await pool.execute("DELETE FROM kv WHERE key LIKE 'exposure:%'")
        p = object.__new__(Poller)
        p.settings, p.api = Settings(), FakeApi()
        await p.poll_exposure()                       # baseline: no alert
        assert not await rules(pool, "exposure_change")
        p.api.nat.append({"uuid": "n2", "enabled": "1", "interface": "wan", "protocol": "TCP", "destination_port": "3389",
                          "target": "192.168.1.33", "local-port": "3389", "description": "rdp"})
        await p.poll_exposure()
        a = await rules(pool, "exposure_change")
        assert len(a) == 1 and a[0]["severity"] == "medium" and "3389" in a[0]["title"] and "+ " in a[0]["description"]
        await p.poll_exposure()                       # nothing changed since: no new alert
        assert len(await rules(pool, "exposure_change")) == 1
        await pool.execute("DELETE FROM kv WHERE key LIKE 'exposure:%'")
    run(body)
