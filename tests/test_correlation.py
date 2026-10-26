import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest

from lookingglass import db
from lookingglass.config import Settings
from lookingglass.detections import DetectionEngine, login_target, raise_alert
from lookingglass.parsers import parse_line
from lookingglass.parsers.common import event

DSN = os.environ.get("TEST_DATABASE_URL")
NOW = datetime.now(timezone.utc)


def test_unraid_and_unifi_logins_are_parsed():
    ok = parse_line("<14>Oct 19 14:05:09 Tower webGUI: Successful login user root from 192.168.1.5", sender="x",
                    local_tz=timezone.utc)
    bad = parse_line("<14>Oct 19 14:05:09 Tower webGUI: Unsuccessful login user admin from 203.0.113.9. Ignoring login "
                     "attempts for 900 seconds.", sender="x", local_tz=timezone.utc)
    assert (ok["action"], ok["username"], ok["src_ip"], ok["host"]) == ("login_success", "root", "192.168.1.5", "Tower")
    assert (bad["action"], bad["src_ip"]) == ("login_failed", "203.0.113.9")
    from lookingglass.unifi import event_from_legacy
    e = event_from_legacy({"key": "EVT_AD_Login", "admin": "jan", "ip": "203.0.113.7", "time": 1760000000000,
                           "msg": "Admin[jan] log in from 203.0.113.7"}, "default")
    assert (e["action"], e["username"], e["src_ip"]) == ("login_success", "jan", "203.0.113.7")
    assert login_target("unifi", "unifi") == "UniFi controller" and login_target("auth", "Tower", ["webGUI"]) == "Tower (webGUI)"


def ev(source, minutes=1, **kw):
    return event(NOW - timedelta(minutes=minutes), source, severity=5, **kw)


async def alerts(pool, rule):
    return [dict(r) for r in await pool.fetch("SELECT title, severity, host(src_ip) ip, data FROM alerts WHERE rule = $1", rule)]


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_correlation_rules():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, alerts, devices")
            await pool.execute("DELETE FROM kv WHERE key LIKE 'wm:%'")
            evs = []
            # password spray: one address, 6 usernames, against Unraid
            evs += [ev("auth", i, host="Tower", program="webGUI", action="login_failed", src_ip="203.0.113.20",
                       username=f"user{i}") for i in range(6)]
            # distributed brute force on 'admin' from 12 addresses, one of them then logs in
            evs += [ev("auth", 5, host="opn", action="login_failed", src_ip=f"198.51.100.{i}", username="admin") for i in range(12)]
            evs.append(ev("auth", 1, host="opn", action="login_success", src_ip="198.51.100.3", username="admin"))
            # lateral movement: 192.168.1.50 hits SMB / SSH on 6 internal hosts
            evs += [ev("firewall", 2, action="pass", src_ip="192.168.1.50", dst_ip=f"192.168.1.{100 + i}", dst_port=445)
                    for i in range(6)]
            # DNS bypass
            evs.append(ev("firewall", 1, action="pass", src_ip="192.168.1.60", dst_ip="8.8.8.8", dst_port=53))
            # beaconing: every 5 minutes for 3 hours to a domain nobody else uses
            evs += [event(NOW - timedelta(minutes=5 * i), "unbound", severity=6, src_ip="192.168.1.50", domain="cdn-x7.badhost.example",
                          action="pass") for i in range(36)]
            await db.copy_events(evs)
            # login from a new country: history NL, now two countries within an hour
            await db.copy_events([event(NOW - timedelta(days=3), "vpn", severity=5, action="login_success", src_ip="203.0.113.80",
                                        username="jan", src_country="NL")])
            await db.kv_set("wm:login_geo", await pool.fetchval("SELECT max(id) FROM events"))
            await db.copy_events([ev("vpn", 50, action="login_success", src_ip="203.0.113.81", username="jan", src_country="NL"),
                                  ev("vpn", 1, action="login_success", src_ip="198.51.100.200", username="jan", src_country="BR")])

            eng = DetectionEngine(Settings())
            for rule in (eng.password_spray, eng.distributed_brute_force, eng.lateral_movement, eng.dns_bypass,
                         eng.beaconing, eng.login_location):
                await rule()

            spray = await alerts(pool, "password_spray")
            assert spray and spray[0]["ip"] == "203.0.113.20" and "6 usernames" in spray[0]["title"]
            dist = await alerts(pool, "distributed_brute_force")
            assert dist and dist[0]["severity"] == "critical" and dist[0]["ip"] == "198.51.100.3"
            lat = await alerts(pool, "lateral_movement")
            assert lat and lat[0]["severity"] == "high" and "SMB" in lat[0]["title"]  # medium + allowed
            assert (await alerts(pool, "dns_bypass"))[0]["ip"] == "192.168.1.60"
            # with a DNS redirect (port forward 53 -> Unbound) the logged 8.8.8.8 queries were answered locally ...
            await db.set_snapshot("nat_rules", [{"interface": "lan", "destination_port": "53", "target": "127.0.0.1"}])
            await db.copy_events([ev("zenarmor", 1, action="conn", src_ip="192.168.1.61", dst_ip="8.8.8.8", dst_port=53,
                                     data={"dst_npackets": "1"}),
                                  ev("firewall", 1, action="pass", src_ip="192.168.1.61", dst_ip="8.8.8.8", dst_port=53),
                                  # ... unless the firewall logged it leaving towards the internet
                                  ev("firewall", 1, action="pass", src_ip="192.168.1.62", dst_ip="8.8.4.4", dst_port=53,
                                     direction="out"),
                                  ev("firewall", 1, action="pass", src_ip="192.168.1.61", dst_ip="1.1.1.1", dst_port=853)])
            await eng.dns_bypass()
            got = {(a["ip"], "(53)" in a["title"]) for a in await alerts(pool, "dns_bypass")}
            assert ("192.168.1.61", True) not in got and ("192.168.1.61", False) in got and ("192.168.1.62", True) in got
            await db.set_snapshot("nat_rules", [])
            beacon = await alerts(pool, "beaconing")
            assert beacon and "every 5 min" in beacon[0]["title"]
            geo = await alerts(pool, "login_new_location")
            assert geo and geo[0]["severity"] == "high" and "Impossible travel" in geo[0]["title"]

            # chain: 192.168.1.50 beacons (C2) and moves laterally (spreading) -> possibly compromised device
            await eng.attack_chains()
            chain = await alerts(pool, "attack_chain")
            assert [c["ip"] for c in chain] == ["192.168.1.50"]
            assert chain[0]["severity"] == "high" and chain[0]["data"]["stages"] == ["Command & control", "Spreading / theft"]
            # outside -> in: scan, brute force, then a login from the same address = critical chain
            await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint, src_ip) VALUES "
                               "('port_scan', 'low', 's', 'c1', '203.0.113.99'), ('brute_force', 'medium', 'b', 'c2', '203.0.113.99'), "
                               "('success_after_failures', 'critical', 'l', 'c3', '203.0.113.99'), "
                               "('port_scan', 'low', 's', 'c4', '203.0.113.98'), ('brute_force', 'medium', 'b', 'c5', '203.0.113.98')")
            await eng.attack_chains()
            ext = {c["ip"]: c for c in await alerts(pool, "attack_chain")}
            assert ext["203.0.113.99"]["severity"] == "critical" and ext["203.0.113.99"]["data"]["stages"] == ["Recon", "Attack", "Access"]
            assert "203.0.113.98" not in ext  # never got in: noise
            await pool.execute("TRUNCATE events, alerts, devices")
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_zenarmor_blocked_alert_setting():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, alerts")

            async def run(mode):
                await pool.execute("TRUNCATE alerts")
                await pool.execute("DELETE FROM kv WHERE key = 'wm:zenarmor'")
                await db.kv_set("wm:zenarmor", 0)
                await DetectionEngine(Settings(zenarmor_blocked_alerts=mode)).zenarmor_threats()
                return sorted((r["title"].split(" (")[-1].rstrip(")"), r["severity"]) for r in
                              await pool.fetch("SELECT title, severity FROM alerts WHERE rule = 'zenarmor_threat'"))

            evs = [ev("zenarmor", 1, action="block", src_ip="192.168.1.5", domain="db.example", data={"security": "Database"}),
                   ev("zenarmor", 1, action="block", src_ip="192.168.1.6", domain="c2.example", data={"security": "Malware"}),
                   ev("zenarmor", 1, action="conn", src_ip="192.168.1.7", domain="p.example", data={"security": "Phishing"})]
            await db.copy_events(evs)
            assert await run("all") == [("Database", "low"), ("Malware", "low"), ("Phishing", "critical")]
            assert await run("threats") == [("Malware", "low"), ("Phishing", "critical")]    # the default
            assert await run("never") == [("Phishing", "critical")]                           # not blocked: always
            await pool.execute("TRUNCATE events, alerts")
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_blocked_threat_traffic_is_low_unless_repeated_or_confirmed():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, alerts")
            evs = [ev("zenarmor", 1, action="block", src_ip="192.168.1.5", domain="ad.example", data={"security": "Malware"}),
                   ev("qfeeds", 1, action="block", src_ip="192.168.1.8", dst_ip="91.92.1.1", dst_port=443)]
            # calling home: many blocked attempts / many different threat targets
            evs += [ev("zenarmor", 2 + 30 * i, action="block", src_ip="192.168.1.6", domain="c2.example",
                       data={"security": "Botnet"}) for i in range(6)]  # every 30 minutes for 3 hours
            # one visit to a phishing page: many retries to 4 subdomains within a minute - not repeated
            evs += [ev("zenarmor", 1, action="block", src_ip="192.168.1.11", domain=f"file{i % 4}.acgnngca.com",
                       data={"security": '["Phishing"]'}) for i in range(54)]
            evs += [ev("zenarmor", 2, action="block", src_ip="192.168.1.7", domain=f"m{i}.example",
                       data={"security": "Malware"}) for i in range(5)]
            evs += [ev("qfeeds", 2, action="block", src_ip="192.168.1.9", dst_ip=f"91.92.1.{i}", dst_port=443) for i in range(5)]
            # confirmed by two other sources
            evs += [ev("suricata", 2, src_ip="192.168.1.10"),
                    ev("zenarmor", 1, action="block", src_ip="192.168.1.10", domain="x.example", data={"security": "Phishing"})]
            await db.copy_events(evs)
            await raise_alert("dns_tunneling", "medium", "x", "t:1", src_ip="192.168.1.10")
            for rule in ("zenarmor", "qfeeds"):
                await db.kv_set(f"wm:{rule}", 0)
            await DetectionEngine(Settings()).zenarmor_threats()
            await DetectionEngine(Settings()).qfeeds_hits()
            sev = {r["ip"]: r["severity"] for r in await pool.fetch(
                "SELECT host(src_ip) ip, severity FROM alerts WHERE rule IN ('zenarmor_threat', 'threat_intel_outbound')")}
            assert sev == {"192.168.1.5": "low", "192.168.1.8": "low", "192.168.1.6": "medium", "192.168.1.7": "medium",
                           "192.168.1.9": "medium", "192.168.1.10": "high", "192.168.1.11": "low"}
            why = await pool.fetchval("SELECT description FROM alerts WHERE host(src_ip) = '192.168.1.6'")
            assert "working as intended" in why and "in 6 separate 10-minute periods" in why
            why = await pool.fetchval("SELECT description FROM alerts WHERE host(src_ip) = '192.168.1.11' LIMIT 1")
            assert "repeated" not in why
            await pool.execute("TRUNCATE events, alerts")
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_zenarmor_alerts_name_app_category_and_policy():
    from lookingglass.parsers.security import zenarmor_record

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, alerts")
            t = NOW - timedelta(minutes=1)
            await db.copy_events([
                zenarmor_record("conn", {"is_blocked": 1, "ip_src_saddr": "192.168.30.5", "ip_dst_saddr": "155.133.230.1",
                                         "ip_dst_port": 27015, "app_name": "MySQL", "app_category": "Database", "policyid": "2"}, t),
                zenarmor_record("dns", {"is_blocked": 1, "ip_src_saddr": "192.168.30.6", "query": "bad.example",
                                        "domain_categories": ["Phishing"]}, t)])
            msg = await pool.fetchval("SELECT message FROM events WHERE host(src_ip) = '192.168.30.5'")
            assert msg == "BLOCKED MySQL -> 155.133.230.1 - app MySQL (Database) · policy 2"
            await db.kv_set("wm:zenarmor", 0)
            await DetectionEngine(Settings(zenarmor_blocked_alerts="all")).zenarmor_threats()
            a = {r["ip"]: r for r in await pool.fetch(
                "SELECT host(src_ip) ip, title, severity, description FROM alerts WHERE rule = 'zenarmor_threat'")}
            assert a["192.168.30.5"]["title"] == "Zenarmor blocked: 192.168.30.5 → 155.133.230.1 (MySQL, Database)"
            assert "app MySQL (Database) · policy 2" in a["192.168.30.5"]["description"]
            assert "Zenarmor › Policies" in a["192.168.30.5"]["description"] and a["192.168.30.5"]["severity"] == "low"
            assert a["192.168.30.6"]["severity"] == "low" and "Phishing" in a["192.168.30.6"]["title"]  # blocked once
            # default (threats only): the policy block is skipped, the phishing lookup still alerts
            await pool.execute("TRUNCATE alerts")
            await db.kv_set("wm:zenarmor", 0)
            await DetectionEngine(Settings()).zenarmor_threats()
            assert [r["ip"] for r in await pool.fetch("SELECT host(src_ip) ip FROM alerts")] == ["192.168.30.6"]
            await pool.execute("TRUNCATE events, alerts")
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_zenarmor_alert_record_before_its_block_is_not_critical():
    """Zenarmor's threat "alert" record has no blocked flag; the blocked DNS record can come in a later batch. The alert
    must end up as blocked (low), not stay critical."""
    from lookingglass.parsers.security import zenarmor_record

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, alerts")
            t = NOW - timedelta(minutes=2)
            src, dom = {"ip_src_saddr": "10.0.3.3"}, "file.acgnngca.com"
            await db.copy_events([zenarmor_record("alert", {**src, "dst_hostname": dom, "alert_category": "Phishing"}, t)])
            await db.kv_set("wm:zenarmor", 0)
            await DetectionEngine(Settings()).zenarmor_threats()
            assert await pool.fetchval("SELECT severity FROM alerts") == "critical"  # nothing says it was blocked (yet)
            await db.copy_events([zenarmor_record("dns", {**src, "query": dom, "is_blocked": 1, "alert_category": "Phishing"}, t)
                                  for _ in range(3)])
            await DetectionEngine(Settings()).zenarmor_threats()
            a = await pool.fetchrow("SELECT title, severity, description FROM alerts WHERE rule = 'zenarmor_threat'")
            assert a["severity"] == "low" and a["title"].startswith("Zenarmor blocked:")
            assert "NOT blocked" not in a["description"] and "(blocked)" in a["description"]
            # a later alert record alone: the block of the last 24h still counts
            await db.copy_events([zenarmor_record("alert", {**src, "dst_hostname": dom, "alert_category": "Phishing"}, NOW)])
            await DetectionEngine(Settings()).zenarmor_threats()
            assert await pool.fetchval("SELECT severity FROM alerts") == "low"
            # flagged traffic that got through: critical again
            await db.copy_events([zenarmor_record("tls", {**src, "server_name": dom, "alert_category": "Phishing"}, NOW)])
            await DetectionEngine(Settings()).zenarmor_threats()
            a = await pool.fetchrow("SELECT severity, description FROM alerts")
            assert a["severity"] == "critical" and "some of it was NOT blocked" in a["description"]
            await pool.execute("TRUNCATE events, alerts")
        finally:
            await db.close()

    asyncio.run(main())


def test_config_change_says_what_and_who():
    from lookingglass.parsers.security import config_change
    line = ("<37>Oct 20 10:15:01 fw audit[42]: user admin@192.168.1.10 changed configuration to "
            "/conf/backup/config-1760000000.1234.xml in /api/nginx/settings/set /api/nginx/settings/set made changes")
    e = parse_line(line, sender="x", local_tz=timezone.utc)
    assert (e["action"], e["username"], e["src_ip"]) == ("config_change", "admin", "192.168.1.10")
    assert e["data"]["config"]["label"] == "Nginx" and e["data"]["config"]["path"] == "/api/nginx/settings/set"
    legacy = config_change("user root@10.0.0.5 changed configuration to /conf/backup/c.xml in /firewall_rules_edit.php?id=3 x")
    assert (legacy["area"], legacy["label"], legacy["user"]) == ("firewall_rules", "firewall rules", "root")
    system = config_change("user (root) changed configuration to /conf/backup/c.xml in /usr/local/sbin/pluginctl ")
    assert system["user"] is None and system["ip"] is None
    if not DSN:
        return

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, alerts")
            await pool.execute("DELETE FROM kv WHERE key LIKE 'wm:%'")
            await db.copy_events([e])
            await DetectionEngine(Settings()).config_changes()
            a = (await alerts(pool, "config_change"))[0]
            assert a["title"] == "Configuration change on fw: Nginx by admin from 192.168.1.10" and a["ip"] == "192.168.1.10"
            assert a["data"]["config"]["area"] == "nginx"
            # configd's "trigger config changed event" of the same save says nothing: no second, empty alert
            trigger = "<37>Oct 20 10:15:01 fw configd.py[7]: [a18da959-fabd-4157-8979-bb5c9f7ae07e] trigger config changed event"
            t = parse_line(trigger, sender="x", local_tz=timezone.utc)
            assert t["action"] == "config_change"
            t["ts"] = e["ts"]
            await db.copy_events([t])
            await DetectionEngine(Settings()).config_changes()
            assert len(await alerts(pool, "config_change")) == 1
            # without the audit line (not forwarded): still an alert, saying how to get the details
            await pool.execute("TRUNCATE events, alerts")
            await db.copy_events([t])
            await DetectionEngine(Settings()).config_changes()
            d = await pool.fetchval("SELECT description FROM alerts WHERE rule = 'config_change'")
            assert "Applications empty (or include 'audit')" in d
            await pool.execute("TRUNCATE events, alerts")
        finally:
            await db.close()
    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_blocked_traffic_is_never_critical():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, alerts")
            await db.copy_events([
                # Suricata and Q-Feeds also flagged 192.168.1.6 and it keeps trying - that would push the blocked malware
                # hit to critical
                ev("suricata", 5, action="alert", src_ip="192.168.1.6", dst_ip="198.51.100.1", message="ET MALWARE x"),
                ev("qfeeds", 5, action="block", src_ip="192.168.1.6", dst_ip="198.51.100.1"),
                *[ev("zenarmor", 1 + 30 * i, action="block", src_ip="192.168.1.6", domain="c2.example",
                     data={"security": "Malware"}) for i in range(6)],
                ev("zenarmor", 1, action="conn", src_ip="192.168.1.7", domain="p.example", data={"security": "Phishing"}),
                # ordinary categories / app names: no malware
                ev("zenarmor", 1, action="block", src_ip="192.168.1.8", domain="coins.example", data={"security": "Cryptocurrency"}),
                ev("zenarmor", 1, action="block", src_ip="192.168.1.9", domain="ec2.example",
                   data={"security": "", "zen": {"app": "Amazon EC2", "app_category": "Cloud"}})])
            await db.kv_set("wm:zenarmor", 0)
            await DetectionEngine(Settings()).zenarmor_threats()
            a = {r["ip"]: r for r in await alerts(pool, "zenarmor_threat")}
            assert a["192.168.1.6"]["severity"] == "high" and "Zenarmor blocked it" in " ".join(a["192.168.1.6"]["data"]["severity_why"])
            assert a["192.168.1.7"]["severity"] == "critical"  # NOT blocked: still critical
            assert "192.168.1.8" not in a and "192.168.1.9" not in a  # policy blocks, skipped by default
            await pool.execute("TRUNCATE events, alerts")
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_no_blocked_traffic_is_critical():
    from lookingglass import alert_filters
    from lookingglass.detections import Rating, raise_alert

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, alerts, alert_filters, devices")
            alert_filters.invalidate()

            async def sev(fp):
                return await pool.fetchval("SELECT severity FROM alerts WHERE fingerprint = $1", fp)
            await raise_alert("threat_feed", Rating("medium", "listed").up("confirmed", 2), "x", "f:1", src_ip="192.168.1.20",
                              blocked="the connection was blocked")
            await raise_alert("threat_feed", "critical", "x", "f:2", src_ip="192.168.1.21", blocked=True)
            await raise_alert("threat_feed", Rating("critical", "got through", sticky=True), "x", "f:3", src_ip="192.168.1.22")
            assert (await sev("f:1"), await sev("f:2"), await sev("f:3")) == ("high", "high", "critical")
            why = (await pool.fetchval("SELECT data FROM alerts WHERE fingerprint = 'f:1'"))["severity_why"]
            assert why[-1] == "≤ high: the connection was blocked"
            # stored as critical before the cap existed: back to high on the next sighting (sticky ratings keep the max)
            await pool.execute("UPDATE alerts SET severity = 'critical' WHERE fingerprint = 'f:1'")
            await raise_alert("threat_feed", Rating("high", "listed", sticky=True), "x", "f:1", src_ip="192.168.1.20", blocked=True)
            assert await sev("f:1") == "high"
            # your own severity rule still decides
            await pool.execute("INSERT INTO alert_filters (name, rules, action, set_severity) VALUES ('mine', '{dns_malicious_blocked}', 'severity', 'critical')")
            alert_filters.invalidate()
            await raise_alert("dns_malicious_blocked", "medium", "x", "d:1", src_ip="192.168.1.23", blocked=True)
            assert await sev("d:1") == "critical"
            # an internal attack chain built only from blocked alerts: high, not critical
            await pool.execute("TRUNCATE alerts, alert_filters")
            alert_filters.invalidate()
            for rule in ("threat_intel_outbound", "internal_blocked_outbound", "port_scan"):
                await raise_alert(rule, "medium", rule, f"c:{rule}", src_ip="192.168.1.30", blocked=True)
            await DetectionEngine(Settings()).attack_chains()
            a = (await alerts(pool, "attack_chain"))[0]
            assert a["severity"] == "high" and a["data"]["stages"] == ["Threat sign", "Command & control", "Spreading / theft"]
            # one step got through: critical again
            await raise_alert("beaconing", "low", "beacon", "c:beacon", src_ip="192.168.1.30")
            await DetectionEngine(Settings()).attack_chains()
            assert (await alerts(pool, "attack_chain"))[0]["severity"] == "critical"
            await pool.execute("TRUNCATE events, alerts")
        finally:
            await db.close()

    asyncio.run(main())


def test_zenarmor_device_name_skips_ips_and_fingerprint_labels():
    from lookingglass.detections import zen_device_name

    steam = {"name": "Steam OS", "os": "Steam OS", "vendor": "ASUSTek", "category": "Computer"}
    assert zen_device_name({"src_hostname": "Desktop-PB", "device": steam}, "192.168.3.3") == "Desktop-PB"
    assert zen_device_name({"src_hostname": "192.168.3.3", "device": steam}, "192.168.3.3") is None  # IP / OS label
    assert zen_device_name({"src_hostname": "10.0.3.9", "device": {"name": "Living room TV", "os": "Tizen"}},
                           "10.0.3.3") == "Living room TV"
    assert zen_device_name({"src_hostname": "*", "device": {}}, None) is None


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_zenarmor_device_listener_names_devices_without_a_better_source():
    from lookingglass import detections
    from lookingglass.detections import track_devices, zenarmor_device_listener

    def rec(mac, ip, **kw):
        return {"source": "zenarmor", "src_ip": ip, "data": {"src_hwaddr": mac, **kw}}

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE devices")
            detections._zen_seen.clear()
            await track_devices([{"mac": "aa:00:00:00:00:09", "ip": "10.0.3.9", "hostname": "tv-dhcp"}], origin="dhcp")
            # first record without a name, the next one (same batch) has it; the IP as host name is ignored
            await zenarmor_device_listener([
                rec("aa:00:00:00:00:03", "10.0.3.3", src_hostname="10.0.3.3", device={"os": "Android"}),
                rec("aa:00:00:00:00:03", "10.0.3.3", device={"name": "Pixel-7", "os": "Android"}),
                rec("aa:00:00:00:00:09", "10.0.3.9", src_hostname="zen-tv")])
            # a name arriving later is still picked up (no 10-minute wait while there was none)
            await zenarmor_device_listener([rec("aa:00:00:00:00:04", "10.0.3.4", src_hostname="10.0.3.4")])
            await zenarmor_device_listener([rec("aa:00:00:00:00:04", "10.0.3.4", src_hostname="laptop-jo")])
            names = {r["mac"]: (r["hostname"], r["name_source"]) for r in await pool.fetch("SELECT mac, hostname, name_source FROM devices")}
            assert names["aa:00:00:00:00:03"] == ("Pixel-7", "zenarmor")
            assert names["aa:00:00:00:00:04"] == ("laptop-jo", "zenarmor")
            assert names["aa:00:00:00:00:09"] == ("tv-dhcp", "dhcp")  # a better source wins
            await pool.execute("TRUNCATE devices")
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_macless_zenarmor_clients_become_devices():
    """WireGuard clients (no MAC) seen by Zenarmor are listed under their IP."""
    from lookingglass import detections
    from lookingglass.detections import track_devices, zenarmor_device_listener

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE devices, alerts")
            detections._zen_seen.clear()
            await track_devices([{"mac": "aa:00:00:00:00:01", "ip": "192.168.1.5"}], origin="arp")  # not the first run
            # WireGuard clients (no MAC, or a placeholder one), one with a MAC device already on that IP, an internet address
            await zenarmor_device_listener([
                {"source": "zenarmor", "src_ip": "10.10.0.2", "data": {"src_hostname": "pixel-jo", "interface": "wg1"}},
                {"source": "zenarmor", "src_ip": "10.0.3.3", "data": {"src_hwaddr": "00:00:00:00:00:00",
                                                                      "device": {"name": "Wireguard Phone"}}},
                {"source": "zenarmor", "src_ip": "10.0.3.4", "data": {"src_hwaddr": "-", "src_hostname": "tablet"}},
                # the firewall's own interface MAC on a WireGuard interface: still no client MAC
                {"source": "zenarmor", "src_ip": "10.0.3.5", "data": {"src_hwaddr": "a8:b8:e0:01:02:03", "interface": "wg0",
                                                                      "src_hostname": "laptop"}},
                {"source": "zenarmor", "src_ip": "192.168.1.5", "data": {}},
                {"source": "zenarmor", "src_ip": "203.0.113.5", "data": {}}])
            # the ARP table never lists it: it keeps its state
            await track_devices([{"mac": "aa:00:00:00:00:01", "ip": "192.168.1.5"}], origin="arp", mark_online=True)
            d = {r["mac"]: dict(r) for r in await pool.fetch(
                "SELECT mac, host(ip) ip, hostname, name_source, online, interface FROM devices")}
            assert set(d) == {"aa:00:00:00:00:01", "ip:10.10.0.2", "ip:10.0.3.3", "ip:10.0.3.4", "ip:10.0.3.5"}
            assert d["ip:10.0.3.3"]["hostname"] == "Wireguard Phone" and d["ip:10.0.3.4"]["hostname"] == "tablet"
            assert d["ip:10.10.0.2"] == {"mac": "ip:10.10.0.2", "ip": "10.10.0.2", "hostname": "pixel-jo",
                                         "name_source": "zenarmor", "online": True, "interface": "wg1"}
            assert "New device on network: ip:10.10.0.2 (pixel-jo)" in \
                [r["title"] for r in await pool.fetch("SELECT title FROM alerts WHERE rule = 'new_device'")]
            await pool.execute("TRUNCATE devices, alerts")
        finally:
            await db.close()

    asyncio.run(main())


def test_real_mac_skips_placeholders():
    from lookingglass.detections import real_mac

    assert real_mac("E8-9C-25-6E-46-D1") == "e8:9c:25:6e:46:d1"
    for bad in (None, "", "-", "unknown", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "e8:9c:25"):
        assert real_mac(bad) is None


def test_opnsense_own_interfaces_are_named_after_the_interface():
    from lookingglass.opnsense import interface_device, own_address

    lan = {"mac": "a8:b8:e0:00:00:01", "ip": "192.168.1.1", "intf": "igc1", "intf_description": "LAN", "permanent": True,
           "manufacturer": "Intel"}
    iot = {**lan, "ip": "192.168.20.1", "intf": "vlan0.20", "intf_description": "VLAN_IoT", "permanent": False,
           "expires": "permanent"}
    assert own_address(lan) and own_address(iot)
    assert not own_address({"mac": "aa:00:00:00:00:01", "ip": "192.168.1.5", "expires": 1199, "permanent": False})
    d = interface_device("a8:b8:e0:00:00:01", [lan, iot])  # VLANs share the port's MAC
    assert d["hostname"] == "OPNsense (LAN, VLAN_IoT)" and d["name_source"] == "opnsense" and d["ip"] == "192.168.1.1"


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_opnsense_interface_name_replaces_a_guessed_one():
    from lookingglass.detections import track_devices
    from lookingglass.opnsense import interface_device

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE devices")
            mac = "a8:b8:e0:00:00:01"
            await track_devices([{"mac": mac, "ip": "192.168.1.1", "hostname": "router.lan", "name_source": "dns"}], origin="arp")
            await track_devices([interface_device(mac, [{"ip": "192.168.1.1", "intf_description": "LAN"}])], origin="arp")
            assert await pool.fetchval("SELECT hostname FROM devices WHERE mac = $1", mac) == "OPNsense (LAN)"
            await pool.execute("UPDATE devices SET hostname = 'Firewall', name_source = 'manual', name_rank = 100")
            await track_devices([interface_device(mac, [{"ip": "192.168.1.1", "intf_description": "LAN"}])], origin="arp")
            assert await pool.fetchval("SELECT hostname FROM devices WHERE mac = $1", mac) == "Firewall"  # yours wins
            await pool.execute("TRUNCATE devices")
        finally:
            await db.close()

    asyncio.run(main())
