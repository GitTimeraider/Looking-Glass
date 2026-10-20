import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest

from lookingglass import db
from lookingglass.config import Settings
from lookingglass.detections import DetectionEngine, login_target
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
            assert await run("all") == [("Database", "low"), ("Malware", "high"), ("Phishing", "critical")]
            assert await run("threats") == [("Malware", "high"), ("Phishing", "critical")]   # the default
            assert await run("never") == [("Phishing", "critical")]                           # not blocked: always
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
            assert a["192.168.30.6"]["severity"] == "high" and "Phishing" in a["192.168.30.6"]["title"]
            # default (threats only): the policy block is skipped, the phishing lookup still alerts
            await pool.execute("TRUNCATE alerts")
            await db.kv_set("wm:zenarmor", 0)
            await DetectionEngine(Settings()).zenarmor_threats()
            assert [r["ip"] for r in await pool.fetch("SELECT host(src_ip) ip FROM alerts")] == ["192.168.30.6"]
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
        finally:
            await db.close()
    asyncio.run(main())
