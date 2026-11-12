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
            await db.copy_events([ev("firewall", 1, action="pass", src_ip="192.168.1.61", dst_ip="8.8.8.8", dst_port=53),
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
def test_blocked_threat_traffic_is_low_unless_repeated_or_confirmed():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, alerts")
            # a single blocked visit: Q-Feeds did its job - low
            evs = [ev("qfeeds", 1, action="block", src_ip="192.168.1.8", dst_ip="91.92.1.1", dst_port=443)]
            # calling home: many blocked attempts / many different threat targets
            evs += [ev("qfeeds", 2 + 30 * i, action="block", src_ip="192.168.1.6", dst_ip="91.92.2.1", dst_port=443)
                    for i in range(6)]  # every 30 minutes for 3 hours
            evs += [ev("qfeeds", 2, action="block", src_ip="192.168.1.9", dst_ip=f"91.92.1.{i}", dst_port=443) for i in range(5)]
            # confirmed by two other sources
            evs += [ev("suricata", 2, action="alert", src_ip="192.168.1.10", data={"priority": 1}),
                    ev("qfeeds", 1, action="block", src_ip="192.168.1.10", dst_ip="91.92.3.1", dst_port=443)]
            await db.copy_events(evs)
            await raise_alert("dns_tunneling", "medium", "x", "t:1", src_ip="192.168.1.10")
            await db.kv_set("wm:qfeeds", 0)
            await DetectionEngine(Settings()).qfeeds_hits()
            sev = {r["ip"]: r["severity"] for r in await pool.fetch(
                "SELECT host(src_ip) ip, severity FROM alerts WHERE rule = 'threat_intel_outbound'")}
            assert sev == {"192.168.1.8": "low", "192.168.1.6": "medium", "192.168.1.9": "medium", "192.168.1.10": "high"}
            why = await pool.fetchval("SELECT description FROM alerts WHERE host(src_ip) = '192.168.1.6'")
            assert "working as intended" in why and "in 6 separate 10-minute periods" in why
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


def test_opnsense_own_interfaces_are_named_after_the_interface():
    from lookingglass.opnsense import (
        interface_device,
        interface_key,
        main_interface,
        own_address,
    )

    lan = {"mac": "A8:B8:E0:00:00:01", "ip": "192.168.1.1", "intf": "igc1", "intf_description": "LAN", "permanent": True,
           "manufacturer": "Intel"}
    iot = {**lan, "ip": "192.168.20.1", "intf": "vlan0.20", "intf_description": "VLAN_IoT", "permanent": False,
           "expires": "permanent"}
    assert own_address(lan) and own_address(iot)
    assert not own_address({"mac": "aa:00:00:00:00:01", "ip": "192.168.1.5", "expires": 1199, "permanent": False})
    # VLANs share the port's MAC: one device per interface
    d, v = interface_device([lan]), interface_device([iot])
    assert (d["mac"], d["hwaddr"], d["hostname"], d["ip"]) == ("if:igc1", "a8:b8:e0:00:00:01", "OPNsense (LAN)", "192.168.1.1")
    assert (v["mac"], v["hostname"], v["ips"]) == ("if:vlan0.20", "OPNsense (VLAN_IoT)", ["192.168.20.1"])
    assert main_interface([interface_key(iot), interface_key(lan)]) == "if:igc1"
    assert main_interface(["if:igc1.20", "if:igc1"]) == "if:igc1"


def test_opnsense_tunnel_interfaces_from_interface_statistics():
    """WireGuard / OpenVPN interfaces have no ARP entries: their addresses come from the interface statistics."""
    from lookingglass.opnsense import addressless_interfaces

    stats = {"[LAN] (igc1) / 192.168.1.1": {"name": "igc1", "address": "192.168.1.1", "received-bytes": 1},
             "[WireGuard] (wg1) / Link#9": {"name": "wg1", "address": "Link#9", "received-bytes": 1},
             "[WireGuard] (wg1) / 10.0.3.1": {"name": "wg1", "address": "10.0.3.1", "received-bytes": 1},
             "[WireGuard] (wg1) / fe80::1%wg1": {"name": "wg1", "address": "fe80::1", "received-bytes": 1},
             "[Loopback] (lo0) / 127.0.0.1": {"name": "lo0", "address": "127.0.0.1", "received-bytes": 1}}
    devs = addressless_interfaces(stats, {"igc1"})
    assert [(d["mac"], d["hostname"], d["ips"], d["hwaddr"]) for d in devs] == \
        [("if:wg1", "OPNsense (WireGuard)", ["10.0.3.1"], None)]
    assert addressless_interfaces(None, set()) == []


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_opnsense_interface_name_replaces_a_guessed_one():
    from lookingglass.detections import track_devices
    from lookingglass.opnsense import interface_device

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE devices")
            lan = {"mac": "a8:b8:e0:00:00:01", "ip": "192.168.1.1", "intf": "igc1", "intf_description": "LAN"}
            await track_devices([{"mac": "if:igc1", "ip": "192.168.1.1", "hostname": "router.lan", "name_source": "dns"}],
                                origin="arp")
            await track_devices([interface_device([lan])], origin="arp")
            assert await pool.fetchval("SELECT hostname FROM devices WHERE mac = 'if:igc1'") == "OPNsense (LAN)"
            await pool.execute("UPDATE devices SET hostname = 'Firewall', name_source = 'manual', name_rank = 100")
            await track_devices([interface_device([lan])], origin="arp")
            assert await pool.fetchval("SELECT hostname FROM devices WHERE mac = 'if:igc1'") == "Firewall"  # yours wins
            await pool.execute("TRUNCATE devices")
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_opnsense_interfaces_are_separate_and_absorb_their_entries():
    """The port and its VLAN are separate devices. Each takes over what was learned under its addresses, the port the
    device an older version kept under the shared MAC - learned behaviour moves along."""
    from lookingglass.behavior import Behavior
    from lookingglass.detections import device_info, track_devices
    from lookingglass.opnsense import absorb_into_interfaces, interface_device

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE devices, device_profile, device_hourly")
            mac = "64:62:66:21:4a:79"
            await track_devices([{"mac": mac, "ip": "192.168.2.1", "ips": ["192.168.2.1", "192.168.20.1"],
                                  "hostname": "OPNsense (LAN_2_WLAN, VLAN_IoT)", "name_source": "opnsense"}], origin="arp")
            await pool.execute("INSERT INTO device_profile (key, kind, value, hits) VALUES "
                               "($1, 'port', '53', 3), ('192.168.20.1', 'port', '53', 2), ('192.168.20.1', 'country', 'NL', 1)",
                               mac)
            base = {"mac": mac, "permanent": True}
            own = [interface_device([{**base, "ip": "192.168.2.1", "intf": "igc1", "intf_description": "LAN_2_WLAN"}]),
                   interface_device([{**base, "ip": "192.168.20.1", "intf": "vlan0.20", "intf_description": "VLAN_IoT"}])]
            await track_devices(own, origin="arp")
            await absorb_into_interfaces(own)
            rows = {r["mac"]: (r["ip"], r["hostname"], r["hwaddr"]) for r in
                    await pool.fetch("SELECT mac, host(ip) ip, hostname, hwaddr FROM devices")}
            assert rows == {"if:igc1": ("192.168.2.1", "OPNsense (LAN_2_WLAN)", mac),
                            "if:vlan0.20": ("192.168.20.1", "OPNsense (VLAN_IoT)", mac)}
            prof = {(r["key"], r["kind"], r["value"]): r["hits"] for r in
                    await pool.fetch("SELECT key, kind, value, hits FROM device_profile")}
            assert prof == {("if:igc1", "port", "53"): 3, ("if:vlan0.20", "port", "53"): 2,
                            ("if:vlan0.20", "country", "NL"): 1}
            assert (await device_info("192.168.20.1"))["hostname"] == "OPNsense (VLAN_IoT)"
            assert (await Behavior(Settings(), lambda ip: True).ip_to_mac())["192.168.20.1"]["mac"] == "if:vlan0.20"
            await pool.execute("TRUNCATE devices, device_profile, device_hourly")
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_device_upkeep_removal():
    from lookingglass.detections import device_upkeep, track_devices
    from lookingglass.web.app import create_app

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE devices, device_profile, device_hourly")
            await track_devices([{"mac": m, "ip": f"192.168.1.{i}", "online": True} for i, m in enumerate(
                ["aa:00:00:00:00:01", "aa:00:00:00:00:02", "aa:00:00:00:00:03", "aa:00:00:00:00:04", "aa:00:00:00:00:05",
                 "if:igc1"], 1)], origin="arp")
            old = "now() - interval '40 days'"
            await pool.execute(f"UPDATE devices SET last_seen = {old} WHERE mac <> 'aa:00:00:00:00:05'")
            await pool.execute("UPDATE devices SET trusted = true WHERE mac = 'aa:00:00:00:00:02'")
            await pool.execute("UPDATE devices SET hostname = 'Mine', name_source = 'manual', name_rank = 100 WHERE mac = 'aa:00:00:00:00:03'")
            await pool.execute("UPDATE devices SET notes = 'spare laptop' WHERE mac = 'aa:00:00:00:00:04'")
            await pool.execute("INSERT INTO device_profile (key, kind, value) VALUES ('aa:00:00:00:00:01', 'port', '443')")
            # 0 = never remove
            assert await device_upkeep(0) == 0
            # 30 days: the unknown old one goes (also what was learned); trusted / named / notes / interfaces / recent stay
            assert await device_upkeep(30) == 1
            left = {r["mac"] for r in await pool.fetch("SELECT mac FROM devices")}
            assert left == {"aa:00:00:00:00:02", "aa:00:00:00:00:03", "aa:00:00:00:00:04", "aa:00:00:00:00:05", "if:igc1"}
            assert await pool.fetchval("SELECT count(*) FROM device_profile") == 0
            # the Delete button
            ep = next(r.endpoint for r in create_app(Settings(), None).routes
                      if getattr(r, "path", "") == "/api/devices/{mac}" and "DELETE" in getattr(r, "methods", set()))
            await ep("AA:00:00:00:00:05")
            assert "aa:00:00:00:00:05" not in {r["mac"] for r in await pool.fetch("SELECT mac FROM devices")}
            await pool.execute("TRUNCATE devices, device_profile, device_hourly")
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_deleted_device_not_brought_back_by_its_old_lease():
    from lookingglass.detections import delete_devices, track_devices

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE devices, device_profile, device_hourly")
            await pool.execute("DELETE FROM kv WHERE key = 'devices:dismissed'")
            gone, kept = "aa:00:00:00:00:31", "aa:00:00:00:00:32"
            lease = lambda mac, exp: {"mac": mac, "ip": "192.168.1.31", "hostname": "old-phone", "lease_expires": exp}  # noqa: E731
            await track_devices([lease(gone, "1767000000"), lease(kept, "1767000000")], origin="dhcp-dnsmasq")
            await delete_devices([gone])
            macs = lambda: pool.fetch("SELECT mac FROM devices")  # noqa: E731
            # OPNsense still lists the same lease: it stays gone
            await track_devices([lease(gone, "1767000000"), lease(kept, "1767000000")], origin="dhcp-dnsmasq")
            assert {r["mac"] for r in await macs()} == {kept}
            # the lease was renewed: the device is really back
            await track_devices([lease(gone, "1767090000")], origin="dhcp-dnsmasq")
            assert gone in {r["mac"] for r in await macs()}
            # deleted again, then seen in the ARP table: back too, and the old lease no longer hides it
            await delete_devices([gone])
            await track_devices([{"mac": gone, "ip": "192.168.1.31"}], origin="arp")
            assert gone in {r["mac"] for r in await macs()}
            assert gone not in (await db.kv_get("devices:dismissed") or {})
            await pool.execute("TRUNCATE devices, device_profile, device_hourly")
            await pool.execute("DELETE FROM kv WHERE key = 'devices:dismissed'")
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_attack_chain_needs_a_strong_link_and_skips_known_alerts():
    from lookingglass.detections import evidence

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, alerts, alert_filters, devices")

            async def add(rule, sev, ip, status="open", reason=None, fp=None):
                await pool.execute("INSERT INTO alerts (rule, severity, title, fingerprint, src_ip, status, close_reason) "
                                   "VALUES ($1, $2, $1, $3, $4::inet, $5, $6)", rule, sev, fp or f"{rule}:{ip}:{status}", ip,
                                   status, reason)

            async def chains():
                await DetectionEngine(Settings()).attack_chains()
                return {c["ip"] for c in await alerts(pool, "attack_chain")}

            # NTP every 9 min + a Steam download, lifted to medium by each other: no "compromised device"
            await add("beaconing", "medium", "192.168.3.3")
            await add("volume_spike", "medium", "192.168.3.3")
            assert await chains() == set()
            # a behaviour alert rated high (more than the other alert's lift) is a strong link
            await pool.execute("UPDATE alerts SET severity = 'high' WHERE rule = 'volume_spike'")
            assert await chains() == {"192.168.3.3"}
            await pool.execute("TRUNCATE alerts")

            # a real sign of compromise is enough, even at low severity
            await add("beaconing", "low", "192.168.3.4")
            await add("lateral_movement", "low", "192.168.3.4")
            # acknowledged: you know it, it no longer builds a chain (nor counts as corroboration)
            await add("beaconing", "low", "192.168.3.5")
            await add("lateral_movement", "high", "192.168.3.5", status="acknowledged")
            # the same rule for the same address closed as false positive: skipped while it keeps coming back
            await add("beaconing", "low", "192.168.3.6", status="closed", reason="false_positive")
            await add("beaconing", "low", "192.168.3.6", fp="beacon:new")
            await add("port_scan", "medium", "192.168.3.6")
            # ... but closed as resolved still counts
            await add("beaconing", "low", "192.168.3.7", status="closed", reason="resolved")
            await add("beaconing", "low", "192.168.3.7", fp="beacon:new7")
            await add("port_scan", "medium", "192.168.3.7")
            assert await chains() == {"192.168.3.4", "192.168.3.7"}
            assert (await evidence("192.168.3.5", "beaconing"))["other_alerts"] == []
            assert (await evidence("192.168.3.4", "beaconing"))["other_alerts"] == ["lateral_movement"]
            await pool.execute("TRUNCATE events, alerts")
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_suricata_alerts_like_crowdsec_and_qfeeds():
    """A signature that fires is no alert on its own: internet addresses only once they keep at it, devices inside
    only for a priority-1 hit that got through, or when it repeats / other sources confirm it."""
    def ids(minutes, src, sig, prio=3, action="alert", dst="198.51.100.1"):
        return event(NOW - timedelta(minutes=minutes), "suricata", severity={1: 2, 2: 3, 3: 4}[prio], action=action,
                     src_ip=src, dst_ip=dst, message=sig, data={"priority": prio})

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, alerts, devices")
            evs = [
                # internet: a few dropped hits -> nothing; 25 hits -> one alert for the address
                *[ids(1, "203.0.113.5", "ET SCAN x", action="drop", dst="192.168.1.2") for _ in range(5)],
                *[ids(1 + i, "203.0.113.6", f"ET SCAN {i % 3}", action="drop", dst="192.168.1.2") for i in range(25)],
                # inside: a policy signature once, a dropped priority-1 once -> nothing
                ids(1, "192.168.1.20", "ET POLICY Dropbox", prio=2),
                ids(1, "192.168.1.21", "ET MALWARE x", prio=1, action="drop"),
                # inside: priority 1 NOT dropped -> high
                ids(1, "192.168.1.22", "ET MALWARE y", prio=1),
                # inside: the same info signature every 30 minutes -> repeated -> medium
                *[ids(1 + 30 * i, "192.168.1.23", "ET INFO z") for i in range(6)],
                # TLS / JA4 records are no signature hits
                *[event(NOW, "suricata", severity=6, action="tls", src_ip="203.0.113.7", dst_ip="192.168.1.2",
                        message="TLS a.example 1.3") for _ in range(30)],
            ]
            await db.copy_events(evs)
            await db.kv_set("wm:ids", 0)
            await DetectionEngine(Settings()).ids_alerts()
            got = {r["ip"]: (r["severity"], r["count"]) for r in await pool.fetch(
                "SELECT host(src_ip) ip, severity, count FROM alerts WHERE rule = 'ids'")}
            assert got == {"203.0.113.6": ("info", 25), "192.168.1.22": ("high", 1), "192.168.1.23": ("medium", 6)}
            await pool.execute("TRUNCATE events, alerts")
        finally:
            await db.close()

    asyncio.run(main())


def test_wireguard_peer_tunnel_addresses():
    from lookingglass.detections import wireguard_ips

    assert wireguard_ips("fd00::2/128, 10.8.0.2/32") == ["10.8.0.2", "fd00::2"]
    assert wireguard_ips(["10.8.0.3/32", "192.168.50.0/24"]) == ["10.8.0.3"]  # a routed network is no address of its own
    assert wireguard_ips("10.8.0.4") == ["10.8.0.4"]
    assert wireguard_ips(None) == [] and wireguard_ips("0.0.0.0/0") == []


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_wireguard_peers_become_devices_named_by_dnsmasq_hosts():
    """WireGuard peers (no MAC, in no lease or ARP table) are listed from the WireGuard status: named by your dnsmasq
    Hosts entry for the tunnel IP, else the peer name; online / offline from the status; no 'new device' alert."""
    from lookingglass.detections import device_info, track_devices
    from lookingglass.opnsense import Poller

    p = Poller.__new__(Poller)
    p._static_names = {"10.8.0.2": "phone-jo", "aa:00:00:00:00:01": "nas"}

    def peer(name, allowed, status):
        return {"type": "peer", "name": name, "if": "wg0", "ifname": "HomeVPN", "allowed-ips": allowed,
                "peer-status": status}

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE devices, alerts")
            await track_devices([{"mac": "aa:00:00:00:00:01", "ip": "192.168.1.5"}], origin="arp")  # not the first run
            await p._track_peers([peer("Phone", "10.8.0.2/32", "online"), peer("Laptop", "10.8.0.3/32,fd00::3/128", "offline"),
                                  peer("Site B", "192.168.50.0/24", "online")])
            d = {r["mac"]: dict(r) for r in await pool.fetch(
                "SELECT mac, host(ip) ip, hostname, name_source, online, interface FROM devices WHERE mac LIKE 'wg:%'")}
            assert d == {"wg:10.8.0.2": {"mac": "wg:10.8.0.2", "ip": "10.8.0.2", "hostname": "phone-jo",
                                         "name_source": "dnsmasq-static", "online": True, "interface": "HomeVPN"},
                         "wg:10.8.0.3": {"mac": "wg:10.8.0.3", "ip": "10.8.0.3", "hostname": "Laptop",
                                         "name_source": "wireguard", "online": False, "interface": "HomeVPN"}}
            assert (await device_info("10.8.0.2"))["hostname"] == "phone-jo"  # what alerts show
            assert await pool.fetchval("SELECT count(*) FROM alerts WHERE rule = 'new_device'") == 0
            # the ARP table never lists them: they keep their state; the next status flips it
            await track_devices([{"mac": "aa:00:00:00:00:01", "ip": "192.168.1.5"}], origin="arp", mark_online=True)
            assert await pool.fetchval("SELECT online FROM devices WHERE mac = 'wg:10.8.0.2'")
            await pool.execute("UPDATE devices SET last_seen = now() - interval '3 days' WHERE mac = 'wg:10.8.0.3'")
            await p._track_peers([peer("Phone", "10.8.0.2/32", "offline"), peer("Laptop", "10.8.0.3/32", "offline")])
            r = {x["mac"]: x for x in await pool.fetch("SELECT mac, online, last_seen < now() - interval '1 day' old "
                                                       "FROM devices WHERE mac LIKE 'wg:%'")}
            assert not r["wg:10.8.0.2"]["online"] and r["wg:10.8.0.3"]["old"]  # offline: last seen stays
            # your own name wins over the Hosts entry
            await pool.execute("UPDATE devices SET hostname = 'Mine', name_source = 'manual', name_rank = 100 "
                               "WHERE mac = 'wg:10.8.0.2'")
            await p._track_peers([peer("Phone", "10.8.0.2/32", "online")])
            assert await pool.fetchval("SELECT hostname FROM devices WHERE mac = 'wg:10.8.0.2'") == "Mine"
            assert not await pool.fetchval("SELECT online FROM devices WHERE mac = 'wg:10.8.0.3'")
            await pool.execute("TRUNCATE devices, alerts")
        finally:
            await db.close()

    asyncio.run(main())
