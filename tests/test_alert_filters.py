import asyncio
import os

import pytest

from lookingglass import alert_filters as af
from lookingglass import db

DSN = os.environ.get("TEST_DATABASE_URL")
A = dict(rule="port_scan", severity="low", title="External port scan from 203.0.113.5 (120 ports)",
         description="Severity low: scan from the internet", src_ip="203.0.113.5", dst_ip=None)


def m(**f):
    return af.matches(af.clean(f), **A)


def test_and_or_and_text_modes():
    assert m(max_severity="low", rules=["port_scan"])                     # both match (AND)
    assert not m(max_severity="info", rules=["port_scan"])                # severity too high -> AND fails
    assert m(max_severity="info", rules=["port_scan"], match_mode="any")  # OR: the rule is enough
    assert not m(rules=["brute_force"], networks="10.0.0.0/8", match_mode="any")
    assert m(contains="nothing here, 120 ports")                          # any of the terms (default)
    assert not m(contains="nothing here, 120 ports", text_mode="all")     # all terms
    assert m(contains="PORT SCAN, internet", text_mode="all")             # case insensitive
    assert m(networks="198.51.100.0/24, 203.0.113.0/24") and not m(networks="203.0.114.0/24")
    assert m(rules=["brute_force", "port_scan"])                          # any ticked rule


def test_validation():
    for bad in ({}, {"action": "suppress"}, {"networks": "not-an-ip"}, {"max_severity": "huge"}, {"rules": ["x"], "match_mode": "xor"}):
        with pytest.raises(ValueError):
            af.clean(bad)
    assert af.clean({"contains": " a ,, b "})["contains"] == "a, b"
    with pytest.raises(ValueError):
        af.clean({"rules": ["port_scan"], "action": "severity"})  # no target severity
    assert af.clean({"rules": ["port_scan"], "action": "severity", "set_severity": "high"})["set_severity"] == "high"
    assert af.clean({"rules": ["port_scan"], "set_severity": "high"})["set_severity"] is None  # only for that action


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_filters_stop_or_close_alerts():
    from lookingglass.detections import raise_alert

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, alert_filters")
            await pool.execute("INSERT INTO alert_filters (name, max_severity, rules, action) VALUES "
                               "('noise', 'low', '{port_scan}', 'suppress'), ('keep closed', NULL, '{firmware}', 'close')")
            af.invalidate()
            await raise_alert("port_scan", "low", "External port scan from 203.0.113.9", "ps:1", src_ip="203.0.113.9")
            await raise_alert("port_scan", "high", "External port scan from 203.0.113.10", "ps:2", src_ip="203.0.113.10")
            await raise_alert("firmware", "low", "OPNsense firmware updates available", "firmware")
            rows = {r["fingerprint"]: r["status"] for r in await pool.fetch("SELECT fingerprint, status FROM alerts")}
            assert "ps:1" not in rows and rows["ps:2"] == "open" and rows["firmware"] == "closed"
            hits = {r["name"]: r["hits"] for r in await pool.fetch("SELECT name, hits FROM alert_filters")}
            assert hits == {"noise": 1, "keep closed": 1}
            await pool.execute("TRUNCATE alerts, alert_filters")
            af.invalidate()
        finally:
            await db.close()

    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_severity_rules_come_before_muting():
    from lookingglass.detections import Rating, raise_alert

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, alert_filters")
            # new devices on the IoT network matter to me: high; and mute everything that ends up "info"
            await pool.execute("INSERT INTO alert_filters (name, rules, networks, action, set_severity) VALUES "
                               "('iot', '{new_device}', '192.168.30.0/24', 'severity', 'high'), "
                               "('quiet', '{port_scan}', NULL, 'severity', 'info')")
            await pool.execute("INSERT INTO alert_filters (name, max_severity, action) VALUES ('drop info', 'info', 'suppress')")
            af.invalidate()
            await raise_alert("new_device", Rating("low", "unknown MAC", sticky=True), "New device", "nd:1", src_ip="192.168.30.7")
            await raise_alert("new_device", Rating("low", "unknown MAC", sticky=True), "New device", "nd:2", src_ip="192.168.1.7")
            await raise_alert("port_scan", Rating("medium", "inside"), "Internal port scan", "ps:1", src_ip="192.168.1.9")
            rows = {r["fingerprint"]: r for r in await pool.fetch("SELECT fingerprint, severity, data FROM alerts")}
            assert rows["nd:1"]["severity"] == "high" and rows["nd:1"]["data"]["severity_override"]["from"] == "low"
            assert rows["nd:2"]["severity"] == "low" and "severity_override" not in rows["nd:2"]["data"]
            assert "ps:1" not in rows  # re-rated to info first, then muted by "drop info"
            await pool.execute("TRUNCATE alerts, alert_filters")
            af.invalidate()
        finally:
            await db.close()

    asyncio.run(main())


def test_invalidate_reloads_right_after_boot(monkeypatch):
    # time.monotonic() counts from boot: on a machine up < 60 s, invalidate() must still force a reload
    loads = []

    class Pool:
        async def fetch(self, *a):
            loads.append(1)
            return []

    monkeypatch.setattr(af.db, "pool", lambda: Pool())
    monkeypatch.setattr(af.time, "monotonic", lambda: 30.0)
    af.invalidate()
    asyncio.run(af._filters())
    af.invalidate()
    asyncio.run(af._filters())
    assert len(loads) == 2
    af.invalidate()


def test_port_conditions():
    one = {"dst": [22], "dst_n": 1, "src": [40001, 40002], "src_n": 2}
    two = {"dst": [22, 3389], "dst_n": 2}
    top5 = {"dst": [22, 23, 25, 80, 443], "dst_n": 9}  # 4 more ports the alert did not keep
    f = af.clean({"dst_ports": " 22 8000-8100,3389"})
    assert f["dst_ports"] == "22, 3389, 8000-8100"
    assert af.matches(f, **A, ports=one) and af.matches(f, **A, ports=two)
    assert not af.matches(af.clean({"dst_ports": "22"}), **A, ports=two)    # 3389 too: not hidden by a port-22 mute
    assert not af.matches(af.clean({"dst_ports": "1-1000"}), **A, ports=top5)  # unknown ports: never muted
    assert not af.matches(f, **A) and not af.matches(f, **A, ports={})       # no known ports
    assert af.matches(af.clean({"src_ports": "40000-40010", "dst_ports": "22"}), **A, ports=one)
    assert af.matches(af.clean({"rules": ["brute_force"], "dst_ports": "22", "match_mode": "any"}), **A, ports=one)
    with pytest.raises(ValueError, match="Destination ports: 'ssh'"):
        af.clean({"dst_ports": "ssh"})
    assert af.clean({"dst_ports": "22"})["src_ports"] is None  # a port alone is a condition (not an empty filter)


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_port_filter_mutes_only_alerts_with_those_ports():
    from datetime import datetime, timezone

    from lookingglass.detections import raise_alert
    from lookingglass.parsers.common import event

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, alert_filters, events")
            now = datetime.now(timezone.utc)
            await db.copy_events([event(now, "firewall", severity=6, action="block", src_ip=ip, dst_ip="192.168.1.2", dst_port=p)
                                  for ip, p in (("45.9.9.1", 22), ("45.9.9.1", 22), ("45.9.9.2", 22), ("45.9.9.2", 3389))])
            await pool.execute("INSERT INTO alert_filters (name, rules, dst_ports, action) VALUES ('ssh noise', '{port_scan}', '22', 'suppress')")
            af.invalidate()
            for ip in ("45.9.9.1", "45.9.9.2"):
                await raise_alert("port_scan", "low", f"Scan from {ip}", f"ps:{ip}", src_ip=ip, events={"source": "firewall", "ip": ip})
            assert [r["fingerprint"] for r in await pool.fetch("SELECT fingerprint FROM alerts")] == ["ps:45.9.9.2"]
        finally:
            await db.pool().execute("TRUNCATE alerts, alert_filters, events")
            af.invalidate()
            await db.close()
    asyncio.run(main())
