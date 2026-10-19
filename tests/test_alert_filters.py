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
