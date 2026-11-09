"""Q-Feeds blocks from the firewall log lines of its rules (also a LAN rule on an interface group)."""
import asyncio
import os
from datetime import datetime, timezone

import pytest

from lookingglass import dashboards, db
from lookingglass.config import Settings
from lookingglass.detections import DetectionEngine
from lookingglass.parsers import filterlog

DSN = os.environ.get("TEST_DATABASE_URL")
# block in on igc2 192.168.3.3:53334 -> 178.16.54.129:443 TCP, rule "Q-feeds LAN" (LAN interface group)
LAN_LINE = "77,,,qf1,igc2,match,block,in,4,0x0,,64,1,0,none,6,tcp,60,192.168.3.3,178.16.54.129,53334,443,0,S,1,,,,"


def test_qfeeds_rule_lines_are_tagged_and_seen():
    filterlog.BLOCKLIST_RULES.clear()
    filterlog.BLOCKLIST_SEEN.clear()
    filterlog.BLOCKLIST_RULES["qf1"] = "Q-Feeds"
    try:
        ev = filterlog.parse(datetime.now(timezone.utc), "fw", LAN_LINE)
        assert ev["source"] == "firewall" and ev["data"]["blocklist"] == "Q-Feeds"
        assert "q-feeds" in filterlog.BLOCKLIST_SEEN  # the poller then skips the plugin's copies
    finally:
        filterlog.BLOCKLIST_RULES.clear()
        filterlog.BLOCKLIST_SEEN.clear()


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_qfeeds_lan_rule_blocks_count_and_alert():
    async def main():
        await db.connect(DSN)
        filterlog.BLOCKLIST_RULES["qf1"] = "Q-Feeds"
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE events, alerts")
            await pool.execute("DELETE FROM snapshots WHERE key = 'blocklists'")
            await db.copy_events([filterlog.parse(datetime.now(timezone.utc), "fw", LAN_LINE)])
            # one rule (IPv4 + IPv6, interface group) is several pf rules with the same id: counted once
            await db.set_snapshot("blocklists", {"q-feeds": {"name": "Q-Feeds", "aliases": ["__qfeeds_*"], "size": 10,
                                                             "rules": [{"rid": "qf1"}, {"rid": "qf1"}, {"rid": "qf2"}, {"rid": "qf2"}],
                                                             "rids": ["qf1", "qf2"], "packets": 5}})
            qf = await dashboards.run_dashboard("threats", 24, tab="qfeeds")
            by = {p["id"]: p for p in qf["panels"]}
            kpi = by["qf_kpi"]["rows"][0]
            assert kpi["Hits"] == 1 and kpi["Outbound"] == 1 and kpi["Inbound"] == 0 and kpi["Internal hosts"] == 1
            assert by["qf"]["rows"][0]["dir"] == "out"  # logged "in" on the LAN interface, but it is outgoing
            main_tab = {p["id"]: p for p in (await dashboards.run_dashboard("threats", 24))["panels"]}
            assert main_tab["kpi"]["rows"][0]["Q-Feeds hits"] == 1
            assert {r["series"] for r in main_tab["src"]["rows"]} == {"qfeeds"}  # not CrowdSec
            assert main_tab["blocklists"]["rows"][0]["rules"] == 2
            await DetectionEngine(Settings()).qfeeds_hits()
            rows = await pool.fetch("SELECT rule, src_ip FROM alerts")
            assert [(r["rule"], str(r["src_ip"])) for r in rows] == [("threat_intel_outbound", "192.168.3.3")]
        finally:
            filterlog.BLOCKLIST_RULES.clear()
            await db.pool().execute("TRUNCATE events, alerts")
            await db.pool().execute("DELETE FROM snapshots WHERE key = 'blocklists'")
            await db.close()
    asyncio.run(main())


def test_qfeeds_poll_skips_plugin_copies_while_rule_lines_arrive(monkeypatch):
    import time
    from lookingglass.opnsense import Poller

    class FakeApi:
        async def search(self, path, **kw):
            return [{"timestamp": "2026-11-09T00:57:23", "source": "192.168.3.3", "destination": "178.16.54.129",
                     "source_port": "53334", "destination_port": "443", "interface": "lan", "direction": "out"}]

        async def get(self, path, **kw):
            return {}

    class Writer:
        def __init__(self):
            self.events = []

        def put(self, ev):
            self.events.append(ev)

    async def no_snapshot(*a, **kw):
        return None
    monkeypatch.setattr(db, "set_snapshot", no_snapshot)

    async def run():
        p = object.__new__(Poller)
        p.settings, p.api, p.writer = Settings(), FakeApi(), Writer()
        p.local_ts = lambda s: datetime.now(timezone.utc)
        filterlog.BLOCKLIST_SEEN.clear()
        await p.poll_qfeeds()  # no tagged log lines: the plugin's events are stored, tagged
        assert len(p.writer.events) == 1 and p.writer.events[0]["data"]["blocklist"] == "Q-Feeds"
        filterlog.BLOCKLIST_SEEN["q-feeds"] = time.time()
        await p.poll_qfeeds()  # tagged log lines arrive: the plugin's copies would count them twice
        assert len(p.writer.events) == 1
        filterlog.BLOCKLIST_SEEN.clear()

    asyncio.run(run())
