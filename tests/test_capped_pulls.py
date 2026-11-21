"""OPNsense pulls that read "the newest N" per call: they page back to what the previous read got (Suricata across a
rotated eve.json, CrowdSec, Q-Feeds), and note when data had to be left out (Unbound, firewall log)."""
import asyncio
from datetime import datetime, timedelta, timezone

from lookingglass import db
from lookingglass.config import Settings
from lookingglass.opnsense import Poller

T0 = datetime(2026, 11, 19, 10, 0, tzinfo=timezone.utc)


class Writer:
    def __init__(self):
        self.events = []

    def put(self, ev):
        self.events.append(ev)


def poller(monkeypatch, api):
    async def no_snapshot(*a, **kw):
        return None
    monkeypatch.setattr(db, "set_snapshot", no_snapshot)
    p = Poller(Settings(), Writer())
    p.api = api
    return p


class FakeIds:
    """queryAlerts: eve.json newest first, 'current' pages from 1; fileid 0 = the rotated file."""

    def __init__(self):
        self.files = [[]]  # [current, rotated 0], oldest first
        self.n = 0
        self.calls = []

    def alert(self, count=1, step=1):
        for _ in range(count):
            self.n += 1
            ts = T0 + timedelta(seconds=self.n * step)
            self.files[0].append({"timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"), "flow_id": self.n,
                                  "src_ip": "45.9.9.9", "src_port": 4000, "dest_ip": "192.168.1.2", "dest_port": 22,
                                  "proto": "TCP", "alert": f"alert {self.n}", "alert_sid": 1, "alert_action": "allowed"})

    def rotate(self):
        self.files.insert(0, [])

    async def post(self, path, body):
        self.calls.append(body)
        idx = int(body["fileid"]) + 1 if "fileid" in body else 0
        rows = self.files[idx][::-1] if idx < len(self.files) else []
        per, page = body["rowCount"], body["current"]
        return {"rows": rows[(page - 1) * per:page * per], "total": len(rows)}


def uids(p):
    out = {e["uid"] for e in p.writer.events}
    p.writer.events.clear()
    return out


def test_ids_pages_back_to_the_last_read(monkeypatch):
    api = FakeIds()
    p = poller(monkeypatch, api)

    async def main():
        api.alert(100)
        await p.poll_ids()
        first = uids(p)
        assert len(first) == 100
        api.alert(1700)  # a storm: more than one page
        await p.poll_ids()
        got = uids(p)
        assert len(got - first) == 1700  # all new alerts, plus a few repeats from the 10 s margin (stored once by uid)
        assert "dropped" not in p.status.get("ids", {})

    asyncio.run(main())


def test_ids_reads_the_rotated_file(monkeypatch):
    api = FakeIds()
    p = poller(monkeypatch, api)

    async def main():
        api.alert(50, step=30)
        await p.poll_ids()
        seen = uids(p)
        api.alert(20, step=30)  # after the last read ...
        api.rotate()  # ... eve.json rotated
        api.alert(5, step=30)
        await p.poll_ids()
        got = uids(p) - seen
        assert len(got) == 25
        assert any(c.get("fileid") == "0" for c in api.calls)

    asyncio.run(main())


def test_ids_flood_beyond_the_page_limit_is_noted(monkeypatch):
    api = FakeIds()
    p = poller(monkeypatch, api)

    async def main():
        api.alert(10)
        await p.poll_ids()
        api.alert(6000)
        await p.poll_ids()
        assert "skipped" in p.status["ids"]["dropped"]["what"]

    asyncio.run(main())


class FakeSearch:
    """A search endpoint sorted newest first (CrowdSec alerts)."""

    def __init__(self):
        self.rows = []

    def add(self, n):
        base = len(self.rows)
        for i in range(n):
            ts = T0 + timedelta(seconds=base + i)
            self.rows.insert(0, {"id": base + i, "value": "Ip:45.9.9.9", "reason": "x", "created": ts.isoformat()})

    async def search(self, path, rows=500, sort=None, page=1):
        if "decisions" in path:
            return []
        return self.rows[(page - 1) * rows:page * rows]


def test_crowdsec_pages_back(monkeypatch):
    api = FakeSearch()
    p = poller(monkeypatch, api)

    async def main():
        api.add(10)
        await p.poll_crowdsec()
        seen = uids(p)
        api.add(1200)
        await p.poll_crowdsec()
        assert len(uids(p) - seen) == 1200

    asyncio.run(main())


class FakeUnbound:
    def __init__(self):
        self.t = 1_000_000.0
        self.log = []

    def queries(self, n, per_second=10):
        for _ in range(n):
            self.t += 1 / per_second
            self.log.append({"uuid": f"q{len(self.log)}", "time": self.t, "client": "192.168.1.20", "domain": "example.com.",
                             "type": "A", "action": 0, "rcode": 0, "source": 0})

    async def get(self, path, **kw):
        return self.log[::-1][:1000]


def test_unbound_reads_sooner_while_busy_and_notes_gaps(monkeypatch):
    api = FakeUnbound()
    p = poller(monkeypatch, api)
    clock = [100.0]
    monkeypatch.setattr("lookingglass.opnsense.time.monotonic", lambda: clock[0])

    async def main():
        api.queries(200)
        await p.poll_unbound()
        assert p._unbound_next - clock[0] > 30  # quiet: in a minute
        api.queries(900)
        clock[0] += 60
        await p.poll_unbound()
        assert p._unbound_next - clock[0] < 15  # busy: soon
        assert "dropped" not in p.status.get("unbound_queries", {})
        api.queries(2500)  # more than one answer holds
        clock[0] += 15
        await p.poll_unbound()
        assert "not stored" in p.status["unbound_queries"]["dropped"]["what"]
        clock[0] += 5
        api.writer_events = len(p.writer.events)
        await p.poll_unbound()  # not due yet: no read
        assert len(p.writer.events) == api.writer_events

    asyncio.run(main())


class FakeFirewallLog:
    def __init__(self, n):
        self.n = n

    async def get(self, path, **params):
        if "systemTime" in path:
            return {"datetime": "Thu Nov 19 10:00:00 UTC 2026"}
        return [{"__digest__": f"d{self.n}", "__timestamp__": "2026-11-19 10:00:00", "action": "block", "src": "45.9.9.9",
                 "dst": "192.168.1.2", "protoname": "tcp", "srcport": "1", "dstport": "22"}] * min(self.n, params["limit"])


def test_firewall_log_flood_is_noted(monkeypatch):
    p = poller(monkeypatch, FakeFirewallLog(10))
    p.settings.firewall_log_pull = "always"

    async def main():
        await p.poll_firewall_log()
        assert "dropped" not in p.status.get("firewall_log", {})
        p.api.n = 9000
        await p.poll_firewall_log()
        assert "syslog" in p.status["firewall_log"]["dropped"]["what"]

    asyncio.run(main())
