"""UniFi Network 11 system log: every page is read, polls overlap a little and an event is handled once."""
import asyncio
import time

from lookingglass.config import Settings
from lookingglass.unifi import UnifiPoller


class FakeConsole:
    major, prefix, site = 11, "/proxy/network", "default"

    def __init__(self):
        self.log: list[dict] = []  # newest first, as the console answers
        self.bodies: list[dict] = []

    def add(self, n, at=None):
        base = len(self.log)
        for i in range(n):
            self.log.insert(0, {"id": f"e{base + i}", "timestamp": int(((at or time.time()) - 1) * 1000), "key": "CLIENT_CONNECTED",
                                "message": f"event {base + i}", "severity": "LOW"})

    async def _req(self, method, path, json=None):
        self.bodies.append(json)
        rows = [e for e in self.log if json["timestampFrom"] <= e["timestamp"] <= json["timestampTo"]]
        page = rows[json["pageNumber"] * json["pageSize"]:(json["pageNumber"] + 1) * json["pageSize"]]
        return {"data": page, "page_number": json["pageNumber"], "total_element_count": len(rows),
                "total_page_count": -(-len(rows) // json["pageSize"])}


class Writer:
    def __init__(self):
        self.events = []

    def put(self, ev):
        self.events.append(ev)


def test_system_log_reads_every_page_and_handles_each_event_once():
    p = UnifiPoller(Settings(), Writer())
    p.client = FakeConsole()

    async def main():
        p.client.add(650)
        await p.poll_events([], [])
        assert len(p.writer.events) == 650 and len(p.client.bodies) == 4  # 200 + 200 + 200 + 50
        assert "warning" not in p.status["sections"]["events"]
        p.writer.events.clear()
        p.client.add(3)
        await p.poll_events([], [])  # the overlap brings the last events again: not handled twice
        assert sorted(e["uid"].rsplit(":", 1)[1] for e in p.writer.events) == ["e650", "e651", "e652"]
        p.writer.events.clear()
        late = time.time() - 60  # logged late by the console, with a time inside the previous window
        p.client.add(1, at=late)
        await p.poll_events([], [])
        assert [e["uid"].rsplit(":", 1)[1] for e in p.writer.events] == ["e653"]

    asyncio.run(main())


def test_system_log_flood_warns():
    p = UnifiPoller(Settings(), Writer())
    p.client = FakeConsole()
    p.EVENT_PAGES = 2

    async def main():
        p.client.add(450)
        await p.poll_events([], [])
        assert len(p.writer.events) == 400
        assert "skipped" in p.status["sections"]["events"]["warning"]

    asyncio.run(main())
