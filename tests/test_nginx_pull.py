"""poll_nginx: quiet logs are read less often, the server lists are cached (every read is a configd action)."""
import asyncio

from lookingglass.config import Settings
from lookingglass.opnsense import ApiError, Poller


class FakeApi:
    def __init__(self):
        self.calls: list[str] = []
        self.lines = {"web": [{"time": "1"}], "api": [{"time": "1"}]}

    async def get(self, path, **_):
        self.calls.append(path)
        if path == "nginx/logs/accesses":
            return [{"id": "web", "server_name": "www.example.com"}, {"id": "api", "server_name": "api.example.com"}]
        if path in ("nginx/logs/errors", "nginx/logs/streamaccesses"):
            raise ApiError(404, "no such log")
        sid = path.split("/")[3]
        return {"pages": 1, "lines": list(self.lines[sid])}


class Writer:
    def __init__(self):
        self.events = []

    def put(self, ev):
        self.events.append(ev)


def test_nginx_pull_backs_off_on_quiet_logs(monkeypatch):
    p = Poller(Settings(), Writer())
    p.api = FakeApi()
    clock = [1000.0]
    monkeypatch.setattr("lookingglass.opnsense.time.monotonic", lambda: clock[0])
    reads = lambda: [c for c in p.api.calls if c.count("/") > 3]  # noqa: E731

    async def minute():
        p.api.calls.clear()
        await p.poll_nginx()
        clock[0] += 60

    async def main():
        await minute()  # first round: lists + both logs
        assert p.api.calls[:1] == ["nginx/logs/accesses"] and len(reads()) == 2
        assert "nginx/logs/errors" in p.api.calls  # asked once, then not for an hour
        await minute()  # nothing new yet: both read again (60 s), unchanged -> next in 120 s
        assert len(reads()) == 2 and p.api.calls[0] != "nginx/logs/accesses"  # list cached
        assert "nginx/logs/errors" not in p.api.calls
        await minute()  # both waiting
        assert reads() == []
        p.api.lines["web"].append({"time": "2"})  # web gets traffic
        await minute()  # both due (120 s): web changed, api unchanged -> api next in 240 s
        assert len(reads()) == 2
        await minute()  # web every minute again, api waits
        assert reads() == ["nginx/logs/accesses/web/-1/1/1000"]
        for _ in range(30):  # api backs off up to 10 minutes, web (unchanged now) too
            await minute()
        assert p._nginx_logs["accesses/api"]["every"] == Poller.NGINX_MAX_EVERY
        assert p._nginx_logs["accesses/web"]["every"] == Poller.NGINX_MAX_EVERY
        p.api.lines["api"].append({"time": "3"})
        for waited in range(11):  # read within 10 minutes; new lines: back to every minute
            await minute()
            if "nginx/logs/accesses/api/-1/1/1000" in reads():
                break
        assert waited <= 10 and p._nginx_logs["accesses/api"]["every"] == Poller.NGINX_EVERY

    asyncio.run(main())


def test_nginx_pull_reads_far_less_than_before(monkeypatch):
    """10 quiet servers, an hour: was 1 list + 10 reads every minute (660), now a fraction."""
    p = Poller(Settings(), Writer())
    api = FakeApi()
    servers = [{"id": f"s{i}", "server_name": f"s{i}"} for i in range(10)]
    api.lines = {s["id"]: [{"time": "1"}] for s in servers}

    async def get(path, **_):
        api.calls.append(path)
        if path == "nginx/logs/accesses":
            return servers
        if path.count("/") == 2:
            raise ApiError(404, "no such log")
        return {"pages": 1, "lines": api.lines[path.split("/")[3]]}
    api.get = get
    p.api = api
    clock = [0.0]
    monkeypatch.setattr("lookingglass.opnsense.time.monotonic", lambda: clock[0])

    async def main():
        for _ in range(60):
            await p.poll_nginx()
            clock[0] += 60

    asyncio.run(main())
    assert len(api.calls) < 150, len(api.calls)
