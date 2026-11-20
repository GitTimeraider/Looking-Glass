"""poll_nginx against a fake os-nginx log API that answers like the real one (scripts/nginx/read_log.php +
LogParserBase.php): newest line first, pages counted from 0, "total" = lines in the file, fileno -1 = the current
file and 0 = the newest rotated one. Quiet logs are read less often and the server lists are cached (every read is
a configd action)."""
import asyncio

from lookingglass.config import Settings
from lookingglass.opnsense import ApiError, Poller


class FakeOpnsense:
    """Log files per server id, oldest line first as on disk; files[sid][0] is the current file, [1] rotation 0."""

    def __init__(self, servers=("web", "api")):
        self.calls: list[str] = []
        self.servers = list(servers)
        self.files = {sid: [[]] for sid in self.servers}
        self.n = 0

    def write(self, sid, count=1):
        if self.files[sid][0] is None:  # nginx creates the file on the first request after a rotation
            self.files[sid][0] = []
        for _ in range(count):
            self.n += 1
            self.files[sid][0].append({"remote_ip": "198.51.100.1", "time": f"t{self.n}", "request_line": f"GET /{self.n} HTTP/1.1",
                                       "status": "200", "size": "1"})

    def rotate(self, sid, created=False):
        self.files[sid].insert(0, [] if created else None)

    async def get(self, path, **_):
        self.calls.append(path)
        if path == "nginx/logs/accesses":
            return [{"id": s, "server_name": f"{s}.example.com"} for s in self.servers]
        if path.count("/") == 2:
            raise ApiError(404, "no such log")
        _, _, _, sid, fileno, page, per = path.split("/")
        idx = 0 if int(fileno) < 0 else int(fileno) + 1
        if idx >= len(self.files[sid]) or self.files[sid][idx] is None:
            return {"error": "cannot retrieve requested logs"}
        lines = self.files[sid][idx][::-1]  # newest first
        page, per = int(page), int(per)
        return {"lines": lines[page * per:(page + 1) * per], "pages": -(-len(lines) // per), "total": len(lines),
                "found": len(lines), "returned": len(lines[page * per:(page + 1) * per])}


class Writer:
    def __init__(self):
        self.events = []

    def put(self, ev):
        self.events.append(ev)


def setup(monkeypatch, servers=("web", "api")):
    p = Poller(Settings(), Writer())
    p.api = FakeOpnsense(servers)
    clock = [1000.0]
    monkeypatch.setattr("lookingglass.opnsense.time.monotonic", lambda: clock[0])

    async def minute():
        p.api.calls.clear()
        await p.poll_nginx()
        clock[0] += 60

    return p, minute


def paths(p):
    return [e["data"]["path"] for e in p.writer.events]


def test_nginx_pull_gets_the_newest_lines_every_minute(monkeypatch):
    """The bug: page 1 is the SECOND page (lines 1000-1999 counting from the newest), so the newest 1000 lines of
    every log were never read - a busy log lagged by 1000 lines, a quiet one by days, a fresh one not at all."""
    p, minute = setup(monkeypatch, servers=("web",))
    p.api.write("web", 1500)

    async def main():
        await minute()
        assert len(p.writer.events) == 1500 and paths(p)[-1] == "/1500"  # all, oldest first, newest included
        for i in range(5):
            p.writer.events.clear()
            p.api.write("web", 3)
            await minute()
            assert paths(p) == [f"/{1501 + 3 * i + k}" for k in range(3)]  # exactly the new lines, none again
            assert p.api.calls == [f"nginx/logs/accesses/web/-1/0/{Poller.NGINX_PAGE}"]  # one read

    asyncio.run(main())


def test_nginx_pull_a_burst_bigger_than_a_page(monkeypatch):
    p, minute = setup(monkeypatch, servers=("web",))
    p.api.write("web", 10)

    async def main():
        await minute()
        p.writer.events.clear()
        p.api.write("web", 2500)
        await minute()
        assert paths(p) == [f"/{i}" for i in range(11, 2511)]
        assert p.api.calls[-1] == "nginx/logs/accesses/web/-1/0/2501"  # the rest in one more read

    asyncio.run(main())


def test_nginx_pull_across_log_rotation(monkeypatch):
    """Lines written between the last read and the rotation are in rotation 0 now: none may be lost."""
    p, minute = setup(monkeypatch, servers=("web",))
    p.api.write("web", 2000)

    async def main():
        await minute()
        p.writer.events.clear()
        p.api.write("web", 40)  # written after the last read ...
        p.api.rotate("web")  # ... then midnight rotation
        await minute()  # new file does not exist yet: nothing, place kept
        assert p.writer.events == []
        p.api.write("web", 7)
        for _ in range(3):  # a missing file backs off like a quiet log: read again within 2 minutes
            await minute()
        assert sorted(paths(p), key=lambda s: int(s[1:])) == [f"/{i}" for i in range(2001, 2048)]
        p.writer.events.clear()
        p.api.write("web", 2)
        for _ in range(3):  # quiet for a round: read again within 2 minutes
            await minute()
        assert paths(p) == ["/2048", "/2049"]

    asyncio.run(main())


def test_nginx_pull_rotation_to_an_empty_file(monkeypatch):
    p, minute = setup(monkeypatch, servers=("web",))
    p.api.write("web", 5)

    async def main():
        await minute()
        p.writer.events.clear()
        p.api.write("web", 2)
        p.api.rotate("web", created=True)
        await minute()
        assert paths(p) == ["/6", "/7"]
        p.writer.events.clear()
        p.api.write("web", 1)
        await minute()
        assert paths(p) == ["/8"]

    asyncio.run(main())


def test_nginx_pull_rotation_while_the_new_file_outgrew_the_old_count(monkeypatch):
    """A quiet log rotated, and the new file already has more lines than the old one had: the line count alone
    says "appended", the line read last is not where it should be - so it is still seen as a rotation."""
    p, minute = setup(monkeypatch, servers=("web",))
    p.api.write("web", 3)

    async def main():
        await minute()
        p.writer.events.clear()
        p.api.write("web", 1)
        p.api.rotate("web")
        p.api.write("web", 5)
        await minute()
        assert sorted(paths(p), key=lambda s: int(s[1:])) == [f"/{i}" for i in range(4, 10)]

    asyncio.run(main())


def test_nginx_pull_backs_off_on_quiet_logs(monkeypatch):
    p, minute = setup(monkeypatch)
    p.api.write("web")
    p.api.write("api")
    reads = lambda: [c for c in p.api.calls if c.count("/") > 3]

    async def main():
        await minute()  # first round: lists + both logs
        assert p.api.calls[:1] == ["nginx/logs/accesses"] and len(reads()) == 2
        assert "nginx/logs/errors" in p.api.calls  # asked once, then not for an hour
        await minute()  # nothing new yet: both read again (60 s), unchanged -> next in 120 s
        assert len(reads()) == 2 and p.api.calls[0] != "nginx/logs/accesses"  # list cached
        assert "nginx/logs/errors" not in p.api.calls
        await minute()  # both waiting
        assert reads() == []
        p.api.write("web")  # web gets traffic
        await minute()  # both due (120 s): web changed, api unchanged -> api next in 240 s
        assert len(reads()) == 2
        await minute()  # web every minute again, api waits
        assert reads() == ["nginx/logs/accesses/web/-1/0/1000"]
        for _ in range(30):  # api backs off up to 10 minutes, web (unchanged now) too
            await minute()
        assert p._nginx_logs["accesses/api"]["every"] == Poller.NGINX_MAX_EVERY
        assert p._nginx_logs["accesses/web"]["every"] == Poller.NGINX_MAX_EVERY
        p.api.write("api")
        for waited in range(11):  # read within 10 minutes; new lines: back to every minute
            await minute()
            if "nginx/logs/accesses/api/-1/0/1000" in reads():
                break
        assert waited <= 10 and p._nginx_logs["accesses/api"]["every"] == Poller.NGINX_EVERY

    asyncio.run(main())


def test_nginx_pull_reads_far_less_than_before(monkeypatch):
    """10 quiet servers, an hour: was 1 list + 10 reads every minute (660), now a fraction."""
    p, minute = setup(monkeypatch, servers=[f"s{i}" for i in range(10)])
    for sid in p.api.servers:
        p.api.write(sid)

    async def main():
        for _ in range(60):
            await minute()

    calls = []
    orig = p.api.get

    async def counting(path, **kw):
        calls.append(path)
        return await orig(path, **kw)
    p.api.get = counting
    asyncio.run(main())
    assert len(calls) < 150, len(calls)
