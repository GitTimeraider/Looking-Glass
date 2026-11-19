"""Unraid /var/log/syslog pull: kept track of by line number, across rotation to syslog.1 (Unraid API logFile:
lines are 1-based, a file is named by its basename inside /var/log)."""
import asyncio

from lookingglass.config import Settings
from lookingglass.unraid import GraphQLError, UnraidServerPoller


class FakeUnraid:
    def __init__(self):
        self.files = {"syslog": []}
        self.n = 0

    def write(self, count=1):
        for _ in range(count):
            self.n += 1
            self.files["syslog"].append(f"Nov 19 10:00:00 Tower kernel: line {self.n}")

    def rotate(self):
        self.files["syslog.1"], self.files["syslog"] = self.files["syslog"], []

    async def query(self, q, variables):
        name = variables["path"].rsplit("/", 1)[-1]
        if name not in self.files:
            raise GraphQLError("ENOENT")
        lines = self.files[name]
        start, count = variables["start"], variables["lines"]
        chunk = lines[start - 1:start - 1 + count]
        return {"logFile": {"totalLines": len(lines), "startLine": start, "content": "\n".join(chunk) + ("\n" if chunk else "")}}


class Writer:
    def __init__(self):
        self.events = []

    def put(self, ev):
        self.events.append(ev)


def setup():
    p = UnraidServerPoller({"id": 1, "name": "Tower", "url": "http://x", "api_key": "k", "verify_ssl": False}, Settings(), Writer())
    p.client = FakeUnraid()
    return p


def numbers(p):
    out = [int(e["message"].rsplit(" ", 1)[1]) for e in p.writer.events]
    p.writer.events.clear()
    return out


def test_syslog_follows_new_lines():
    p = setup()

    async def main():
        p.client.write(1000)
        await p.poll_syslog()
        assert numbers(p) == list(range(700, 1001))  # first read: the newest 300 lines
        p.client.write(5)
        await p.poll_syslog()
        assert numbers(p) == list(range(1001, 1006))
        await p.poll_syslog()
        assert numbers(p) == []
        p.client.write(25000)  # more than one poll reads: the rest follows, nothing skipped
        await p.poll_syslog()
        first = numbers(p)
        await p.poll_syslog()
        assert first + numbers(p) == list(range(1006, 26006))

    asyncio.run(main())


def test_syslog_rotation_loses_nothing():
    p = setup()

    async def main():
        p.client.write(500)
        await p.poll_syslog()
        numbers(p)
        p.client.write(40)  # after the last read ...
        p.client.rotate()  # ... rotated
        p.client.write(700)  # and the new file already longer than 300 lines
        await p.poll_syslog()
        assert sorted(numbers(p)) == list(range(501, 1241))
        assert "warning" not in p.status["sections"]["syslog"]
        p.client.write(3)
        await p.poll_syslog()
        assert numbers(p) == [1241, 1242, 1243]

    asyncio.run(main())


def test_syslog_rotation_to_an_empty_file_then_busy():
    p = setup()

    async def main():
        p.client.write(10)
        await p.poll_syslog()
        numbers(p)
        p.client.rotate()
        await p.poll_syslog()  # new file still empty
        assert numbers(p) == []
        p.client.write(800)
        await p.poll_syslog()
        assert numbers(p) == list(range(11, 811))  # all of it, not just the newest 300

    asyncio.run(main())


def test_syslog_new_file_outgrew_the_old_position():
    """The line count alone would say "same file": the text at the old position tells it was rotated."""
    p = setup()

    async def main():
        p.client.write(20)
        await p.poll_syslog()
        numbers(p)
        p.client.write(2)
        p.client.rotate()
        p.client.write(50)
        await p.poll_syslog()
        assert sorted(numbers(p)) == list(range(21, 73))

    asyncio.run(main())


def test_syslog_rotated_file_gone_warns():
    p = setup()

    async def main():
        p.client.write(20)
        await p.poll_syslog()
        numbers(p)
        p.client.rotate()
        del p.client.files["syslog.1"]
        p.client.write(5)
        await p.poll_syslog()
        assert numbers(p) == list(range(21, 26))
        assert "may be missing" in p.status["sections"]["syslog"]["warning"]

    asyncio.run(main())
