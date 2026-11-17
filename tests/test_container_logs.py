"""Unraid container logs: stderr (through the Docker API), repeated identical lines, log levels and the alert for
emergency / critical lines."""
import asyncio
import os
import struct
from datetime import datetime, timedelta, timezone

import pytest

from lookingglass import db
from lookingglass.config import Settings
from lookingglass.container_watch import line_severity
from lookingglass.unraid import UnraidServerPoller, parse_docker_log_stream

DSN = os.environ.get("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
EMERG = ("2026/11/17 01:22:03 [emerg] 520#520: a duplicate default server for 0.0.0.0:80 in "
         "/config/nginx/site-confs/madnessshell.conf:2")


def frame(stream: int, text: str) -> bytes:
    b = text.encode()
    return bytes([stream, 0, 0, 0]) + struct.pack(">I", len(b)) + b


def test_line_levels():
    assert line_severity(EMERG) == 0
    assert line_severity("2026/11/17 01:22:03 [crit] 1#1: SSL_do_handshake() failed") == 2
    assert line_severity("2026/11/17 01:22:03 [error] 1#1: open() failed") == 3
    assert line_severity("2026/11/17 01:22:03 [notice] 1#1: signal process started") == 5
    assert line_severity('time=x level=info msg="0 errors"') == 6       # explicit level wins over the word
    assert line_severity('{"level":"error","msg":"x"}') == 3
    assert line_severity("FATAL: database is gone") == 2
    assert line_severity("2026-11-17 01:00:00 INFO an error occurred") == 6
    assert line_severity("an error occurred") == 3 and line_severity("all fine") == 6


class FakeWriter:
    def __init__(self):
        self.events = []

    def put(self, ev):
        self.events.append(ev)


def poller(writer=None, docker=True):
    return UnraidServerPoller({"id": 1, "name": "Tower", "url": "http://tower", "api_key": "", "verify_ssl": False,
                               "docker_url": "http://tower:2375" if docker else None},
                              Settings(unraid_log_error_count=50, unraid_log_error_minutes=10), writer or FakeWriter())


def test_docker_stream_keeps_stderr_and_joins_split_lines():
    raw = (frame(1, "2026-11-17T01:22:02.100000000Z starting nginx\n")
           + frame(2, f"2026-11-17T01:22:03.123456789Z {EMERG[:40]}") + frame(2, f"{EMERG[40:]}\n")
           + frame(2, f"2026-11-17T01:22:03.223456789Z {EMERG}\n"))
    out = parse_docker_log_stream(raw)
    assert [(s, m) for _, m, s in out] == [("stdout", "starting nginx"), ("stderr", EMERG), ("stderr", EMERG)]
    # a container with a TTY: plain text
    assert parse_docker_log_stream(b"2026-11-17T01:22:03Z hello\n") == [("2026-11-17T01:22:03Z", "hello", "stdout")]


def test_identical_lines_are_each_stored():
    """The Unraid API gives millisecond timestamps: the same error printed twice in one millisecond is two lines."""
    w = FakeWriter()
    p = poller(w)
    p.put_container_lines("swag", [("2026-11-17T01:22:03.123Z", EMERG, None)] * 3)
    assert len({e["uid"] for e in w.events}) == 3 and all(e["severity"] == 0 for e in w.events)
    # the same answer again (overlap of the next poll): the same keys, stored once
    w2 = FakeWriter()
    poller(w2).put_container_lines("swag", [("2026-11-17T01:22:03.123Z", EMERG, None)] * 3)
    assert [e["uid"] for e in w2.events] == [e["uid"] for e in w.events]


def test_docker_api_is_used_first_and_api_fallback_is_flagged(monkeypatch):
    async def main():
        w = FakeWriter()
        p = poller(w)
        calls = []

        class Resp:
            status_code, content = 200, frame(2, f"2026-11-17T01:22:03.123456789Z {EMERG}\n")

        class Docker:
            async def get(self, path, params=None):
                calls.append((path, params))
                return Resp()

            async def aclose(self):
                pass

        async def query(q, variables=None):
            raise AssertionError("the Unraid API must not be asked when the Docker API answers")

        async def snapshot(key):
            return [{"id": "c1", "names": ["/swag"], "state": "RUNNING"}]

        monkeypatch.setattr(db, "get_snapshot", snapshot)
        p.client.docker = Docker()
        monkeypatch.setattr(p.client, "query", query)
        await p.poll_container_logs()
        assert calls and calls[0][1]["stderr"] == 1
        assert [e["message"] for e in w.events] == [EMERG] and w.events[0]["data"]["stream"] == "stderr"
        assert p.status["sections"]["container_logs"]["variant"].startswith("Docker API")
        assert p.log_cursors["c1"] == "2026-11-17T01:22:03.123456789Z"

        # no Docker API: the Unraid API, and the page says stderr is missing
        w2 = FakeWriter()
        p2 = poller(w2, docker=False)

        async def query2(q, variables=None):
            return {"docker": {"logs": {"cursor": "2026-11-17T01:22:04.000Z",
                                        "lines": [{"timestamp": "2026-11-17T01:22:04.000Z", "message": "ok"}]}}}
        monkeypatch.setattr(p2.client, "query", query2)
        await p2.poll_container_logs()
        sec = p2.status["sections"]["container_logs"]
        assert "stdout only" in sec["variant"] and "stderr" in sec["warning"]
        await p.client.close()
        await p2.client.close()

    asyncio.run(main())


@needs_db
def test_emergency_lines_raise_their_own_alert():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts, events, container_log_rules")
            await db.set_snapshot("unraid:1:docker", [{"names": ["/swag"]}, {"names": ["/quiet"]}])
            now = datetime.now(timezone.utc)
            rows = [(now - timedelta(seconds=i), "swag", 0, EMERG) for i in range(300)]
            rows += [(now - timedelta(seconds=i), "quiet", 3, f"[error] small thing {i}") for i in range(3)]
            await pool.executemany("INSERT INTO events (ts, source, host, program, severity, action, message) "
                                   "VALUES ($1, 'docker', 'Tower', $2, $3, 'container_log', $4)", rows)
            p = poller(docker=False)
            await p.check_logs()
            got = {r["data"]["container"]: r for r in await pool.fetch(
                "SELECT severity, title, data, fingerprint FROM alerts WHERE rule = 'unraid_container_errors'")}
            # one alert for swag (the critical one, not also "300 error lines"), none for 3 ordinary errors
            assert set(got) == {"swag"}
            assert got["swag"]["severity"] == "high" and "emergency / critical lines" in got["swag"]["title"]
            assert got["swag"]["fingerprint"].endswith(":critical")
            assert got["swag"]["data"]["events"]["min_severity"] == 2
            # off: 0 -> only the ordinary default rule (300 >= 50)
            await pool.execute("TRUNCATE alerts")
            p.settings.unraid_log_critical_count = 0
            await p.check_logs()
            titles = [r["title"] for r in await pool.fetch("SELECT title FROM alerts")]
            assert len(titles) == 1 and "300 error lines" in titles[0]
            await pool.execute("TRUNCATE alerts, events, container_log_rules")
        finally:
            await db.close()

    asyncio.run(main())
