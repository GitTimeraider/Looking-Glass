from starlette.testclient import TestClient

from lookingglass.config import Settings
from lookingglass.zenarmor_es import create_es_app


class Writer:
    def __init__(self) -> None:
        self.events = []

    def put(self, ev) -> None:
        self.events.append(ev)


def test_bulk_tolerates_stray_lines():
    """A document without its action line or a non-object action used to crash the request (HTTP 500)."""
    client = TestClient(create_es_app(Settings(), Writer()))
    body = (b'{"index":{"_index":"conn"}}\n\n{"ip_src_saddr":"10.0.0.1"}\n{"stray":"doc"}\n'
            b'{"index":"weird"}\n{"delete":{"_id":"1"}}\n{"index":{}}\n')
    r = client.post("/_bulk", content=body)
    assert r.status_code == 200
    assert [next(iter(i)) for i in r.json()["items"]] == ["index", "delete"]


def test_switching_zenarmor_off_closes_the_receiver_port(monkeypatch):
    """Settings › OPNsense › Receive Zenarmor data: off closes port 9200 within a few seconds, on opens it again."""
    import asyncio
    import socket

    from lookingglass import main

    monkeypatch.setattr(main, "ES_CHECK_S", 0.05)
    with socket.socket() as s:  # a free port
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    settings = Settings(web_host="127.0.0.1", zenarmor_es_port=port, zenarmor_enabled=True)

    async def is_open() -> bool:
        try:
            _, w = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            return False
        w.close()
        return True

    async def wait_for(want: bool) -> bool:
        for _ in range(100):
            if await is_open() == want:
                return True
            await asyncio.sleep(0.05)
        return False

    async def run():
        task = asyncio.create_task(main.zenarmor_es_supervisor(settings, Writer()))
        try:
            assert await wait_for(True)
            settings.zenarmor_enabled = False
            assert await wait_for(False)
            settings.zenarmor_enabled = True
            assert await wait_for(True)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        assert await wait_for(False)  # shut down: closed

    asyncio.run(run())
