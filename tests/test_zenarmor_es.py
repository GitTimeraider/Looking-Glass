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
