"""Unraid redirecting /graphql (http -> https, *.myunraid.net) must not turn the POST into an empty GET."""
import asyncio

import httpx

from lookingglass import crypto
from lookingglass.unraid import UnraidClient


def _client(handler):
    c = UnraidClient({"url": "http://tower.lan", "api_key": crypto.encrypt("k"), "verify_ssl": False, "docker_url": None})
    c.http = httpx.AsyncClient(base_url="http://tower.lan", transport=httpx.MockTransport(handler))
    return c


def test_post_survives_302_and_remembers_new_origin():
    seen = []

    def handler(req):
        seen.append((req.method, str(req.url), req.content))
        if req.url.host == "tower.lan":
            return httpx.Response(302, headers={"Location": "https://abc.myunraid.net/graphql"})
        assert req.method == "POST" and b'"query"' in req.content
        return httpx.Response(200, json={"data": {"info": {"os": {"hostname": "tower"}}}})

    c = _client(handler)
    d = asyncio.run(c.query("{ info { os { hostname } } }"))
    assert d["info"]["os"]["hostname"] == "tower"
    assert c.ws_base == "https://abc.myunraid.net"
    asyncio.run(c.query("{ info { os { hostname } } }"))  # second call goes straight to the new origin
    assert [m for m, *_ in seen] == ["POST", "POST", "POST"]
    assert "tower.lan" not in seen[-1][1]
