import ipaddress
import asyncio
import json
import re
import os

import httpx
import pytest

from lookingglass import ai, db, privacy
from lookingglass.ai import Analyst
from lookingglass.config import Settings

DSN = os.environ.get("TEST_DATABASE_URL")

REAL = {
    "lan": "192.168.1.20", "gw": "192.168.1.1", "iot": "10.20.30.5", "wan": "84.12.33.4", "v6": "2a02:a45f:1234:10::5",
    "ula": "fd12:3456:789a:1::25", "ll": "fe80::a8bb:ccff:fe11:2233", "mac": "AA:BB:CC:11:22:33", "host": "Johns-iPhone",
    "ssid": "Jansen-IoT", "user": "john", "mail": "jan@jansen.nl", "dom": "jansen.nl", "tv": "Living Room TV",
}
TEXT = (
    f'{{"src": "{REAL["lan"]}", "gw": "{REAL["gw"]}", "dst": "8.8.8.8", "dst_port": 443, "domain": "github.com", '
    f'"mac": "{REAL["mac"]}", "host": "{REAL["host"]}.home.lan", "msg": "Accepted password for {REAL["user"]} from '
    f'{REAL["lan"]} port 22; WAN {REAL["wan"]}; {REAL["v6"]} {REAL["ula"]} {REAL["ll"]}%igb0; PTR '
    f'20.1.168.192.in-addr.arpa; ip-192-168-1-20; nas.{REAL["dom"]}; mail {REAL["mail"]}; ssid {REAL["ssid"]}; '
    f'{REAL["tv"]}; iot {REAL["iot"]}; 10.0.0.0/8; subnet 192.168.1.0/24; 12:30:45; ::ffff:192.168.1.20; root"}}'
)


def settings(**kw):
    return Settings(ai_privacy=True, ai_privacy_terms="jansen.nl", **kw)


def make_session(mp=None, s=None):
    s = s or settings()
    mp = mp or privacy.Mapping(privacy.MemoryStore())
    names = privacy.build_names(s, [REAL["host"], REAL["tv"], "nas", "OPNsense (LAN)"], [REAL["ssid"]], [REAL["user"], "root"])
    return privacy.Session(mp, names, {REAL["wan"]}, [], {"2a02:a45f:1234"})


def test_hide_replaces_every_local_identifier_and_reveal_restores_exactly():
    async def main():
        sess = make_session()
        hidden = await sess.hide(TEXT)
        for name, value in REAL.items():
            assert value.lower() not in hidden.lower(), name
        # whole numbers only: the fake network can be e.g. 192.168.131.x, whose PTR "20.131.168.192.in-addr" contains
        # the text "1.168.192.in-addr" without containing the real network
        assert not re.search(r"(?<![\d.])20\.1\.168\.192\.in-addr", hidden), hidden
        assert not re.search(r"(?<!\d)192-168-1-20(?!\d)", hidden), hidden
        # kept: internet addresses, domains, ports, generic names, the whole private block, times
        for kept in ("8.8.8.8", "github.com", "443", "home.lan", " root", "10.0.0.0/8", "12:30:45", "nas."):
            assert kept in hidden, kept
        assert sess.reveal(hidden) == TEXT
    asyncio.run(main())


def test_pseudonyms_keep_structure():
    async def main():
        sess = make_session()
        hidden = json.loads(await sess.hide(TEXT))
        lan, gw = hidden["src"], hidden["gw"]
        assert lan.startswith("192.168.") and lan.endswith(".20") and lan != REAL["lan"]
        assert gw.rsplit(".", 1)[0] == lan.rsplit(".", 1)[0] and gw.endswith(".1")  # same subnet, gateway stays .1
        assert hidden["mac"].startswith("AA:BB:CC:") and hidden["mac"] != REAL["mac"]  # vendor part stays, case kept
        assert hidden["host"].startswith("iphone-") and hidden["host"].endswith(".home.lan")  # device type hint
        msg = hidden["msg"]
        assert "198.51.100." in msg or "203.0.113." in msg or "192.0.2." in msg  # own WAN -> documentation range
        assert "2001:db8:" in msg and "ssid-iot-" in msg and "user-" in msg and "domain-" in msg and ".example" in msg
        assert f"subnet {lan.rsplit('.', 1)[0]}.0/24" in msg  # the CIDR follows the same renumbering
    asyncio.run(main())


def test_same_value_same_pseudonym_across_sessions_and_restarts():
    async def main():
        store = privacy.MemoryStore()
        one = await make_session(privacy.Mapping(store)).hide(TEXT)
        fresh = privacy.Mapping(store)  # e.g. after a restart: loaded from the table
        await fresh.load()
        assert await make_session(fresh).hide(TEXT) == one
    asyncio.run(main())


def test_tool_calls_and_sql_are_translated_back():
    async def main():
        sess = make_session()
        hidden = json.loads(await sess.hide(TEXT))
        net = hidden["src"].rsplit(".", 1)[0]
        token = hidden["host"].split(".")[0]
        msg = {"role": "assistant", "content": f"{token} ({hidden['src']}) looks fine.", "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "sql_query", "arguments": json.dumps(
                {"query": f"SELECT * FROM events WHERE src_ip << '{net}.0/24' AND host(src_ip) LIKE '{net}.%' "
                          f"AND message ILIKE '%{token.upper()}%'"})}}]}
        out = sess.reveal_message(msg)
        assert out["content"] == f"{REAL['host']} ({REAL['lan']}) looks fine."
        q = json.loads(out["tool_calls"][0]["function"]["arguments"])["query"]
        assert "'192.168.1.0/24'" in q and "LIKE '192.168.1.%'" in q and f"%{REAL['host']}%" in q
        # the history that goes out again: tool call arguments pseudonymized as well
        again = await sess.hide_message(out)
        assert REAL["lan"] not in json.dumps(again) and REAL["host"] not in json.dumps(again)
    asyncio.run(main())


def test_names_toggle_keep_list_and_generic_names():
    s = settings(ai_privacy_names=False)
    assert set(privacy.build_names(s, ["Johns-iPhone"], ["Home"], ["john"])) == {"jansen.nl"}
    s = settings(ai_privacy_keep="media-box")
    names = privacy.build_names(s, ["media-box", "router", "nas", "localhost", "192.168.1.5", "aa:bb:cc:dd:ee:ff",
                                    "kitchen-display.lan", "message", "Source"], [], ["root", "admin", "rod"])
    assert "media-box" not in names and "router" not in names and "nas" not in names and "root" not in names
    assert "message" not in names and "source" not in names  # would turn JSON keys / columns into pseudonyms
    assert "192.168.1.5" not in names and "aa:bb:cc:dd:ee:ff" not in names
    assert names["kitchen-display"] == ("host", "kitchen-display") and names["rod"] == ("user", "rod")


def test_device_type_hints():
    assert privacy.name_fake("host", "Johns-iPhone").startswith("iphone-")
    assert privacy.name_fake("host", "ernest-desk").startswith("host-")  # no "nest" inside a word
    assert privacy.name_fake("host", "Living Room TV").startswith("tv-")
    assert privacy.name_fake("ssid", "Smith Guest").startswith("ssid-guest-")
    assert privacy.name_fake("term", "example.com").endswith(".example")


def test_dump_cuts_after_a_whole_value():
    rows = [{"ip": f"192.168.1.{i % 250}", "name": "Jörg"} for i in range(3000)]
    text = ai._dump(rows, 2000)
    assert "Jörg" in text and "\\u00f6" not in text
    body = text.split("... [truncated")[0]
    assert body.endswith(("}", '"', "]")) and len(body) <= 2000


def test_analyst_sends_only_pseudonyms_and_answers_with_real_values(monkeypatch):
    """End to end: the request bodies never contain a real value, the tool gets the real address, the user gets the
    real names back - and the stored conversation holds the real values only."""
    sess = make_session()
    sent: list[str] = []
    tool_args: list[dict] = []

    async def fake_session(_s):
        return sess

    async def fake_prompt(self):
        return "system"

    async def fake_tool(name, args):
        tool_args.append(args)
        return json.dumps({"rows": [{"src": REAL["lan"], "hostname": REAL["host"], "mac": REAL["mac"]}]})

    monkeypatch.setattr(privacy, "session", fake_session)
    monkeypatch.setattr(Analyst, "_system_prompt", fake_prompt)
    monkeypatch.setattr(ai, "run_tool", fake_tool)

    def handler(req):
        body = req.content.decode()
        sent.append(body)
        msgs = json.loads(body)["messages"]
        if len(sent) == 1:
            ip = msgs[-1]["content"].split("(")[1].split(")")[0]  # the pseudonym the model was shown
            assert ip.startswith("192.168.") and ip != REAL["lan"]
            return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "", "tool_calls": [
                {"id": "t1", "type": "function", "function": {"name": "ip_profile", "arguments": json.dumps({"ip": ip})}}]}}]})
        tool_result = json.loads(msgs[-1]["content"])["rows"][0]
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant",
                              "content": f"{tool_result['hostname']} at {tool_result['src']} is fine."}}]})

    real_client = httpx.AsyncClient

    def client(**kw):
        kw.pop("transport", None)
        return real_client(transport=httpx.MockTransport(handler), **kw)

    monkeypatch.setattr(ai.httpx, "AsyncClient", client)
    s = settings(ai_base_url="https://ai.example/v1", ai_api_key="k", ai_model="m", ai_stream=False)
    new = asyncio.run(Analyst(s).chat([], f"What is {REAL['host']} ({REAL['lan']}) doing?"))
    assert len(sent) == 2
    for body in sent:
        for value in (REAL["lan"], REAL["host"], REAL["mac"]):
            assert value not in body
    assert "PRIVACY MODE" in json.loads(sent[0])["messages"][0]["content"]
    assert tool_args == [{"ip": REAL["lan"]}]
    assert new[-1]["content"] == f"{REAL['host']} at {REAL['lan']} is fine."
    assert new[0]["content"] == f"What is {REAL['host']} ({REAL['lan']}) doing?"


def test_privacy_off_sends_real_values(monkeypatch):
    sent = []

    async def fake_prompt(self):
        return "system"

    monkeypatch.setattr(Analyst, "_system_prompt", fake_prompt)
    real_client = httpx.AsyncClient

    def handler(req):
        sent.append(req.content.decode())
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "ok"}}]})

    monkeypatch.setattr(ai.httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    s = Settings(ai_base_url="https://ai.example/v1", ai_api_key="k", ai_model="m", ai_stream=False)
    asyncio.run(Analyst(s).chat([], f"What is {REAL['lan']} doing?"))
    assert REAL["lan"] in sent[0] and "PRIVACY MODE" not in sent[0]


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_pseudonyms_are_stored_and_names_come_from_the_database():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE ai_pseudonyms, devices")
            await pool.execute("DELETE FROM snapshots WHERE key = 'interfaces'")
            await pool.execute("INSERT INTO devices (mac, ip, hostname) VALUES ('aa:bb:cc:11:22:33', '192.168.1.20', "
                               "'Johns-iPhone'), ('if:igb1', '192.168.1.1', 'OPNsense (LAN)')")
            await db.set_snapshot("interfaces", {"[WAN] (igb0) / 84.12.33.4": {"name": "igb0", "address": "84.12.33.4"}})
            privacy.invalidate()
            s = Settings(ai_privacy=True)
            sess = await privacy.session(s)
            text = "Johns-iPhone 192.168.1.20 talks to 84.12.33.4 and OPNsense (LAN)"
            hidden = await sess.hide(text)
            assert "Johns-iPhone" not in hidden and "192.168.1.20" not in hidden and "84.12.33.4" not in hidden
            assert "OPNsense (LAN)" in hidden
            stored = {r["kind"]: r["fake"] for r in await pool.fetch("SELECT kind, fake FROM ai_pseudonyms")}
            assert set(stored) == {"name", "net4", "ip4"}
            privacy.invalidate()  # a restart: same pseudonyms from the table
            again = await privacy.session(s)
            assert await again.hide(text) == hidden and again.reveal(hidden) == text
            # the WAN address changed: the old one stays "own" (older logs still hold it)
            await db.set_snapshot("interfaces", {})
            privacy.invalidate()
            assert "84.12.33.4" not in await (await privacy.session(s)).hide("84.12.33.4")
            await pool.execute("TRUNCATE ai_pseudonyms, devices")
            await pool.execute("DELETE FROM snapshots WHERE key = 'interfaces'")
            privacy.invalidate()
        finally:
            await db.close()

    asyncio.run(main())


def test_ipv6_networks_and_generic_blocks():
    async def main():
        sess = make_session()
        text = ("lan fd12:3456:789a:1::/64 site 2a02:a45f:1234::/48 vlan 2a02:a45f:1234:20::/64 "
                "keep fc00::/7 2a02:a45f::/32 2606:4700::1111")
        hidden = await sess.hide(text)
        assert "fd12:3456:789a" not in hidden and "2a02:a45f:1234" not in hidden
        assert "2001:db8:" in hidden and ":20::/64" in hidden  # the subnet id stays
        assert "fc00::/7" in hidden and "2a02:a45f::/32" in hidden and "2606:4700::1111" in hidden
        assert sess.reveal(hidden) == text
    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_what_the_ai_sees_shows_a_chat_as_it_is_sent():
    """AI Analyst › What the AI sees: every message, tool call and tool result as sent - pseudonyms paired with the
    real values, and the real values joined back give the stored conversation."""
    from lookingglass.web.app import create_app

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE ai_pseudonyms, devices, ai_chats")
            await pool.execute("INSERT INTO devices (mac, ip, hostname) VALUES ('14:c1:4e:51:a1:0b', '192.168.20.3', 'Google-Nest-Mini')")
            privacy.invalidate()
            messages = [
                {"role": "user", "content": "What does Google-Nest-Mini (192.168.20.3) do?"},
                {"role": "assistant", "content": "", "tool_calls": [{"id": "t1", "type": "function", "function": {
                    "name": "ip_profile", "arguments": json.dumps({"ip": "192.168.20.3"})}}]},
                {"role": "tool", "tool_call_id": "t1", "content": json.dumps({"ip": "192.168.20.3", "mac": "14:c1:4e:51:a1:0b",
                                                                              "hostname": "Google-Nest-Mini", "dst": "8.8.8.8"})},
                {"role": "assistant", "content": "Google-Nest-Mini at 192.168.20.3 only talks to 8.8.8.8."},
            ]
            cid = await pool.fetchval("INSERT INTO ai_chats (title, messages) VALUES ('t', $1) RETURNING id", messages)
            for on in (True, False):
                s = Settings(ai_privacy=on, ai_base_url="https://ai.example/v1", ai_api_key="k", ai_model="m")
                app = create_app(s, Analyst(s))
                ep = next(r.endpoint for r in app.routes if getattr(r, "path", "") == "/api/ai/chats/{chat_id}/sent")
                d = await ep(cid)
                assert d["privacy"] is on and d["tools"] and ("PRIVACY MODE" in d["system"]) is on
                sent = json.dumps([[f if f is not None else r for r, f in m["parts"]] for m in d["messages"]])
                real = "".join(r for m in d["messages"] for r, _ in m["parts"])
                assert real.startswith("What does Google-Nest-Mini (192.168.20.3)")  # real values joined = stored
                call = d["messages"][1]["tool_calls"][0]
                assert call["name"] == "ip_profile"
                if on:
                    for value in ("Google-Nest-Mini", "192.168.20.3", "14:c1:4e:51:a1:0b"):
                        assert value not in sent
                    assert "8.8.8.8" in sent and "nest-" in sent  # internet addresses as they are, device type hint
                    swapped = {r: f for m in d["messages"] for r, f in m["parts"] if f}
                    assert swapped["Google-Nest-Mini"].startswith("nest-") and swapped["192.168.20.3"].endswith(".3")
                    assert not [p for p in call["parts"] if p[1] is None and "192.168.20.3" in p[0]]
                    assert d["names"].get("host", 0) >= 1
                else:
                    assert all(f is None for m in d["messages"] for _, f in m["parts"]) and "192.168.20.3" in sent
            await pool.execute("TRUNCATE ai_pseudonyms, devices, ai_chats")
            privacy.invalidate()
        finally:
            await db.close()

    asyncio.run(main())


def test_fake_networks_keep_the_structure_and_stay_out_of_excluded_networks():
    async def main():
        mp = privacy.Mapping(privacy.MemoryStore())
        real_nets = [privacy._site(ipaddress.ip_address(a)) for a in ("192.168.20.1", "192.168.30.1", "10.1.2.3")]
        excluded = privacy.parse_avoid("192.168.0.0-192.168.127.255\n172.16.0.0/12")
        sess = privacy.Session(mp, {}, set(), [], set(), avoid=excluded + real_nets)
        text = "a 192.168.20.3 b 192.168.20.7 c 192.168.30.9 d 10.1.2.3 e 192.168.20.0/24"
        hidden = await sess.hide(text)
        a, b, c, d = (hidden.split(f"{k} ")[1].split(" ")[0] for k in "abcd")
        net = lambda ip: ip.rsplit(".", 1)[0]  # noqa: E731
        assert net(a) == net(b) and a.endswith(".3") and b.endswith(".7")  # same /24 -> same fake /24
        assert net(c) != net(a) and c.endswith(".9")  # other /24 -> other fake /24
        assert d.startswith("10.") and d.endswith(".3")  # the range stays (10.x stays 10.x)
        assert f"e {net(a)}.0/24" in hidden
        for fake in (a, c, d):
            ip = ipaddress.ip_address(fake)
            assert not any(ip in n for n in excluded + real_nets), fake  # never excluded, never one of your own
        assert int(a.split(".")[2]) >= 128  # 192.168.0-127 excluded: the upper half
        assert sess.reveal(hidden) == text

        # 192.168 fully excluded later: the existing fakes are replaced (10.x), everything still round-trips
        sess2 = privacy.Session(mp, {}, set(), [], set(), avoid=privacy.parse_avoid("192.168.0.0/16") + real_nets)
        await privacy._drop_blocked(sess2)
        hidden2 = await sess2.hide(text)
        a2 = hidden2.split("a ")[1].split(" ")[0]
        assert a2.startswith("10.") and a2.endswith(".3") and sess2.reveal(hidden2) == text
        assert "192.168." not in hidden2.replace("192.168.20.0/24", "")

        # everything private excluded: no fake address possible - the request fails instead of sending real ones
        sess3 = privacy.Session(privacy.Mapping(privacy.MemoryStore()), {}, set(), [], set(),
                                avoid=privacy.parse_avoid("10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10"))
        with pytest.raises(RuntimeError, match="never use these networks"):
            await sess3.hide("192.168.1.5")
    asyncio.run(main())


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_fake_networks_avoid_your_own_networks_from_the_database():
    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE ai_pseudonyms, devices")
            privacy.invalidate()
            # one /24 used as a fake ... that later turns out to be a real network of yours
            await pool.execute("INSERT INTO ai_pseudonyms (kind, key, real, fake) VALUES ('net4', '192.168.1', '192.168.1', '192.168.50')")
            await pool.execute("INSERT INTO devices (mac, ip, hostname) VALUES ('aa:bb:cc:00:00:01', '192.168.50.10', 'nas2')")
            sess = await privacy.session(Settings(ai_privacy=True, ai_privacy_avoid="192.168.200.0/24"))
            hidden = await sess.hide("192.168.1.5 and 192.168.50.10")
            fake1 = hidden.split(" ")[0]
            assert not fake1.startswith("192.168.50.") and not fake1.startswith("192.168.200.")
            assert sess.reveal(hidden) == "192.168.1.5 and 192.168.50.10"
            assert await pool.fetchval("SELECT fake FROM ai_pseudonyms WHERE key = '192.168.1'") != "192.168.50"
            await pool.execute("TRUNCATE ai_pseudonyms, devices")
            privacy.invalidate()
        finally:
            await db.close()
    asyncio.run(main())


def test_devices_of_one_subnet_always_share_one_fake_subnet():
    """The analysis depends on it: every device of a /24 (and of the /25 - /30 VLANs inside one) lands in the same fake
    /24, different subnets in different ones - also when fake networks have to be replaced: the whole subnet moves."""
    async def main():
        mp = privacy.Mapping(privacy.MemoryStore())
        subnets = ["192.168.1", "192.168.20", "192.168.30", "10.10.5", "172.16.8"]
        devices = [f"{n}.{h}" for n in subnets for h in (1, 2, 17, 64, 65, 130, 200, 254)]  # .64/.65: a /26 border
        text = " ".join(devices)

        async def check(sess):
            hidden = (await sess.hide(text)).split(" ")
            fake_net = {}
            for real, fake in zip(devices, hidden):
                assert fake.rsplit(".", 1)[1] == real.rsplit(".", 1)[1]  # host part kept
                assert fake.split(".")[0] == real.split(".")[0]  # private range kept (192.168 / 10 / 172.16)
                fake_net.setdefault(real.rsplit(".", 1)[0], set()).add(fake.rsplit(".", 1)[0])
            assert all(len(f) == 1 for f in fake_net.values()), fake_net  # one subnet -> one fake subnet
            assert len({next(iter(f)) for f in fake_net.values()}) == len(subnets)  # different -> different
            assert sess.reveal(" ".join(hidden)) == text
            return {k: next(iter(v)) for k, v in fake_net.items()}

        first = await check(privacy.Session(mp, {}, set(), [], set()))
        # the fake of 192.168.1 (and more) becomes forbidden: whole subnets move, still together
        excluded = privacy.parse_avoid(", ".join(f"{f}.0/24" for f in list(first.values())[:3]))
        sess = privacy.Session(mp, {}, set(), [], set(), avoid=excluded)
        await privacy._drop_blocked(sess)
        second = await check(sess)
        assert [second[k] != first[k] for k in subnets] == [True, True, True, False, False]
        # and once more with all of 192.168.0-127 excluded
        sess = privacy.Session(mp, {}, set(), [], set(), avoid=excluded + privacy.parse_avoid("192.168.0.0-192.168.127.255"))
        await privacy._drop_blocked(sess)
        await check(sess)
    asyncio.run(main())
