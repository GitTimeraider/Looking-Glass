import asyncio

from lookingglass import nut

VARS = {"battery.charge": "87", "battery.runtime": "1830", "ups.load": "23", "ups.realpower.nominal": "540",
        "ups.status": "OL CHRG", "device.mfr": "EATON", "device.model": "Ellipse PRO 650", "input.voltage": "231.0"}


async def fake_upsd(reader, writer):
    while line := (await reader.readline()).decode().strip():
        if line == "LIST UPS":
            writer.write(b'BEGIN LIST UPS\nUPS eaton "Eaton on Unraid"\nEND LIST UPS\n')
        elif line == "LIST VAR eaton":
            writer.write(b"BEGIN LIST VAR eaton\n" + "".join(f'VAR eaton {k} "{v}"\n' for k, v in VARS.items()).encode()
                         + b"END LIST VAR eaton\n")
        elif line.startswith("LIST VAR"):
            writer.write(b"ERR UNKNOWN-UPS\n")
        elif line == "LOGOUT":
            break
        await writer.drain()
    writer.close()


def test_nut_reads_ups_like_the_unraid_api():
    async def main():
        server = await asyncio.start_server(fake_upsd, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            [u] = await nut.read_ups("127.0.0.1", port)
            assert u["name"] == "eaton" and u["model"] == "EATON Ellipse PRO 650" and u["source"] == "NUT"
            assert u["status"] == "Online, Charging"
            assert u["battery"]["chargeLevel"] == 87 and u["battery"]["estimatedRuntime"] == 1830
            assert u["power"]["loadPercentage"] == 23 and u["power"]["currentPower"] == 124.2
            try:
                await nut.read_ups("127.0.0.1", port, "other")
                raise AssertionError("unknown UPS must fail")
            except ConnectionError as exc:
                assert "UNKNOWN-UPS" in str(exc)
    asyncio.run(main())


def test_nut_target_and_status():
    assert nut.parse_target("ups@192.168.1.10:3494", None) == ("ups", "192.168.1.10", 3494)
    assert nut.parse_target("", "tower.lan") == (None, "tower.lan", 3493)
    assert nut.status_text("OB LB") == "On Battery, Low Battery"


def test_poller_uses_nut_when_the_api_ups_query_fails(monkeypatch):
    # without Unraid's own UPS service the API's upsDevices query errors; NUT must still be asked
    from lookingglass import crypto, unraid
    from lookingglass.config import Settings
    monkeypatch.setattr(crypto, "decrypt", lambda v: v)
    p = unraid.UnraidServerPoller({"id": 7, "name": "Tower", "url": "http://tower.lan", "api_key": "k", "verify_ssl": False,
                                   "nut": "ups@tower.lan"}, Settings(), writer=None)
    snaps = {}

    async def query(q, variables=None):
        if "upsDevices" in q:
            raise unraid.GraphQLError("apcupsd is not running")
        return {"vms": {"domains": []}, "shares": []}

    async def read_ups(host, port, ups):
        return [nut.device("ups", "", {"ups.status": "OL", "device.model": "Back-UPS XS 950U "})]

    async def snap(key, data):
        snaps[key] = data

    async def nothing():
        return None
    monkeypatch.setattr(p.client, "query", query)
    monkeypatch.setattr(nut, "read_ups", read_ups)
    monkeypatch.setattr(p, "snap", snap)
    monkeypatch.setattr(p, "check_ups", nothing)
    asyncio.run(p.poll_misc())
    assert [u["name"] for u in snaps["ups"]] == ["ups"] and snaps["ups"][0]["model"] == "Back-UPS XS 950U"
    assert p.status["sections"]["ups"]["ok"] and p.status["sections"]["nut"]["ok"]
