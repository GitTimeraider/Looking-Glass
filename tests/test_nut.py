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
