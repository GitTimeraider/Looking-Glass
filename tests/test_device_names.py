import asyncio
import os

import pytest

from lookingglass import db
from lookingglass.config import Settings
from lookingglass.opnsense import Poller
from lookingglass.parsers.common import real_name

DSN = os.environ.get("TEST_DATABASE_URL")


def test_placeholders_are_no_names():
    for v in ("*", "-", "?", "", None, " * ", "<unknown>"):
        assert real_name(v) is None, v
    assert real_name("nas.home.lan.") == "nas.home.lan" and real_name("pixel-7") == "pixel-7"


class FakeApi:
    def __init__(self, hosts):
        self.hosts = hosts

    async def search(self, path, rows=500):
        assert path == "dnsmasq/settings/search_host"
        return self.hosts


def poller(hosts):
    p = Poller.__new__(Poller)
    p.api, p._static_names, p._dns_ip_names = FakeApi(hosts), {}, {}
    return p


def test_names_from_dnsmasq_hosts_and_unbound():
    p = poller([{"host": "plug", "ip": "192.168.1.61", "hwaddr": "AA:AA:AA:AA:AA:61,aa:aa:aa:aa:aa:99"},
                {"host": "", "descr": "Office printer", "ip": "192.168.1.90", "hwaddr": ""},
                {"host": "*", "ip": "192.168.1.5"}])
    asyncio.run(p._load_static_names())
    assert p._static_names == {"aa:aa:aa:aa:aa:61": "plug", "aa:aa:aa:aa:aa:99": "plug",
                               "192.168.1.61": "plug", "192.168.1.90": "Office printer"}
    assert p._named({"mac": "aa:aa:aa:aa:aa:99", "ip": "10.0.0.9", "hostname": "*"})["hostname"] == "plug"
    by_ip = p._named({"mac": "bb:bb:bb:bb:bb:01", "ip": "192.168.1.90", "hostname": "-"})
    assert by_ip["hostname"] == "Office printer" and by_ip["name_source"] == "dnsmasq-static"
    p._dns_ip_names["192.168.1.62"] = "tv.home.lan"
    dns = p._named({"mac": "aa:aa:aa:aa:aa:62", "ip": "192.168.1.62", "hostname": "*"})
    assert dns["hostname"] == "tv.home.lan" and dns["name_source"] == "dns"
    own = p._named({"mac": "aa:aa:aa:aa:aa:62", "ip": "192.168.1.62", "hostname": "tv"})
    assert own["hostname"] == "tv" and "name_source" not in own


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_better_names_win_and_manual_names_stay():
    from lookingglass.detections import track_devices

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("DELETE FROM devices WHERE mac LIKE 'ee:ee:%'")
            mac = "ee:ee:ee:ee:ee:01"
            name = lambda: pool.fetchrow("SELECT hostname, name_source FROM devices WHERE mac = $1", mac)  # noqa: E731
            await track_devices([{"mac": mac, "ip": "192.168.9.1", "hostname": "*"}], origin="dhcp-dnsmasq")
            assert (await name())["hostname"] is None
            await track_devices([{"mac": mac, "hostname": "dev.home.lan"}], origin="arp")
            assert tuple(await name()) == ("dev.home.lan", "arp")
            await track_devices([{"mac": mac, "hostname": "dev"}], origin="dhcp-dnsmasq")
            assert tuple(await name()) == ("dev", "dhcp-dnsmasq")
            await track_devices([{"mac": mac, "hostname": "dev.home.lan"}, ], origin="arp")  # worse source: no change
            await track_devices([{"mac": mac, "hostname": "-"}], origin="dhcp-dnsmasq")  # placeholder: no change
            assert tuple(await name()) == ("dev", "dhcp-dnsmasq")
            await pool.execute("UPDATE devices SET hostname = 'My plug', name_source = 'manual', name_rank = 100 WHERE mac = $1", mac)
            await track_devices([{"mac": mac, "hostname": "plug", "name_source": "dnsmasq-static"}], origin="dhcp-dnsmasq")
            assert tuple(await name()) == ("My plug", "manual")
            await pool.execute("DELETE FROM devices WHERE mac LIKE 'ee:ee:%'")
        finally:
            await db.close()

    asyncio.run(main())
