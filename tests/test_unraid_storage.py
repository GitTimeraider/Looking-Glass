import asyncio
import os

import pytest

from lookingglass import unraid_storage as st

DSN = os.environ.get("TEST_DATABASE_URL")


def d(name, typ="DATA", rot=True, spin=True, fs="xfs", fs_size=1000, used=600, idx=0, status="DISK_OK", device="sdx"):
    return {"name": name, "idx": idx, "type": typ, "rotational": rot, "isSpinning": spin, "fsType": fs, "status": status,
            "device": device, "fsSize": fs_size, "fsUsed": used if fs_size else None, "fsFree": fs_size - used if fs_size else None,
            "temp": 35 if spin else None, "numErrors": 0, "numReads": 0, "numWrites": 0, "color": None}


ARR = {
    "capacity": {"kilobytes": {"total": 3000, "used": 1500, "free": 1500}},
    "parities": [d("parity", "PARITY", fs_size=None)],
    "disks": [d("disk1", idx=1), d("disk2", idx=2, spin=False), {"name": "disk3", "status": "DISK_NP", "device": None}],
    "caches": [d("cache", "CACHE", rot=False, fs="btrfs", idx=30), d("cache2", "CACHE", rot=False, fs="btrfs", fs_size=None, idx=31),
               d("ssd", "CACHE", rot=False, fs="zfs", fs_size=2000, used=500, idx=32),
               d("ssd2", "CACHE", rot=False, fs="zfs", fs_size=None, idx=33),
               d("nvme2", "CACHE", rot=False, fs="xfs", fs_size=500, used=100, idx=34)],
}


def test_groups_split_pools_and_use_first_member_capacity():
    groups = {g["name"]: g for g in st.build_groups(ARR, st.default_prefs())}
    assert list(groups) == ["array", "cache", "nvme2", "ssd"]  # "nvme2" has no "nvme" sibling -> own pool
    assert groups["cache"]["disks"] == 2 and groups["ssd"]["disks"] == 2
    assert groups["ssd"]["fsType"] == "zfs" and groups["ssd"]["size"] == 2000 and groups["ssd"]["used_pct"] == 25.0
    arr = groups["array"]
    assert arr["disks"] == 3 and arr["spinning"] == 2 and arr["standby"] == 1 and arr["used_pct"] == 50.0
    assert all("numReads" not in m and "color" not in m for m in arr["members"])
    assert {m["spin"] for m in groups["cache"]["members"]} == {"ssd"}


def test_excluded_group_keeps_summary_without_members():
    prefs = st.clean_prefs({"groups": {"array": {"exclude": True}}})
    g = next(g for g in st.build_groups(ARR, prefs) if g["name"] == "array")
    assert g["excluded"] and g["members"] == [] and g["disks"] == 3


def test_all_awake_needs_every_hdd_spinning():
    assert not st.all_awake(ARR)  # disk2 is spun down
    awake = {**ARR, "disks": [d("disk1"), d("disk2")]}
    assert st.all_awake(awake)
    unknown = {**ARR, "disks": [{**d("disk1"), "isSpinning": None}]}
    assert not st.all_awake(unknown)  # unknown spin state counts as asleep
    ssd_only = {"caches": [d("cache", "CACHE", rot=False, spin=None)]}
    assert st.all_awake(ssd_only)  # SSDs never matter


def test_temperature_api_versions():
    assert not st.temps_never_wake("4.37.5")
    assert not st.temps_never_wake("4.37.5-build-number-89")
    assert not st.temps_never_wake("4.25.0") and not st.temps_never_wake(None)
    assert st.temps_never_wake("4.37.6") and st.temps_never_wake("4.38.0") and st.temps_never_wake("5.0.0")


def test_prefs_validation():
    p = st.clean_prefs({"sensor_temps": "on", "groups": {"array": {"exclude": 1, "smart_minutes": 60},
                                                          "bad name!": {"exclude": True}, "ssd": {"smart_minutes": 7}}})
    assert p["sensor_temps"] == "auto"
    assert p["groups"] == {"array": {"exclude": True, "smart_minutes": 60}, "ssd": {"exclude": False, "smart_minutes": 0}}


def test_zfs_problems():
    assert st.zfs_problem("zed", "eid=77 class=statechange pool='ssd' vdev=nvme1n1p1 vdev_state=DEGRADED") == "ZFS device state DEGRADED"
    assert st.zfs_problem("zed", "eid=78 class=statechange pool='ssd' vdev_state=ONLINE") is None
    assert st.zfs_problem("zed", "eid=79 class=checksum pool='ssd'") == "ZFS checksum event"
    assert st.zfs_problem("zed", "eid=80 class=scrub_finish pool='ssd'") is None
    assert st.zfs_problem("kernel", "WARNING: Pool 'ssd' has encountered an uncorrectable I/O failure and has been suspended. ZFS") == "ZFS error"
    assert st.zfs_problem("kernel", "eth0: link up") is None


def test_docker_stats_strings():
    from lookingglass import unraid
    assert unraid._size("512MiB") == 512 * 1024 ** 2 and unraid._size("1.5GB") == 1_500_000_000 and unraid._size("0B") == 0
    assert unraid._size("--") is None and unraid._io_pair("1.2MB / 300kB") == (1_200_000, 300_000)
    assert unraid._short_id("4f1c...:abc123") == "abc123" and unraid._short_id("abc123") == "abc123"


def test_network_labels():
    from lookingglass.unraid import interface_names, net_label
    nets = interface_names([{"id": "0a1b2c3d4e5f" + "0" * 52, "name": "proxynet", "driver": "bridge"},
                             {"id": "9" * 64, "name": "bridge", "driver": "bridge", "options": {"com.docker.network.bridge.name": "docker0"}},
                             {"id": "1" * 64, "name": "host", "driver": "host"}])
    assert nets == {"br-0a1b2c3d4e5f": "proxynet", "docker0": "bridge"}
    assert net_label("lo", nets) is None and net_label("veth9a8b7c6", nets) == "containers (all veth)"
    assert net_label("br-0a1b2c3d4e5f", nets) == "docker: proxynet" and net_label("br-ffffffffffff", nets) == "docker: br-ffffffffffff"
    assert net_label("br0", nets) == "br0" and net_label("docker0", nets) == "docker: bridge"


@pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")
def test_container_down_waits_after_boot_and_closes_when_running_again():
    from lookingglass import db
    from lookingglass.config import Settings
    from lookingglass.unraid import UnraidServerPoller

    async def main():
        await db.connect(DSN)
        try:
            pool = db.pool()
            await pool.execute("TRUNCATE alerts")
            p = UnraidServerPoller({"id": 1, "name": "Tower", "url": "http://tower", "api_key": "k", "verify_ssl": False},
                                   Settings(unraid_container_grace=10), None)
            stopped = [{"names": ["/plex"], "state": "EXITED", "autoStart": True, "status": "Exited (0)"}]
            running = [{"names": ["/plex"], "state": "RUNNING", "autoStart": True, "status": "Up 11 minutes"}]
            t = 1_000_000.0
            p.boot_at, p.reachable_since = t - 60, t  # just rebooted: containers are still starting
            await p.check_containers(stopped, now=t)
            await p.check_containers(stopped, now=t + 300)
            assert await pool.fetchval("SELECT count(*) FROM alerts") == 0
            await p.check_containers(stopped, now=t + 601)  # up 10 min and still stopped: alert
            assert await pool.fetchval("SELECT status FROM alerts") == "open"
            await p.check_containers(running, now=t + 700)  # just started: stays open for now
            assert await pool.fetchval("SELECT status FROM alerts") == "open"
            await p.check_containers(running, now=t + 1301)  # running for 10 min: closed
            row = await pool.fetchrow("SELECT status, close_reason, description FROM alerts")
            assert row["status"] == "closed" and row["close_reason"] == "resolved" and "running again" in row["description"]
            await p.check_containers(stopped, now=t + 1400)  # stops again: after the grace time a new / re-opened alert
            await p.check_containers(stopped, now=t + 2001)
            assert await pool.fetchval("SELECT status FROM alerts") == "open"
            p.boot_at = None  # no boot time from the API: Looking Glass's own first contact counts
            p.reachable_since = t + 3000
            p.ctr_state.clear()
            await pool.execute("TRUNCATE alerts")
            await p.check_containers(stopped, now=t + 3000)
            await p.check_containers(stopped, now=t + 3500)
            assert await pool.fetchval("SELECT count(*) FROM alerts") == 0
        finally:
            await db.close()

    asyncio.run(main())


def test_container_cpu_is_a_share_of_the_whole_cpu(monkeypatch):
    """docker stats counts 100 % per thread; Looking Glass shows the share of the whole CPU, like the server's graph:
    one busy thread on an 8-thread server is 12.5 %."""
    import asyncio

    import httpx

    from lookingglass import db, unraid

    def poller(threads):
        p = object.__new__(unraid.UnraidServerPoller)
        p.sid, p.threads, p.status, p.last_run, p.got = 1, threads, {"sections": {}}, {}, []

        async def store(stats):
            p.got = stats
        p.store_docker_stats = store
        return p

    # Docker engine API: 1 s of CPU time out of 8 s of system time (8 threads × 1 s)
    stats = {"cpu_stats": {"cpu_usage": {"total_usage": 2_000_000_000}, "system_cpu_usage": 16_000_000_000, "online_cpus": 8},
             "precpu_stats": {"cpu_usage": {"total_usage": 1_000_000_000}, "system_cpu_usage": 8_000_000_000},
             "memory_stats": {"usage": 100}}

    def handler(req):
        return httpx.Response(200, json=[{"Id": "abc", "Names": ["/plex"]}] if req.url.path == "/containers/json" else stats)
    p = poller(0)
    p.client = type("C", (), {"docker": httpx.AsyncClient(base_url="http://d", transport=httpx.MockTransport(handler))})()
    asyncio.run(p.poll_docker_stats())
    assert p.got[0]["cpu_pct"] == 12.5

    # Unraid API (docker stats' numbers): 100 % = one thread, divided by the server's 8 threads
    async def snapshot(key):
        return [{"id": "x:abc", "state": "RUNNING", "names": ["/plex"]}]
    monkeypatch.setattr(db, "get_snapshot", snapshot)

    async def subscribe(q, until, timeout):
        until([{"dockerContainerStats": {"id": "abc", "cpuPercent": 100.0, "memUsage": "1MiB / 2GiB"}}] * 2)
    p = poller(8)
    p.client = type("C", (), {"subscribe": staticmethod(subscribe)})()
    asyncio.run(p.poll_docker_stats_api())
    assert p.got[0]["cpu_pct"] == 12.5
