from lookingglass import unraid_storage as st


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
