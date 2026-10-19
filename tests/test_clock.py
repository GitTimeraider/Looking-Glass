from datetime import datetime, timedelta, timezone

from lookingglass import ingest
from lookingglass.ingest import STATS, ClockSkew, EventWriter

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)


def feed(skew: ClockSkew, sender: str, offsets_s: list[float]) -> list[datetime]:
    return [skew.correct(sender, NOW + timedelta(seconds=o), NOW) for o in offsets_s]


def test_local_time_without_zone_is_corrected():
    STATS.clock_offsets.clear()
    skew = ClockSkew()
    # OPNsense on Europe/Amsterdam (UTC+2) sending BSD syslog, read as UTC: everything 2 h "in the future"
    out = feed(skew, "10.0.0.1", [7200 - i for i in range(60)])
    assert STATS.clock_offsets["10.0.0.1"] == 7200
    assert abs((out[-1] - NOW).total_seconds()) < 120
    # a sender with correct time stamps is left alone
    feed(skew, "10.0.0.2", [-i % 5 for i in range(60)])
    assert "10.0.0.2" not in STATS.clock_offsets
    # a backlog of old messages (all different ages) is not mistaken for a time zone
    feed(skew, "10.0.0.3", [-60 * i for i in range(60)])
    assert "10.0.0.3" not in STATS.clock_offsets
    # UTC-5 (America/New_York in October would be UTC-4) - past offsets are corrected too
    feed(skew, "10.0.0.4", [-4 * 3600 - 3 for _ in range(60)])
    assert STATS.clock_offsets["10.0.0.4"] == -4 * 3600
    STATS.clock_offsets.clear()


def test_writer_never_stores_the_future(monkeypatch):
    w = EventWriter.__new__(EventWriter)
    import asyncio
    w.queue = asyncio.Queue()
    before = STATS.future_clamped
    future = datetime.now(timezone.utc) + timedelta(hours=2)
    w.put({"ts": future, "source": "qfeeds"})
    ev = w.queue.get_nowait()
    assert ev["ts"] < future - timedelta(hours=1) and STATS.future_clamped == before + 1
    assert ingest  # module import used for monkeypatch scope


def test_opnsense_local_time_from_the_api():
    from lookingglass.config import Settings
    from lookingglass.opnsense import Poller, opnsense_utc_offset

    assert opnsense_utc_offset("Mon Oct 19 14:58:06 CEST 2026", NOW.replace(hour=12, minute=58)) == 7200
    p = Poller.__new__(Poller)
    p.settings, p.utc_offset = Settings(), 7200
    # firewall log API: OPNsense strips "+02:00" (read_log.py) -> local time
    assert p.local_ts("2026-10-19T14:00:00") == datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
    # a time stamp with its own zone is kept
    assert p.local_ts("2026-10-19T14:00:00+02:00") == datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
    p.utc_offset = None  # clock not read yet: fall back to the Looking Glass time zone setting (UTC)
    assert p.local_ts("2026-10-19T14:00:00") == datetime(2026, 10, 19, 14, 0, tzinfo=timezone.utc)
