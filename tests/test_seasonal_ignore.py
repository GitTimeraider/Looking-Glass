"""Settings › Behaviour & ML › Hour of the week: ignore - metrics, optionally only on some days / hours."""
from __future__ import annotations

from datetime import datetime

import pytest

from lookingglass import app_config
from lookingglass.behavior import parse_seasonal_ignore, seasonal_ignored

# 2026-11-10 is a Tuesday
TUE = lambda h: datetime(2026, 11, 10, h)  # noqa: E731
MON = lambda h: datetime(2026, 11, 9, h)  # noqa: E731


def ignored(spec: str, metric: str, local: datetime) -> bool:
    return seasonal_ignored(parse_seasonal_ignore(spec), metric, local)


def test_plain_metric_is_ignored_always():
    assert ignored("blocks, source:nginx", "source:nginx", TUE(14))
    assert not ignored("blocks", "dns", TUE(14))


def test_day_and_hour_window():
    rule = "source:unraid tue 01-02"
    assert ignored(rule, "source:unraid", TUE(1))
    assert not ignored(rule, "source:unraid", TUE(2))   # the end hour is not included
    assert not ignored(rule, "source:unraid", TUE(0))
    assert not ignored(rule, "source:unraid", MON(1))   # other day
    assert not ignored(rule, "blocks", TUE(1))          # other metric


def test_every_day_hours_and_day_ranges():
    assert ignored("dns 02-04", "dns", MON(3)) and ignored("dns 02-04", "dns", TUE(2))
    assert ignored("dns 1:00-2:00", "dns", TUE(1))
    assert ignored("* sat+sun", "blocks", datetime(2026, 11, 15, 9))  # Sunday, any hour, any metric
    assert not ignored("* sat+sun", "blocks", TUE(9))
    assert ignored("blocks mon-fri", "blocks", datetime(2026, 11, 13, 9))  # Friday
    assert ignored("blocks fri-mon", "blocks", MON(9)) and not ignored("blocks fri-mon", "blocks", TUE(9))
    assert ignored("blocks Tuesday 00-24", "blocks", TUE(23))


def test_window_past_midnight_belongs_to_the_day_it_starts():
    rule = "blocks mon 22-06"
    assert ignored(rule, "blocks", MON(23))
    assert ignored(rule, "blocks", TUE(5))       # Monday night, after midnight
    assert not ignored(rule, "blocks", TUE(6))
    assert not ignored(rule, "blocks", TUE(23))  # Tuesday night is not Monday night
    assert not ignored(rule, "blocks", MON(5))   # that belongs to Sunday night


@pytest.mark.parametrize("bad", ["blocks tue 01", "blocks tue 25-26", "blocks tuex 01-02", "blocks 03-03",
                                 "blocks 01:30-02", "blocks tue wed", "blocks 01-02 03-04"])
def test_unreadable_entries_are_refused(bad):
    with pytest.raises(ValueError):
        parse_seasonal_ignore(bad)


def test_settings_refuse_an_unreadable_entry_and_keep_good_ones():
    f = next(f for f in app_config.FIELDS if f.key == "seasonal_ignore")
    assert app_config._coerce(f, "source:unraid tue 01-02\nblocks") == "source:unraid tue 01-02, blocks"
    with pytest.raises(app_config.SettingsError, match="tue 1-"):
        app_config._coerce(f, "source:unraid tue 1-")
