"""The watchlist rules and the shape of the timeline, on small hand-made histories (no data files)."""
import datetime as dt

from depscan.scoring.config import load_config
from depscan.temporal import watch_reason

CFG = load_config()
AS_OF = dt.date(2026, 10, 16)


def hist(*epss):
    return [{"date": f"2025-0{i + 1}-01", "risk": 40.0, "epss": e, "event": None, "simulated": False} for i, e in enumerate(epss)]


def test_a_big_absolute_epss_rise_is_watched():
    why = watch_reason(hist(0.01, 0.08), 40.0, None, AS_OF, CFG)
    assert why and "1.0%" in why and "8.0%" in why and "not yet in the critical tier" in why


def test_a_doubling_is_watched_but_only_from_a_meaningful_start():
    assert watch_reason(hist(0.02, 0.045), 40.0, None, AS_OF, CFG)             # 2% -> 4.5%: doubled, and started above the floor
    assert watch_reason(hist(0.001, 0.004), 40.0, None, AS_OF, CFG) is None    # 0.1% -> 0.4% is noise


def test_a_small_or_falling_epss_is_not_watched():
    assert watch_reason(hist(0.02, 0.03), 40.0, None, AS_OF, CFG) is None
    assert watch_reason(hist(0.30, 0.10), 40.0, None, AS_OF, CFG) is None


def test_one_epss_point_is_not_a_trend():
    assert watch_reason(hist(0.5), 40.0, None, AS_OF, CFG) is None
    assert watch_reason(hist(None, 0.5), 40.0, None, AS_OF, CFG) is None


def test_the_first_and_last_scored_points_are_compared_not_the_first_and_last_dates():
    h = hist(None, 0.01, 0.09, None)
    assert watch_reason(h, 40.0, None, AS_OF, CFG)


def test_findings_already_in_the_critical_tier_are_not_watched():
    assert watch_reason(hist(0.01, 0.9), 60.0, None, AS_OF, CFG) is None
    assert watch_reason(hist(0.01, 0.9), 59.9, None, AS_OF, CFG)
    assert watch_reason([], 80.0, "2026-10-10", AS_OF, CFG) is None


def test_a_recent_kev_listing_is_watched_an_old_one_is_not():
    assert "added to CISA KEV on 2026-10-10" in watch_reason([], 40.0, "2026-10-10", AS_OF, CFG)
    assert watch_reason([], 40.0, "2026-09-16", AS_OF, CFG)                     # exactly 30 days
    assert watch_reason([], 40.0, "2026-09-15", AS_OF, CFG) is None             # 31 days
    assert watch_reason([], 40.0, "2026-10-17", AS_OF, CFG) is None             # after the snapshot: not possible, not trusted
    assert watch_reason([], 40.0, "not a date", AS_OF, CFG) is None


def test_a_jump_of_five_points_counts_even_from_almost_zero():
    assert watch_reason(hist(0.001, 0.06), 40.0, None, AS_OF, CFG)             # only the absolute rule catches this (start is below the floor)
