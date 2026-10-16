"""Old or missing data must be said out loud: a stale scan must never read as a current one."""
import datetime as dt

from depscan.data.feeds import snapshot_warnings
from depscan.pipeline import DataBundle, scan_files

D = dt.date


def snaps(**kw):
    return {"osv": "2030-03-01", "nvd": "2030-03-01", "kev": "2030-03-01", "epss": "2030-03-01", **kw}


def test_fresh_data_has_no_warnings():
    assert snapshot_warnings(snaps(), D(2030, 3, 5), 14) == []


def test_old_snapshots_are_named_with_their_age():
    [w] = snapshot_warnings(snaps(osv="2030-01-01", epss="2030-03-01"), D(2030, 3, 5), 14)
    assert "osv 2030-01-01 (63 days old)" in w and "epss" not in w and "fetch_data.py" in w


def test_threshold_is_inclusive_of_the_limit():
    assert snapshot_warnings(snaps(), D(2030, 3, 15), 14) == []                      # exactly 14 days old
    assert len(snapshot_warnings(snaps(), D(2030, 3, 16), 14)) == 1                  # 15 days old


def test_missing_nvd_is_explained():
    [w] = snapshot_warnings(snaps(nvd=None), D(2030, 3, 5), 14)
    assert "NVD snapshot missing" in w and "OSV CVSS" in w and "rejected/disputed" in w


def test_unparsable_and_future_dates_do_not_crash_or_warn():
    assert snapshot_warnings(snaps(kev="not-a-date", epss="2031-01-01"), D(2030, 3, 5), 14) == []


def test_scan_reports_staleness_and_missing_nvd(data_dir):
    # the synthetic data_dir has snapshots dated 2030-03-01 and no NVD file
    bundle = DataBundle(data_dir)
    fresh = scan_files([("requirements.txt", b"alpha==1.0\n")], bundle, today=D(2030, 3, 2))
    assert any("NVD snapshot missing" in w for w in fresh["warnings"])
    assert not any("out of date" in w for w in fresh["warnings"])
    old = scan_files([("requirements.txt", b"alpha==1.0\n")], bundle, today=D(2030, 6, 1))
    assert any("advisory data is out of date" in w and "osv 2030-03-01" in w for w in old["warnings"])
    assert old["findings"]                                                          # a stale scan still returns findings


def test_stale_threshold_comes_from_the_config(data_dir):
    from depscan.scoring.config import load_config
    cfg = load_config()
    cfg["data"]["stale_days"] = 400
    r = scan_files([("requirements.txt", b"alpha==1.0\n")], DataBundle(data_dir), cfg, today=D(2030, 6, 1))
    assert not any("out of date" in w for w in r["warnings"])
