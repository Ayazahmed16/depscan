"""The benchmark harness: its oracle and metrics on hand-made cases, and the committed results against a fresh run."""
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from depscan import bench
from depscan.pipeline import DataBundle, scan_files

ROOT = Path(__file__).resolve().parent.parent


def rec(rid, events, versions=(), aliases=(), withdrawn=None, rtype="ECOSYSTEM"):
    return {"id": rid, "aliases": list(aliases), "withdrawn": withdrawn,
            "affected": [{"ranges": [{"type": rtype, "events": events}], "versions": list(versions)}]}


# ------------------------------------------------------------------ oracle
def test_oracle_follows_introduced_and_fixed():
    r = rec("X", [{"introduced": "1.0"}, {"fixed": "1.5"}])
    assert bench.oracle_affected("PyPI", "1.0", r) and bench.oracle_affected("PyPI", "1.4.9", r)
    assert not bench.oracle_affected("PyPI", "0.9", r)
    assert not bench.oracle_affected("PyPI", "1.5", r)                     # the fixed version itself is not affected


def test_oracle_last_affected_is_inclusive_and_ranges_can_repeat():
    r = rec("X", [{"introduced": "0"}, {"last_affected": "2.0"}, {"introduced": "3.0"}, {"fixed": "3.2"}])
    assert bench.oracle_affected("PyPI", "2.0", r) and not bench.oracle_affected("PyPI", "2.1", r)
    assert bench.oracle_affected("PyPI", "3.1", r) and not bench.oracle_affected("PyPI", "3.2", r)


def test_introduced_zero_is_below_every_version_including_go_pseudo_versions():
    """Regression: 'introduced 0' sorted AFTER a fixed pseudo-version (0.0.0-2018...), so v0.14.0 looked affected."""
    r = rec("X", [{"introduced": "0"}, {"fixed": "0.0.0-20180816102801-aaf60122140d"}], rtype="SEMVER")
    assert not bench.oracle_affected("Go", "0.14.0", r)
    assert not bench.oracle_affected("Go", "v0.14.0", r)
    assert bench.oracle_affected("Go", "0.0.0-20170101000000-aaaaaaaaaaaa", r)


def test_oracle_lists_versions_ignores_git_hashes_and_unknown_range_types():
    assert bench.oracle_affected("PyPI", "1.2", rec("X", [], versions=["1.2"]))
    assert not bench.oracle_affected("PyPI", "1.3", rec("X", [], versions=["1.2"]))
    r = rec("X", [{"introduced": "0"}, {"fixed": "9f2c1a7b6e5d4c3b2a1908f7e6d5c4b3a2918070"}])      # a commit, not a version
    assert bench.oracle_affected("PyPI", "1.0", r)                                                 # cannot be compared, so it never closes the range
    assert not bench.oracle_affected("PyPI", "1.0", rec("X", [{"introduced": "0"}], rtype="GIT"))
    assert not bench.oracle_affected("PyPI", "not a version", rec("X", [{"introduced": "0"}]))


def test_oracle_semver_prereleases_sort_below_the_release():
    r = rec("X", [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}], rtype="SEMVER")
    assert bench.oracle_affected("npm", "1.1.9", r) and not bench.oracle_affected("npm", "1.2.0", r)
    assert not bench.oracle_affected("npm", "1.0.0-beta.1", r)                                    # before 1.0.0
    assert bench.oracle_affected("npm", "1.2.0-rc.1", r)                                          # before the fix


def test_a_withdrawn_record_is_not_evidence():
    live, dead = rec("A", [{"introduced": "0"}], aliases=["CVE-1"]), rec("B", [{"introduced": "0"}], aliases=["CVE-1"], withdrawn="2024-01-01")
    assert bench.oracle_issue_affected("PyPI", "1.0", bench.group_records([live, dead])[0])
    assert not bench.oracle_issue_affected("PyPI", "1.0", bench.group_records([dead])[0])


def test_records_sharing_an_alias_are_one_issue_named_by_the_lowest_cve():
    groups = bench.group_records([
        rec("GHSA-1", [], aliases=["CVE-2020-0002"]), rec("PYSEC-1", [], aliases=["CVE-2020-0002", "GHSA-1"]),
        rec("GHSA-2", [], aliases=["CVE-2019-0001"]), rec("GO-1", []),
    ])
    assert [(g["canon"], len(g["records"])) for g in groups] == [("CVE-2019-0001", 1), ("CVE-2020-0002", 2), ("GO-1", 1)]
    assert groups[1]["ids"] == {"GHSA-1", "PYSEC-1", "CVE-2020-0002"}


# ------------------------------------------------------------------ metrics
def test_listing_metrics():
    m = bench.listing_metrics({"a", "b", "c", "d"}, {"a", "b", "z"})
    assert (m["reported"], m["true_positives"], m["false_positives"]) == (4, 2, 2)
    assert m["precision"] == 0.5 and m["recall"] == round(2 / 3, 3)
    empty = bench.listing_metrics(set(), {"a"})
    assert empty["precision"] is None and empty["recall"] == 0.0                # nothing reported: precision is undefined, not 100%
    assert bench.listing_metrics({"a"}, set())["recall"] is None


def test_top_n_metrics():
    ranked = ["a", "b", "c", "d", "e"]
    assert bench.top_n_metrics(ranked, {"c", "e"}) == {"hits": 1, "possible": 2, "share": 0.5, "first_rank": 3}
    assert bench.top_n_metrics(ranked, {"a", "b", "c", "d"}) == {"hits": 3, "possible": 3, "share": 1.0, "first_rank": 1}
    assert bench.top_n_metrics(ranked, {"zz"}) == {"hits": 0, "possible": 1, "share": 0.0, "first_rank": None}   # not listed at all
    assert bench.top_n_metrics([], {"a"})["first_rank"] is None
    assert bench.top_n_metrics(ranked, set())["share"] is None


def test_cvss_order_ignores_everything_but_the_score():
    by_key = {("p", "a"): {"cvss": 5.0}, ("p", "b"): {"cvss": 9.8}, ("p", "c"): {"cvss": None}, ("p", "d"): {"cvss": 9.8}}
    assert bench.cvss_order(list(by_key), by_key) == [("p", "b"), ("p", "d"), ("p", "a"), ("p", "c")]


def test_without_kev_renormalises_the_other_weights():
    from depscan.scoring.config import load_config
    cfg = load_config()
    out = bench.without_kev(cfg)
    w = out["risk"]["weights"]
    assert w["known_exploited"] == 0 and abs(sum(w.values()) - 1) < 1e-9
    assert cfg["risk"]["weights"]["known_exploited"] > 0                        # the original is untouched


# ------------------------------------------------------------------ the committed fixtures and results
@pytest.fixture(scope="module")
def results():
    return bench.run_all()


def test_the_nine_fixtures_run_and_the_labels_are_marked_unverified(results):
    assert [f["name"] for f in results["fixtures"]] == [
        "known-sample", "known-sample-report", "django-app", "py-web-old", "py-kev-mix", "npm-old", "go-old", "clean-current", "boundary"]
    assert results["labels_verified_by_owner"] is False
    for path in (ROOT / "benchmark" / "labels.yaml", ROOT / "tests" / "sample" / "labels.yaml"):
        text = path.read_text("utf-8")
        assert "NEEDS MANUAL VERIFICATION" in text and yaml.safe_load(text)["verified_by_owner"] is False
    assert "needs manual verification" in (ROOT / "docs" / "BENCHMARK.md").read_text("utf-8").lower()


def test_committed_results_and_tables_are_up_to_date(results):
    committed = (ROOT / "benchmark" / "results.json").read_text("utf-8")
    assert committed == json.dumps(results, indent=1, sort_keys=True) + "\n"
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "benchmark.py"), "--check"], capture_output=True, text=True, cwd=ROOT)
    assert out.returncode == 0 and "up to date" in out.stdout, out.stdout + out.stderr


def test_the_run_is_deterministic(results):
    assert bench.run_all() == results


def test_every_non_hand_fixture_has_a_label_entry():
    labels = yaml.safe_load((ROOT / "benchmark" / "labels.yaml").read_text("utf-8"))["fixtures"]
    wanted = {f.name for f in bench.load_fixtures() if "hand" not in f.labels}
    assert wanted == set(labels)


def test_naive_matching_by_name_is_worse_than_version_aware_matching(results):
    t = results["totals"]
    assert t["depscan"]["reported"] < t["naive"]["reported"] and t["depscan"]["precision"] > t["naive"]["precision"]
    assert t["depscan"]["recall"] >= 0.95                                        # a floor, not the observed value
    by = {f["name"]: f for f in results["fixtures"]}
    assert by["clean-current"]["naive"]["false_positives"] > 100                 # a name match flags everything, even current pins
    assert by["clean-current"]["depscan"]["reported"] <= 1
    assert by["known-sample-report"]["naive"]["precision"] < 0.5                 # report claims at boundary versions and unconfirmed ids


def test_boundary_versions_are_not_reported():
    """The pin equals an advisory's fixed version: that advisory must not appear."""
    fx = next(f for f in bench.load_fixtures() if f.name == "boundary")
    res = scan_files([(p.name, p.read_bytes()) for p in fx.inputs], DataBundle(fx.snapshot))
    seen = {(f["package"], f["id"]) for f in res["findings"]}
    assert ("pyyaml", "CVE-2020-1747") not in seen                               # fixed in exactly 5.3.1
    assert not any(p == "requests" and i == "CVE-2023-32681" for p, i in seen)  # fixed in exactly 2.31.0


def test_depscan_reports_nothing_the_labels_call_unaffected_and_misses_only_the_listed_cases(results):
    for r in results["fixtures"]:
        assert r["disagreements"]["reported_but_not_labelled_affected"] == [], r["name"]
    missed = [(r["name"], e["package"], e["id"]) for r in results["fixtures"] for e in r["disagreements"]["labelled_affected_but_not_reported"]]
    assert missed == [("py-kev-mix", "apache-airflow", "CVE-2024-32077"), ("py-kev-mix", "apache-airflow", "CVE-2024-45498"),
                      ("py-kev-mix", "apache-airflow", "CVE-2025-54831")]          # documented in docs/BENCHMARK.md


def test_the_ranking_numbers_match_the_table_arithmetic(results):
    t = results["totals"]["ranking"]
    rows = [r for r in results["fixtures"] if r["known_exploited_affected"]]
    for name in ("cvss_only", "depscan", "depscan_without_kev_weight"):
        assert t[name]["hits"] == sum(r["ranking"][name]["hits"] for r in rows)
        assert t[name]["possible"] == sum(r["ranking"][name]["possible"] for r in rows)
        assert t[name]["fixtures_counted"] == len(rows)
    assert t["depscan"]["hits"] > t["cvss_only"]["hits"]                         # on these fixtures; see the limits in docs/BENCHMARK.md


def test_the_django_fixture_exposure_matches_its_construction(results):
    django = next(r for r in results["fixtures"] if r["name"] == "django-app")
    assert django["reachability"]["exposure_matches_design"] is True
    assert django["reachability"]["web_reachable_affected"] == 6
