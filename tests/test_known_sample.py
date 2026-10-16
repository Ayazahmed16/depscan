"""Phase 4: the known test sample, with the expected results written down.

Input  tests/sample/requirements.txt and tests/sample/scan-report.json
Data   tests/sample/snapshot/ (REAL advisory, KEV and EPSS records for six packages, frozen on 2026-10-16,
       so these expectations cannot drift when the live data changes)

The sample covers: several known-vulnerable pins, one KEV-listed vulnerability, one uncertain match (a
withdrawn advisory), one clean package, one package that only a name-matching scanner would flag
(a false positive), and a scan report with false-positive and unconfirmed claims.

!! The expected values below were reasoned from the documented scoring rules (docs/SCORING.md) and checked
!! against the advisory ranges in tests/sample/labels.yaml. They have NOT been verified by the project owner.
!! A failing test here means "behaviour changed, re-read the expectation", not necessarily "bug".
"""
from pathlib import Path

import pytest
import yaml

from depscan.pipeline import DataBundle, scan_files
from depscan.report import NOTICE, render_html, render_markdown

SAMPLE = Path(__file__).parent / "sample"


@pytest.fixture(scope="module")
def bundle():
    return DataBundle(SAMPLE / "snapshot")  # no registry, no API: fully offline and deterministic


def scan(bundle, name):
    return scan_files([(name, (SAMPLE / name).read_bytes())], bundle)


@pytest.fixture(scope="module")
def reqs(bundle):
    return scan(bundle, "requirements.txt")


@pytest.fixture(scope="module")
def report(bundle):
    return scan(bundle, "scan-report.json")


def keys(result):
    return [(f["package"], f["id"]) for f in result["findings"]]


# ---------------------------------------------------------------------------------------------------------------
# requirements.txt: expected ranking, highest risk first.
#
# Why this order (default weights, see config/scoring.yaml):
#   1. pyspark CVE-2022-33891   the ONLY KEV-listed finding, with EPSS 93%: nothing else comes close.
#   2. pyspark CVE-2023-32007   very high EPSS (76%) and a same-major fix.
#   3-5. the three pyyaml CVEs  CVSS 9.8 each, EPSS 5-6% (ordered by EPSS: 14343 > 1747 > 20477).
#   6. pyspark CVE-2023-22946   CVSS 9.9 but EPSS only 1%, so it sits just below the pyyaml trio.
#   ... then lower CVSS / lower EPSS findings; the withdrawn pyyaml advisory (no CVSS, no EPSS) near the bottom.
# Adjacent scores can differ by less than 1 point (e.g. the pyyaml trio). If a weight in config/scoring.yaml
# changes, those neighbours may legitimately swap: update this list after re-reading the reasoning above.
EXPECTED_RANKING = [
    ("pyspark", "CVE-2022-33891"),
    ("pyspark", "CVE-2023-32007"),
    ("pyyaml", "CVE-2020-14343"),
    ("pyyaml", "CVE-2020-1747"),
    ("pyyaml", "CVE-2019-20477"),
    ("pyspark", "CVE-2023-22946"),
    ("flask", "CVE-2023-30861"),
    ("pyspark", "CVE-2025-55039"),
    ("pyspark", "CVE-2026-32773"),
    ("requests", "CVE-2024-35195"),
    ("pyspark", "CVE-2022-31777"),
    ("requests", "CVE-2024-47081"),
    ("pyyaml", "PYSEC-2020-195"),
    ("requests", "CVE-2026-25645"),
    ("flask", "CVE-2026-27205"),
]

# Minimum fixed version we must recommend for each finding (from the advisory `fixed` events).
EXPECTED_FIX = {
    "CVE-2022-33891": "3.2.2", "CVE-2023-32007": "3.2.2", "CVE-2023-22946": "3.3.2",   # GHSA says 3.3.2, PYSEC says 3.4.0: lowest wins
    "CVE-2025-55039": "3.4.4", "CVE-2026-32773": "3.5.8", "CVE-2022-31777": "3.2.2",
    "CVE-2020-14343": "5.4", "CVE-2020-1747": "5.3.1", "CVE-2019-20477": "5.2b1", "PYSEC-2020-195": "5.2b1",
    "CVE-2023-30861": "2.2.5", "CVE-2026-27205": "3.1.3",
    "CVE-2024-35195": "2.32.0", "CVE-2024-47081": "2.32.4", "CVE-2026-25645": "2.33.0",
}


def test_expected_ranking(reqs):
    assert keys(reqs) == EXPECTED_RANKING


def test_clean_and_false_positive_packages_have_no_findings(reqs):
    packages = {f["package"] for f in reqs["findings"]}
    assert "six" not in packages                # clean: no advisories exist
    assert "jinja2" not in packages             # 21 advisories exist, none include 3.1.6
    assert reqs["dependencies_read"] == 6


def test_boundary_version_that_is_itself_the_fix_is_not_flagged(reqs):
    ids = {f["id"] for f in reqs["findings"] if f["package"] == "flask"}
    assert "CVE-2019-1010083" not in ids        # "fixed 1.0" and the pin is exactly 1.0
    assert ids == {"CVE-2023-30861", "CVE-2026-27205"}


def test_kev_finding_is_first_and_flagged(reqs):
    top = reqs["findings"][0]
    assert top["id"] == "CVE-2022-33891" and top["kev"] is True and top["epss"] > 0.9
    assert top["risk"]["score"] > 90
    assert sum(1 for f in reqs["findings"] if f["kev"]) == 1
    assert next(r for r in top["risk"]["factors"] if r["name"] == "known_exploited")["value"].startswith("KEV, added")


def test_actions(reqs):
    actions = {(f["package"], f["id"]): f["action"] for f in reqs["findings"]}
    assert [k for k, a in actions.items() if a == "fix_now"] == EXPECTED_RANKING[:2]   # only the two highest-risk
    assert [k for k, a in actions.items() if a == "verify_first"] == [("pyyaml", "PYSEC-2020-195")]
    assert all(a == "monitor" for k, a in actions.items() if k not in EXPECTED_RANKING[:2] and k != ("pyyaml", "PYSEC-2020-195"))


def test_the_one_uncertain_match_is_the_withdrawn_advisory(reqs):
    uncertain = [f for f in reqs["findings"] if f["match"]["confidence"] == "uncertain"]
    assert [(f["package"], f["id"]) for f in uncertain] == [("pyyaml", "PYSEC-2020-195")]
    f = uncertain[0]
    assert any("withdrawn on 2023-03-14" in e for e in f["match"]["evidence"])
    assert f["cvss"] is None and f["epss"] is None                       # no severity data at all for it
    assert any("severity unknown" in n for n in f["risk"]["notes"])      # and it says so
    assert "Verify it before changing anything" in f["recommendation"]
    assert "pre-release" in f["recommendation"]                           # its fix, 5.2b1, is a beta


def test_every_other_match_is_confirmed_because_versions_are_pinned(reqs):
    others = [f for f in reqs["findings"] if f["id"] != "PYSEC-2020-195"]
    assert len(others) == 14 and all(f["match"]["confidence"] == "confirmed" for f in others)
    assert all(f["claim_status"] == "matched" for f in reqs["findings"])


def test_recommended_fixed_versions(reqs):
    assert {f["id"]: f["fixed_version"] for f in reqs["findings"]} == EXPECTED_FIX


def test_package_upgrade_targets(reqs):
    targets = {a["package"]: (a["target_version"], a["clears"], a["total"]) for a in reqs["package_actions"]}
    assert targets == {
        "pyspark": ("3.5.8", 6, 6),     # one version clears all six pyspark findings
        "pyyaml": ("5.4", 4, 4),
        "flask": ("3.1.3", 2, 2),
        "requests": ("2.33.0", 3, 3),
    }


def test_no_exposure_graph_means_the_exposure_factor_is_dropped(reqs):
    f = reqs["findings"][0]
    assert "exposure" not in [r["name"] for r in f["risk"]["factors"]]
    assert any("exposure factor dropped" in n for n in f["risk"]["notes"])


# ---------------------------------------------------------------------------------------------------------------
# scan-report.json: a Dependency-Check-style report. We re-check every claim against the advisory data.
#
# Expected order: our own matches first (by risk), then the one unconfirmed claim, then the two likely
# false positives. The contradicted claims have HIGHER raw risk than some confirmed findings (42.5 vs 41.0),
# which is exactly why the list is tiered instead of sorted by risk alone.
EXPECTED_REPORT = [
    ("flask", "CVE-2023-30861", "matched"),          # claimed by the scanner AND confirmed by advisory data
    ("requests", "CVE-2024-35195", "matched"),       # found by us although the report listed no claims
    ("requests", "CVE-2024-47081", "matched"),
    ("requests", "CVE-2026-25645", "matched"),
    ("flask", "CVE-2026-27205", "matched"),
    ("six", "CVE-2999-0001", "unconfirmed"),         # no advisory mentions it
    ("flask", "CVE-2019-1010083", "contradicted"),   # advisory says: fixed in 1.0
    ("jinja2", "CVE-2025-27516", "contradicted"),    # advisory says: fixed in 3.1.6
]


def test_report_expected_order_and_statuses(report):
    assert [(f["package"], f["id"], f["claim_status"]) for f in report["findings"]] == EXPECTED_REPORT


def test_false_positives_are_kept_flagged_not_dropped(report):
    fps = [f for f in report["findings"] if f["claim_status"] == "contradicted"]
    assert len(fps) == 2
    for f in fps:
        assert f["match"]["confidence"] == "uncertain" and f["action"] == "verify_first"
        assert any("NOT affected" in e for e in f["match"]["evidence"])
        assert "false positive" in f["recommendation"].lower()
        assert f["fixed_version"] is None


def test_unconfirmed_claim_is_uncertain_and_explained(report):
    [f] = [f for f in report["findings"] if f["claim_status"] == "unconfirmed"]
    assert f["id"] == "CVE-2999-0001" and f["match"]["confidence"] == "uncertain"
    assert any("no advisory in the OSV snapshot confirms it" in e for e in f["match"]["evidence"])


def test_confirmed_claim_says_the_scanner_agreed(report):
    f = report["findings"][0]
    assert any("also reported by the NVD" in e for e in f["match"]["evidence"])


def test_naive_scanner_would_report_more_than_we_do(report):
    """A scanner that trusts every claim reports 6 CVEs here; 3 of them are false or unconfirmed."""
    claimed = {"CVE-2023-30861", "CVE-2019-1010083", "CVE-2025-27516", "CVE-2999-0001"}
    ours_confirmed = {f["id"] for f in report["findings"] if f["claim_status"] == "matched"}
    assert claimed - ours_confirmed == {"CVE-2019-1010083", "CVE-2025-27516", "CVE-2999-0001"}


# ---------------------------------------------------------------------------------------------------------------
# labels.yaml agrees with what the tool does
def test_labels_agree_with_the_tool(reqs, report):
    labels = yaml.safe_load((SAMPLE / "labels.yaml").read_text("utf-8"))
    assert labels["verified_by_owner"] is False          # flip this only after the owner has checked the labels
    by_input = {"requirements.txt": reqs, "scan-report.json": report}
    for name, result in by_input.items():
        found = {(f["package"], f["id"]): f for f in result["findings"]}
        for item in labels["inputs"][name]:
            key = (item["package"], item.get("advisory"))
            label = item["label"]
            if label == "affected":
                assert key in found and found[key]["claim_status"] == "matched", key
            elif label == "retracted":
                assert found[key]["match"]["confidence"] == "uncertain" and found[key]["claim_status"] == "matched", key
            elif label == "false_positive":
                assert found[key]["claim_status"] == "contradicted", key
            elif label == "unconfirmed":
                assert found[key]["claim_status"] == "unconfirmed", key
            elif label in ("clean", "not_listed"):
                assert not any(p == item["package"] and (item.get("advisory") in (None, i)) for p, i in found), key
    # every finding the tool reports for requirements.txt has a label (nothing unexplained)
    labelled = {(i["package"], i["advisory"]) for i in labels["inputs"]["requirements.txt"] if "advisory" in i}
    assert set(keys(reqs)) <= labelled


# ---------------------------------------------------------------------------------------------------------------
def test_scan_is_deterministic(bundle):
    a, b = scan(bundle, "requirements.txt"), scan(bundle, "requirements.txt")
    a.pop("scanned_at"), b.pop("scanned_at")
    assert a == b


def test_sample_snapshot_is_frozen_real_data(bundle):
    assert bundle.snapshots == {"osv": "2026-10-16", "nvd": None, "kev": "2026-10-16", "epss": "2026-10-16"}
    note = (SAMPLE / "snapshot" / "manifest.json").read_text()
    assert "Extract of the live cache" in note


def test_reports_render_for_the_sample(reqs):
    md, page = render_markdown(reqs), render_html(reqs)
    for text in (md, page):
        assert NOTICE in text and "CVE-2022-33891" in text and "PYSEC-2020-195" in text
    assert md.count("### ") == 15   # one section per finding
