"""Phase 5: the trust layer. Every signal, the action matrix, and "high risk + low trust = verify first"."""
import datetime as dt
import json

import pytest

from depscan.matcher import match_dependency
from depscan.models import CONFIDENCE_ORDER, Dependency, ScannerClaim
from depscan.pipeline import DataBundle, make_release_check, scan_files
from depscan.registry import Registry
from depscan.scoring.config import load_config
from depscan.scoring.recommend import decide_action
from depscan.scoring.trust import compute_trust, level

CFG = load_config()
T = CFG["trust"]
AS_OF = dt.date(2030, 3, 1)


def adv(id, aliases=(), fixed="1.4", modified="2030-01-01T00:00:00Z", summary="s", withdrawn=None, fix_refs=(), severity=(), label=None):
    return {"id": id, "aliases": list(aliases), "summary": summary, "modified": modified, "withdrawn": withdrawn,
            "fix_refs": list(fix_refs), "severity": list(severity), "label": label,
            "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": fixed}]}], "versions": []}]}


def dep(version="1.2", **kw):
    return Dependency(name="pkg", ecosystem="PyPI", spec=f"=={version}", version=version, lower_bound=version, **kw)


def trust(records, *, nvd=None, fixed="1.4", release_exists=None, d=None, as_of=AS_OF):
    [m] = match_dependency(d or dep(), records)
    return compute_trust(m, nvd=nvd or {}, fixed_version=fixed, as_of=as_of, cfg=CFG, release_exists=release_exists)


def sig(result, name):
    return next(s for s in result["signals"] if s["name"] == name)


def effect(result, name):
    return sig(result, name)["effect"]


GOOD = [adv("GHSA-a", ["CVE-2030-1"]), adv("PYSEC-1", ["CVE-2030-1", "GHSA-a"])]


# ---------------------------------------------------------------- transparency
def test_score_is_exactly_base_plus_the_listed_effects_when_not_clamped():
    r = trust(GOOD)
    assert r["score"] == pytest.approx(T["base"] + sum(s["effect"] for s in r["signals"]))
    assert r["base"] == T["base"] and 0 < r["score"] < 100


def test_every_signal_is_always_listed_with_name_value_effect_note():
    r = trust([adv("GHSA-a", ["CVE-2030-1"])])
    names = [s["name"] for s in r["signals"]]
    assert {"independent sources", "version ranges", "fixed versions", "withdrawn", "NVD status", "disputed",
            "last modified", "fix", "match confidence", "severity"} <= set(names)
    assert all(set(s) == {"name", "value", "effect", "note"} and s["note"] for s in r["signals"])


def test_score_is_clamped_to_0_100():
    worst = trust([adv("GHSA-a", ["CVE-2030-1"], withdrawn="2029-01-01T00:00:00Z")], nvd={"CVE-2030-1": {"vulnStatus": "Rejected", "tags": ["disputed"]}}, fixed=None)
    assert worst["score"] == 0.0 and sum(s["effect"] for s in worst["signals"]) + T["base"] < 0
    assert 0 <= trust(GOOD, nvd={"CVE-2030-1": {"vulnStatus": "Analyzed", "cvss": {"v31": {"score": 9.8}}}})["score"] <= 100


def test_best_case_stays_below_the_ceiling_so_strong_findings_are_distinguishable():
    best = T["base"] + max(T["sources"].values()) + T["ranges_agree"] + T["nvd_analysed"] + T["fresh"] + T["fix_release_exists"] \
        + T["confidence"]["confirmed"] + T["severity_agree"]
    assert best < 100


# ---------------------------------------------------------------- sources
def test_source_count_uses_distinct_databases_and_nvd():
    one = trust([adv("GHSA-a", ["CVE-2030-1"])])
    assert sig(one, "independent sources")["value"] == "1" and effect(one, "independent sources") == T["sources"][1]
    two = trust(GOOD)                                              # GHSA + PYSEC
    assert effect(two, "independent sources") == T["sources"][2]
    assert "GitHub Advisory Database" in sig(two, "independent sources")["note"]
    three = trust(GOOD, nvd={"CVE-2030-1": {"vulnStatus": "Analyzed"}})   # + NVD
    assert effect(three, "independent sources") == T["sources"][3] and "NVD" in sig(three, "independent sources")["note"]
    many = trust([adv("GHSA-a", ["CVE-2030-1", "BIT-x", "RUSTSEC-y", "GO-z"])], nvd={"CVE-2030-1": {"vulnStatus": "Analyzed"}})
    assert effect(many, "independent sources") == T["sources"][4]  # 4+ is capped


def test_a_rejected_nvd_record_and_withdrawn_records_do_not_count_as_sources():
    r = trust([adv("GHSA-a", ["CVE-2030-1"])], nvd={"CVE-2030-1": {"vulnStatus": "Rejected"}})
    assert sig(r, "independent sources")["value"] == "1"
    w = trust([adv("GHSA-a", ["CVE-2030-1"], withdrawn="2029-01-01T00:00:00Z")])
    assert sig(w, "independent sources")["value"] == "0" and effect(w, "independent sources") == T["sources"][0]


# ---------------------------------------------------------------- ranges and fixes
def test_ranges_agree_disagree_and_single_source():
    assert effect(trust(GOOD), "version ranges") == T["ranges_agree"]
    single = trust([adv("GHSA-a", ["CVE-2030-1"])])
    assert effect(single, "version ranges") == 0 and sig(single, "version ranges")["value"] == "one source"
    dissent = trust([adv("GHSA-a", ["CVE-2030-1"], fixed="1.4"), adv("PYSEC-1", ["CVE-2030-1", "GHSA-a"], fixed="1.1")])
    s = sig(dissent, "version ranges")
    assert s["effect"] == T["ranges_disagree"] and "PYSEC-1" in s["note"] and "NOT affected" in s["note"]


def test_different_fixed_versions_are_named():
    r = trust([adv("GHSA-a", ["CVE-2030-1"], fixed="1.4"), adv("PYSEC-1", ["CVE-2030-1", "GHSA-a"], fixed="1.6")])
    s = sig(r, "fixed versions")
    assert s["effect"] == T["fix_versions_disagree"] and "GHSA-a says 1.4" in s["note"] and "PYSEC-1 says 1.6" in s["note"]
    assert effect(trust(GOOD), "fixed versions") == 0


# ---------------------------------------------------------------- status
def test_withdrawn_duplicate_vs_all_withdrawn():
    dupe = trust([adv("GHSA-a", ["CVE-2030-1"]), adv("PYSEC-old", ["CVE-2030-1", "GHSA-a"], withdrawn="2029-01-01T00:00:00Z")])
    assert effect(dupe, "withdrawn") == T["withdrawn_some"] and "PYSEC-old" in sig(dupe, "withdrawn")["note"]
    allw = trust([adv("GHSA-a", ["CVE-2030-1"], withdrawn="2029-01-01T00:00:00Z")])
    assert effect(allw, "withdrawn") == T["withdrawn_all"]
    assert effect(trust(GOOD), "withdrawn") == 0


@pytest.mark.parametrize("status,expected", [
    ("Rejected", "nvd_rejected"), ("Analyzed", "nvd_analysed"), ("Modified", "nvd_analysed"),
    ("Awaiting Analysis", "nvd_pending"), ("Deferred", "nvd_pending"), ("Undergoing Analysis", "nvd_pending"), ("Received", "nvd_pending"),
])
def test_nvd_status_signal(status, expected):
    assert effect(trust(GOOD, nvd={"CVE-2030-1": {"vulnStatus": status}}), "NVD status") == T[expected]


def test_no_nvd_record_is_neutral():
    s = sig(trust(GOOD), "NVD status")
    assert s["effect"] == 0 and s["value"] == "not in NVD"


def test_disputed_from_nvd_tag_and_from_advisory_text():
    by_tag = trust(GOOD, nvd={"CVE-2030-1": {"vulnStatus": "Analyzed", "tags": ["disputed"]}})
    assert effect(by_tag, "disputed") == T["disputed"] and "NVD tags it disputed" in sig(by_tag, "disputed")["note"]
    by_text = trust([adv("PYSEC-1", ["CVE-2030-1"], summary="** DISPUTED ** An issue was discovered")])
    assert effect(by_text, "disputed") == T["disputed"] and "marked ** DISPUTED **" in sig(by_text, "disputed")["note"]
    assert effect(trust(GOOD), "disputed") == 0


def test_unsupported_when_assigned_tag():
    r = trust(GOOD, nvd={"CVE-2030-1": {"vulnStatus": "Analyzed", "tags": ["unsupported-when-assigned"]}})
    assert effect(r, "unsupported product") == T["unsupported_when_assigned"]
    assert "unsupported product" not in [s["name"] for s in trust(GOOD)["signals"]]


# ---------------------------------------------------------------- observed exploitation
def test_kev_listing_is_independent_proof_the_vulnerability_is_real():
    [m] = match_dependency(dep(), GOOD)
    hit = compute_trust(m, nvd={}, kev={"CVE-2030-1": {"dateAdded": "2030-02-01"}}, fixed_version="1.4", as_of=AS_OF, cfg=CFG)
    s = sig(hit, "known exploited")
    assert s["effect"] == T["kev_listed"] and "2030-02-01" in s["value"] and "independent confirmation" in s["note"]
    miss = trust(GOOD)
    assert effect(miss, "known exploited") == 0 and sig(miss, "known exploited")["value"] == "not in KEV"
    assert hit["score"] == pytest.approx(miss["score"] + T["kev_listed"])


def test_a_weakly_documented_but_actively_exploited_vulnerability_is_not_sent_to_verify_first(data_dir):
    """One database, a 5-year-old record, no NVD record: trust 44 alone. CISA KEV lifts it past the fix-now minimum."""
    f = scan_files([("requirements.txt", b"alpha==1.0\n")], DataBundle(data_dir))["findings"][0]
    assert f["kev"] and sig(f["trust"], "independent sources")["value"] == "1" and sig(f["trust"], "last modified")["effect"] == T["stale"]
    assert f["trust"]["score"] == T["base"] + T["sources"][1] + T["stale"] + T["fix_release_exists"] + T["confidence"]["confirmed"] + T["kev_listed"]
    assert f["trust"]["score"] >= CFG["actions"]["fix_now_min_trust"] and f["action"] == "fix_now"


# ---------------------------------------------------------------- freshness (measured at the snapshot date, not today)
@pytest.mark.parametrize("modified,expected", [
    ("2030-02-01T00:00:00Z", "fresh"),       # 28 days
    ("2029-03-01T00:00:00Z", "fresh"),       # exactly 365 days: still fresh
    ("2028-09-01T00:00:00Z", None),          # about 18 months: neither
    ("2027-03-01T00:00:00Z", "stale"),       # 3 years
])
def test_freshness_bands(modified, expected):
    r = trust([adv("GHSA-a", ["CVE-2030-1"], modified=modified)])
    assert effect(r, "last modified") == (T[expected] if expected else 0)


def test_freshness_uses_the_newest_date_including_nvd_and_reproduces_from_the_snapshot():
    old = [adv("GHSA-a", ["CVE-2030-1"], modified="2020-01-01T00:00:00Z")]
    assert effect(trust(old), "last modified") == T["stale"]
    assert effect(trust(old, nvd={"CVE-2030-1": {"lastModified": "2030-02-20T00:00:00.000"}}), "last modified") == T["fresh"]
    assert trust(old, as_of=dt.date(2020, 6, 1)) == trust(old, as_of=dt.date(2020, 6, 1))  # same snapshot date, same answer
    assert effect(trust(old, as_of=dt.date(2020, 6, 1)), "last modified") == T["fresh"]


# ---------------------------------------------------------------- does a fix exist?
def test_fix_signal_variants():
    assert effect(trust(GOOD), "fix") == T["fix_release_exists"] and "not checked against the registry" in sig(trust(GOOD), "fix")["note"]
    commit = trust([adv("GHSA-a", ["CVE-2030-1"], fix_refs=["https://example.test/c"])], fixed=None)
    assert effect(commit, "fix") == T["fix_commit_only"] and sig(commit, "fix")["value"] == "commit only"
    none = trust([adv("GHSA-a", ["CVE-2030-1"])], fixed=None)
    assert effect(none, "fix") == T["no_fix"]


def test_fix_is_checked_against_the_registry_when_possible():
    yes = trust(GOOD, release_exists=lambda e, n, v: True)
    assert effect(yes, "fix") == T["fix_release_exists"] and "found on the package registry" in sig(yes, "fix")["note"]
    no = trust(GOOD, release_exists=lambda e, n, v: False)
    s = sig(no, "fix")
    assert s["effect"] == T["fix_not_on_registry"] and "no such release" in s["note"] and "not on registry" in s["value"]
    unknown = trust(GOOD, release_exists=lambda e, n, v: None)         # registry unreachable: no penalty, says so
    assert effect(unknown, "fix") == T["fix_release_exists"] and "not checked" in sig(unknown, "fix")["note"]


def test_make_release_check_compares_versions_properly(tmp_path):
    import urllib.error

    class Net:
        def __call__(self, url, timeout):
            if "pypi.org/pypi/pkg/" in url:
                return json.dumps({"releases": {"1.4": [{"yanked": False}], "1.5rc1": [{"yanked": False}], "weird!": [{"yanked": False}]}}).encode()
            raise urllib.error.URLError("down")
    check = make_release_check(Registry(tmp_path, get=Net()))
    assert check("PyPI", "pkg", "1.4") is True
    assert check("PyPI", "pkg", "1.4.0") is True                      # PEP 440: 1.4 == 1.4.0
    assert check("PyPI", "pkg", "1.5rc1") is True
    assert check("PyPI", "pkg", "9.9") is False
    assert check("PyPI", "pkg", "not a version") is None
    assert check("PyPI", "other", "1.0") is None                      # registry unreachable for it
    assert check("Go", "x", "1.0") is None                            # ecosystem the registry does not cover
    assert make_release_check(None)("PyPI", "pkg", "1.4") is None


# ---------------------------------------------------------------- match confidence and scan-report claims
@pytest.mark.parametrize("conf", CONFIDENCE_ORDER)
def test_match_confidence_signal_for_every_level(conf):
    [m] = match_dependency(dep(), GOOD)
    m.confidence = conf
    r = compute_trust(m, nvd={}, fixed_version="1.4", as_of=AS_OF, cfg=CFG)
    assert effect(r, "match confidence") == T["confidence"][conf]
    assert T["confidence"]["confirmed"] > T["confidence"]["likely"] > T["confidence"]["possible"] > T["confidence"]["probable"] > T["confidence"]["uncertain"]


def test_scan_report_claims_the_data_does_not_back_get_very_low_trust():
    d = dep(claims=[ScannerClaim("CVE-2999-1", "HIGH", 8.0, "LOW", "NVD")])
    [m] = match_dependency(d, [])
    r = compute_trust(m, nvd={}, fixed_version=None, as_of=AS_OF, cfg=CFG)
    assert effect(r, "scan-report claim") == T["claim"]["unconfirmed"] and r["score"] <= 5
    d2 = dep("1.5", claims=[ScannerClaim("CVE-2030-1", "HIGH", 8.0, "HIGH", "NVD")])
    [m2] = match_dependency(d2, [adv("GHSA-a", ["CVE-2030-1"])])
    assert m2.contradicted
    r2 = compute_trust(m2, nvd={}, fixed_version=None, as_of=AS_OF, cfg=CFG)
    assert effect(r2, "scan-report claim") == T["claim"]["contradicted"] and r2["level"] == "low"


# ---------------------------------------------------------------- severity agreement
VEC98 = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]   # computes to 9.8


def test_severity_signal_variants():
    agree = trust([adv("GHSA-a", ["CVE-2030-1"], severity=VEC98)], nvd={"CVE-2030-1": {"vulnStatus": "Analyzed", "cvss": {"v31": {"score": 9.8}}}})
    assert effect(agree, "severity") == T["severity_agree"]
    near = trust([adv("GHSA-a", ["CVE-2030-1"], severity=VEC98)], nvd={"CVE-2030-1": {"cvss": {"v30": {"score": 9.0}}}})
    assert effect(near, "severity") == T["severity_agree"]                                  # within the 1.0 tolerance
    differ = trust([adv("GHSA-a", ["CVE-2030-1"], severity=VEC98)], nvd={"CVE-2030-1": {"cvss": {"v31": {"score": 4.8}}}})
    assert effect(differ, "severity") == T["severity_differ"] and "NVD 4.8, OSV 9.8" in sig(differ, "severity")["value"]
    one = trust([adv("GHSA-a", ["CVE-2030-1"], severity=VEC98)])
    assert effect(one, "severity") == 0 and sig(one, "severity")["value"] == "one source"
    unknown = trust([adv("GHSA-a", ["CVE-2030-1"])])
    assert effect(unknown, "severity") == T["severity_unknown"]
    label_only = trust([adv("GHSA-a", ["CVE-2030-1"], label="HIGH")])
    assert effect(label_only, "severity") == 0                                              # a label counts as published severity


def test_level_bands_follow_config():
    assert [level(s, CFG) for s in (100, 60, 59.9, 30, 29.9, 0)] == ["high", "high", "medium", "medium", "low", "low"]


# ---------------------------------------------------------------- actions: risk AND trust
@pytest.mark.parametrize("risk,trust_score,uncertain,expected", [
    (96, 94, False, "fix_now"),          # high risk, high trust
    (96, 50, False, "fix_now"),          # exactly at the trust minimum
    (96, 49.9, False, "verify_first"),   # high risk but not trustworthy enough: verify first
    (96, 0, False, "verify_first"),
    (80, 90, True, "verify_first"),      # uncertain match always needs verifying
    (45, 90, False, "monitor"),
    (45, 35, False, "monitor"),
    (45, 34.9, False, "verify_first"),   # medium risk, low trust
    (10, 0, False, "no_action"),         # low risk stays low risk even with low trust
    (59.9, 90, False, "monitor"),
    (60, 90, False, "fix_now"),
])
def test_decide_action_matrix(risk, trust_score, uncertain, expected):
    assert decide_action(risk, trust_score, CFG, uncertain=uncertain) == expected


# ---------------------------------------------------------------- end to end: the headline requirement
def write_nvd(data_dir, **rec):
    (data_dir / "nvd.json").write_text(json.dumps({"timestamp": "2030-03-01", "records": {"CVE-2030-0001": {
        "id": "CVE-2030-0001", "lastModified": "2030-02-01T00:00:00.000", "cvss": {"v31": {"score": 9.8}}, **rec}}}))
    manifest = json.loads((data_dir / "manifest.json").read_text())
    manifest["nvd"] = {"snapshot_date": "2030-03-01"}
    (data_dir / "manifest.json").write_text(json.dumps(manifest))


def test_high_risk_with_low_trust_reads_verify_first_not_fix_now(data_dir):
    """alpha 1.0 / CVE-2030-0001 is in KEV with EPSS 0.9 and CVSS 9.8: very high risk either way."""
    write_nvd(data_dir, vulnStatus="Analyzed", tags=[])
    solid = scan_files([("requirements.txt", b"alpha==1.0\n")], DataBundle(data_dir))["findings"][0]
    assert solid["risk"]["score"] >= 60 and solid["action"] == "fix_now"

    write_nvd(data_dir, vulnStatus="Rejected", tags=["disputed"])           # same advisory, but NVD rejected it and it is disputed
    doubted = scan_files([("requirements.txt", b"alpha==1.0\n")], DataBundle(data_dir))["findings"][0]
    assert doubted["risk"]["score"] == solid["risk"]["score"]               # risk is unchanged: it is a separate question
    assert doubted["trust"]["score"] < CFG["actions"]["fix_now_min_trust"] < solid["trust"]["score"]
    assert doubted["action"] == "verify_first"
    assert {s["name"] for s in doubted["trust"]["signals"] if s["effect"] < 0} >= {"NVD status", "disputed"}


def test_findings_expose_trust_in_the_shape_the_frontend_reads(data_dir):
    f = scan_files([("requirements.txt", b"alpha==1.0\n")], DataBundle(data_dir))["findings"][0]
    assert set(f["trust"]) == {"score", "level", "base", "signals"}
    assert all(isinstance(s["effect"], (int, float)) and isinstance(s["value"], str) for s in f["trust"]["signals"])


def test_reports_show_trust_and_every_signal(data_dir):
    from depscan.report import render_html, render_markdown
    r = scan_files([("requirements.txt", b"alpha==1.0\n")], DataBundle(data_dir))
    md, page = render_markdown(r), render_html(r)
    for text in (md, page):
        assert "Trust" in text and "independent sources" in text and "match confidence" in text
    assert "| # | Advisory | Package | Risk | Trust |" in md and "Trust signals (start at 40" in md


def test_a_yanked_fixed_version_is_not_reported_as_missing():
    r = trust(GOOD, release_exists=lambda e, n, v: "yanked")
    s = sig(r, "fix")
    assert s["effect"] == T["fix_yanked"] and s["value"] == "1.4 yanked" and "yanked" in s["note"] and "no such release" not in s["note"]
    assert T["fix_not_on_registry"] < T["fix_yanked"] < T["fix_release_exists"]        # yanked is milder than never-existed


def test_make_release_check_reports_yanked(tmp_path):
    class Net:
        def __call__(self, url, timeout):
            return json.dumps({"releases": {"1.4": [{"yanked": False}], "1.5": [{"yanked": True}]}}).encode()
    check = make_release_check(Registry(tmp_path, get=Net()))
    assert check("PyPI", "pkg", "1.4") is True and check("PyPI", "pkg", "1.5") == "yanked" and check("PyPI", "pkg", "2.0") is False
