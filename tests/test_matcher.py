"""Phase 2 tests: version logic and matching, on synthetic advisories with known answers."""
from pathlib import Path

import pytest

from depscan.data.osv import load_osv_index
from depscan.matcher import match_all, match_dependency
from depscan.matcher.versions import SemVer, evaluate_advisory, evaluate_range, major_of
from depscan.models import Dependency, ScannerClaim

REAL_DATA = Path(__file__).resolve().parent.parent / "data"


def rng(*events):
    return {"type": "ECOSYSTEM", "events": list(events)}


# ---------------------------------------------------------------- versions
def test_semver_precedence():
    order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.10.0", "2.0.0"]
    parsed = [SemVer(v) for v in order]
    assert parsed == sorted(parsed)
    assert SemVer("1.0.0+build1") == SemVer("1.0.0")  # build metadata is ignored


@pytest.mark.parametrize("version,affected,fixed", [
    ("0.9", False, None),      # before introduced
    ("1.0", True, "1.4"),      # at introduced (inclusive)
    ("1.3.9", True, "1.4"),
    ("1.4", False, None),      # at fixed (exclusive)
    ("1.5", False, None),
    ("2.1", True, "2.3"),      # second interval
    ("2.3", False, None),
])
def test_pep440_two_intervals(version, affected, fixed):
    r = rng({"introduced": "1.0"}, {"fixed": "1.4"}, {"introduced": "2.0"}, {"fixed": "2.3"})
    hit, fix, _ = evaluate_range("PyPI", version, r)
    assert (hit, fix) == (affected, fixed)


def test_introduced_zero_and_last_affected():
    assert evaluate_range("PyPI", "0.0.1", rng({"introduced": "0"}, {"fixed": "1.0"}))[0]
    r = rng({"introduced": "0"}, {"last_affected": "1.9"})
    assert evaluate_range("PyPI", "1.9", r)[0] and not evaluate_range("PyPI", "1.9.1", r)[0]
    assert evaluate_range("PyPI", "5.0", rng({"introduced": "0"}))[1] is None  # still vulnerable, no fix listed


def test_pep440_prerelease_ordering():
    r = rng({"introduced": "0"}, {"fixed": "2.0"})
    assert evaluate_range("PyPI", "2.0rc1", r)[0]       # a release candidate sorts below 2.0
    assert not evaluate_range("PyPI", "2.0.post1", r)[0]


def test_event_order_in_file_does_not_matter():
    r = rng({"fixed": "1.4"}, {"introduced": "1.0"})
    assert evaluate_range("PyPI", "1.2", r)[0]


def test_npm_semver_prerelease():
    r = {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}
    assert evaluate_range("npm", "2.0.0-rc.1", r)[0]
    assert not evaluate_range("npm", "2.0.0", r)[0]


def test_explicit_versions_list_and_git_only_records():
    entry = {"ranges": [{"type": "GIT", "events": [{"introduced": "abc"}]}], "versions": ["1.1"]}
    assert evaluate_advisory("PyPI", "1.1", [entry])[0] is True
    assert evaluate_advisory("PyPI", "9.9", [entry])[0] is None  # git ranges cannot decide


def test_unparsable_version_is_undecided_not_a_crash():
    affected, _, why = evaluate_advisory("PyPI", "not-a-version", [{"ranges": [rng({"introduced": "0"}, {"fixed": "1"})]}])
    assert affected is None and "could not compare" in why


def test_major_of():
    assert major_of("PyPI", "3.2.1") == 3 and major_of("npm", "4.17.21") == 4 and major_of("npm", "x") is None


# ---------------------------------------------------------------- matching
def adv(id, aliases=(), fixed="1.4", introduced="1.0", **extra):
    return {"id": id, "aliases": list(aliases), "modified": "2024-01-01T00:00:00Z",
            "affected": [{"ranges": [rng({"introduced": introduced}, {"fixed": fixed})], "versions": []}], **extra}


def dep(version="1.2", exact=True, **kw):
    return Dependency(name="pkg", ecosystem="PyPI", spec=f"=={version}" if exact else f">={version}",
                      version=version if exact else None, lower_bound=version, **kw)


def test_exact_match_has_evidence_and_fix():
    [m] = match_dependency(dep(), [adv("PYSEC-1", ["CVE-2020-1"])])
    assert m.id == "CVE-2020-1" and m.aliases == ["PYSEC-1"]
    assert m.confidence == "exact" and m.fixed_versions == ["1.4"]
    assert "inside the range introduced 1.0, fixed 1.4" in m.evidence[0]


def test_range_spec_gives_probable_with_explanation():
    [m] = match_dependency(dep(exact=False), [adv("PYSEC-1")])
    assert m.confidence == "probable"
    assert any("lowest version it allows" in e for e in m.evidence)


def test_clean_version_has_no_match():
    assert match_dependency(dep("1.5"), [adv("PYSEC-1")]) == []
    assert match_dependency(dep("0.5"), [adv("PYSEC-1")]) == []


def test_two_records_for_same_cve_merge_into_one_finding():
    ghsa = adv("GHSA-aaaa", ["CVE-2020-1"])
    pysec = adv("PYSEC-1", ["CVE-2020-1", "GHSA-aaaa"])
    [m] = match_dependency(dep(), [ghsa, pysec])
    assert m.id == "CVE-2020-1" and sorted(m.aliases) == ["GHSA-aaaa", "PYSEC-1"]
    assert len(m.verdicts) == 2 and m.confidence == "exact"


def test_disagreeing_sources_make_the_match_uncertain():
    yes = adv("GHSA-aaaa", ["CVE-2020-1"], fixed="1.4")
    no = adv("PYSEC-1", ["CVE-2020-1"], fixed="1.1")  # this record thinks 1.2 is already fixed
    [m] = match_dependency(dep(), [yes, no])
    assert m.confidence == "uncertain"
    assert any("sources disagree" in e for e in m.evidence)


def test_withdrawn_advisory_is_uncertain():
    [m] = match_dependency(dep(), [adv("GHSA-x", withdrawn="2023-05-05T00:00:00Z")])
    assert m.confidence == "uncertain" and any("withdrawn on 2023-05-05" in e for e in m.evidence)


def test_scanner_claim_not_in_osv_is_kept_as_uncertain():
    d = dep(claims=[ScannerClaim("CVE-2999-1", "HIGH", 8.0, "LOW", "NVD")])
    [m] = match_dependency(d, [])
    assert m.scanner_only and m.confidence == "uncertain" and not m.contradicted
    assert m.id == "CVE-2999-1"


def test_scanner_claim_contradicted_by_osv_range():
    d = dep("1.5", claims=[ScannerClaim("CVE-2020-1", "HIGH", 8.0, "HIGH", "NVD")])
    [m] = match_dependency(d, [adv("PYSEC-1", ["CVE-2020-1"])])  # 1.5 is past the fix
    assert m.scanner_only and m.contradicted
    assert any("NOT affected" in e for e in m.evidence)


def test_scanner_claim_confirmed_by_osv_adds_evidence_not_a_duplicate():
    d = dep(claims=[ScannerClaim("CVE-2020-1", "HIGH", 8.0, "HIGHEST", "NVD")])
    ms = match_dependency(d, [adv("PYSEC-1", ["CVE-2020-1"])])
    assert len(ms) == 1 and not ms[0].scanner_only
    assert any("also reported by the NVD" in e for e in ms[0].evidence)


def test_dependency_without_candidate_version_is_skipped():
    assert match_dependency(Dependency(name="pkg", ecosystem="PyPI"), [adv("PYSEC-1")]) == []


def test_match_all_routes_by_ecosystem_and_name():
    index = {"PyPI": {"pkg": [adv("PYSEC-1")]}, "npm": {}}
    out = match_all([dep(), Dependency(name="other", ecosystem="PyPI", version="1.2", lower_bound="1.2")], index)
    assert [m.id for m in out] == ["PYSEC-1"]


# ---------------------------------------------------------------- real data smoke
@pytest.mark.skipif(not (REAL_DATA / "osv" / "PyPI.index.json").exists(), reason="run scripts/fetch_data.py first")
def test_old_django_matches_real_advisories_and_new_one_is_quieter():
    index = {"PyPI": load_osv_index(REAL_DATA, "PyPI")}
    old = match_all([Dependency(name="django", ecosystem="PyPI", spec="==3.0", version="3.0", lower_bound="3.0")], index)
    assert len(old) >= 5
    assert any(m.fixed_versions for m in old)
    print(f"django 3.0 -> {len(old)} matches, e.g. {[m.id for m in old[:3]]}")
