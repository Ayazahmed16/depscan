"""Phase 3 tests: CVSS maths, risk factors, weights, recommendations, config validation."""
import copy

import pytest

from depscan.models import Dependency, Match
from depscan.scoring.config import load_config
from depscan.scoring.cvss import cvss3_score
from depscan.scoring.recommend import action_from_risk, minimum_fix, recommendation_text
from depscan.scoring.risk import compute_risk

CFG = load_config()


# ---------------------------------------------------------------- CVSS (values from the FIRST / NVD examples)
@pytest.mark.parametrize("vector,expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),   # Log4Shell
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),     # classic reflected XSS
])
def test_cvss3_known_vectors(vector, expected):
    assert cvss3_score(vector) == expected


def test_cvss_rejects_non_v3_and_malformed():
    assert cvss3_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    assert cvss3_score("CVSS:3.1/AV:N") is None
    assert cvss3_score("garbage") is None


# ---------------------------------------------------------------- risk
def make(direct=True, scope="runtime", exact=True, claims=None, aliases=("CVE-2030-0001",), advisories=None, fixed=("1.5",)):
    d = Dependency(name="alpha", ecosystem="PyPI", spec="==1.0", version="1.0" if exact else None,
                   lower_bound="1.0", direct=direct, scope=scope, claims=claims or [])
    return Match(id=aliases[0], aliases=list(aliases[1:]), dependency=d, confidence="confirmed", evidence=[],
                 verdicts=[], advisories=advisories or [], fixed_versions=list(fixed))


def risk(match, *, kev=None, epss=None, nvd=None, fixed="1.5", major=False, exposed=None, cfg=CFG):
    return compute_risk(match, nvd=nvd or {}, kev=kev or {}, epss=epss or {}, fixed_version=fixed, major_bump=major, cfg=cfg, exposed=exposed)


NVD_98 = {"CVE-2030-0001": {"cvss": {"v31": {"score": 9.8}}}}


def test_weights_in_config_sum_to_one_and_bad_config_is_rejected(tmp_path):
    assert abs(sum(CFG["risk"]["weights"].values()) - 1) < 1e-9
    bad = copy.deepcopy(CFG)
    bad["risk"]["weights"]["severity"] = 0.9
    import yaml
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump(bad))
    with pytest.raises(ValueError, match="sum to 1"):
        load_config(p)


def test_factor_contributions_add_up_to_the_score():
    r = risk(make(), nvd=NVD_98, kev={"CVE-2030-0001": {"dateAdded": "2030-02-01"}}, epss={"CVE-2030-0001": (0.9, 0.99)})
    assert abs(sum(f["contribution"] for f in r["factors"]) - r["score"]) < 0.2  # rounding only
    assert abs(sum(f["weight"] for f in r["factors"]) - 1) < 1e-3


def test_exposure_factor_is_dropped_and_weights_renormalised_when_unknown():
    r = risk(make(), nvd=NVD_98)
    assert "exposure" not in [f["name"] for f in r["factors"]]
    assert any("exposure factor dropped" in n for n in r["notes"])
    assert abs(sum(f["weight"] for f in r["factors"]) - 1) < 1e-3
    with_exposure = risk(make(), nvd=NVD_98, exposed=True)
    assert "exposure" in [f["name"] for f in with_exposure["factors"]]


def test_exposed_ranks_above_not_exposed():
    assert risk(make(), nvd=NVD_98, exposed=True)["score"] > risk(make(), nvd=NVD_98, exposed=False)["score"]


def test_ranking_follows_the_documented_factors():
    base = risk(make(), nvd=NVD_98)["score"]
    kev = risk(make(), nvd=NVD_98, kev={"CVE-2030-0001": {"dateAdded": "x"}})["score"]
    epss = risk(make(), nvd=NVD_98, epss={"CVE-2030-0001": (0.9, 0.9)})["score"]
    dev = risk(make(scope="dev"), nvd=NVD_98)["score"]
    transitive = risk(make(direct=False), nvd=NVD_98)["score"]
    no_fix = risk(make(), nvd=NVD_98, fixed=None)["score"]
    major = risk(make(), nvd=NVD_98, major=True)["score"]
    low_cvss = risk(make(), nvd={"CVE-2030-0001": {"cvss": {"v31": {"score": 3.0}}}})["score"]
    assert kev > base and epss > base                   # exploitation signals raise it
    assert dev < base and transitive < base             # less critical dependencies lower it
    assert no_fix < major < base                        # fix actionability: none < major bump < same-major fix
    assert low_cvss < base


def test_epss_is_capped_and_skewed_values_still_count():
    half = risk(make(), nvd=NVD_98, epss={"CVE-2030-0001": (0.5, 0.9)})["score"]
    full = risk(make(), nvd=NVD_98, epss={"CVE-2030-0001": (0.99, 0.99)})["score"]
    assert half == full  # at or above the cap counts as 1.0


def test_severity_source_order_nvd_then_osv_vector_then_scanner_then_label():
    vec = [{"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}]}]
    assert risk(make(advisories=vec), nvd=NVD_98)["cvss"] == 9.8            # NVD wins
    assert risk(make(advisories=vec))["cvss"] == 5.3                         # computed from OSV vector
    from depscan.models import ScannerClaim
    claim = make(claims=[ScannerClaim("CVE-2030-0001", "HIGH", 8.0, "HIGH", "NVD")])
    assert risk(claim)["cvss"] == 8.0
    label = risk(make(advisories=[{"label": "HIGH"}]))
    assert label["cvss"] is None and "label" in label["cvss_source"]
    unknown = risk(make())
    assert unknown["cvss"] is None and any("severity unknown" in n for n in unknown["notes"])


# ---------------------------------------------------------------- recommendations
def test_minimum_fix_and_major_bump():
    m = make(fixed=("1.5", "2.0"))
    assert minimum_fix(m) == ("1.5", False)
    m2 = make(fixed=("2.0",))
    assert minimum_fix(m2) == ("2.0", True)
    assert minimum_fix(make(fixed=())) == (None, None)
    assert minimum_fix(make(fixed=("0.5",))) == (None, None)  # a "fix" below the current version is not a fix


def test_action_thresholds_and_uncertain():
    assert action_from_risk(80, CFG) == "fix_now"
    assert action_from_risk(40, CFG) == "monitor"
    assert action_from_risk(10, CFG) == "no_action"
    assert action_from_risk(95, CFG, uncertain=True) == "verify_first"


def test_recommendation_text_is_advice_only_and_covers_the_cases():
    txt = recommendation_text(make(), "1.5", False, "fix_now")
    assert "Upgrade alpha from 1.0 to 1.5" in txt and "same major" in txt
    assert "major version bump" in recommendation_text(make(), "2.0", True, "fix_now")
    assert "No fixed version" in recommendation_text(make(), None, None, "monitor")
    assert "dev-only" in recommendation_text(make(scope="dev"), "1.5", False, "monitor")
    assert "transitive" in recommendation_text(make(direct=False), "1.5", False, "monitor")
    assert "pin or lock" in recommendation_text(make(exact=False), "1.5", False, "monitor")
    fp = make()
    fp.scanner_only, fp.contradicted = True, True
    assert "false positive" in recommendation_text(fp, None, None, "verify_first")
