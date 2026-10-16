"""Risk score (0-100): how bad is this finding if the advisory is real?

A weighted sum of factors, each scaled 0..1. Weights come from config/scoring.yaml.
Formulas and rationale: docs/SCORING.md. Every factor is returned with its value, weight and
contribution so the UI can show exactly where the number came from.
"""
from __future__ import annotations

from ..models import Match
from .cvss import cvss3_score

# NVD record keys in order of preference when several CVSS versions exist.
_NVD_ORDER = ("v31", "v30", "v40", "v2")


def cve_ids(match: Match) -> list[str]:
    return [i for i in [match.id, *match.aliases] if i.startswith("CVE-")]


def severity(match: Match, nvd: dict[str, dict], cfg: dict) -> tuple[float | None, str, float, bool]:
    """Returns (cvss 0-10 or None, where it came from, factor 0..1, known)."""
    for cve in cve_ids(match):
        rec = nvd.get(cve)
        if rec:
            for key in _NVD_ORDER:
                score = (rec.get("cvss", {}).get(key) or {}).get("score")
                if score is not None:
                    return float(score), f"NVD CVSS {key[1:]} base score", float(score) / 10, True
    for adv in match.advisories:
        for sev in adv.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                score = cvss3_score(sev.get("score", ""))
                if score is not None:
                    return score, "OSV CVSS v3 vector (score computed from the vector)", score / 10, True
    for claim in match.dependency.claims:
        if claim.cve in [match.id, *match.aliases] and claim.cvss is not None:
            return claim.cvss, f"{claim.source} CVSS score", claim.cvss / 10, True
    for adv in match.advisories:
        label = (adv.get("label") or "").upper()
        if label in cfg["risk"]["label_severity"]:
            return None, f"advisory severity label '{label}' (no CVSS number available)", cfg["risk"]["label_severity"][label], True
    return None, "no severity data found, a neutral value is used", cfg["risk"]["unknown_severity"], False


def epss_for(match: Match, epss: dict[str, tuple[float, float]]) -> float | None:
    values = [epss[c][0] for c in cve_ids(match) if c in epss]
    return max(values) if values else None


def kev_for(match: Match, kev: dict[str, dict]) -> dict | None:
    for c in cve_ids(match):
        if c in kev:
            return {"cve": c, **kev[c]}
    return None


def compute_risk(match: Match, *, nvd, kev, epss, fixed_version: str | None, major_bump: bool | None,
                 cfg: dict, exposed: bool | None = None) -> dict:
    """Returns {score, factors, cvss, epss, kev, notes}. `exposed=None` means no graph data: factor dropped."""
    r = cfg["risk"]
    dep = match.dependency
    cvss, cvss_source, sev_factor, sev_known = severity(match, nvd, cfg)
    p = epss_for(match, epss)
    kev_entry = kev_for(match, kev)
    crit = (r["criticality"]["direct"] if dep.direct else r["criticality"]["transitive"]) * r["criticality"][dep.scope]

    if fixed_version is None:
        fix_factor, fix_text = r["fix"]["none"], "no fixed version listed"
    elif major_bump:
        fix_factor, fix_text = r["fix"]["major_bump"], f"fix {fixed_version} needs a major version bump"
    else:
        fix_factor, fix_text = r["fix"]["available"], f"fix {fixed_version} available"

    # (name, display value, factor 0..1 or None when not applicable)
    raw = [
        ("severity", f"{cvss:.1f}" if cvss is not None else ("unknown" if not sev_known else cvss_source), sev_factor),
        ("known_exploited", f"KEV, added {kev_entry['dateAdded']}" if kev_entry else "not in KEV", 1.0 if kev_entry else 0.0),
        ("exploit_likelihood", f"EPSS {p * 100:.1f}%" if p is not None else "no EPSS (no CVE id)",
         min(p / r["epss_cap"], 1.0) if p is not None else 0.0),
        ("criticality", f"{'direct' if dep.direct else 'transitive'}, {dep.scope}", crit),
        ("fix_availability", fix_text, fix_factor),
        ("exposure", "n/a (no app graph)" if exposed is None else ("reachable from an entry point" if exposed else "not reachable"),
         None if exposed is None else (1.0 if exposed else 0.0)),
    ]
    active = [(n, v, f) for n, v, f in raw if f is not None]
    total_w = sum(r["weights"][n] for n, _, _ in active)  # renormalise when a factor is dropped
    factors, score = [], 0.0
    for name, value, f in active:
        w = r["weights"][name] / total_w
        contribution = 100 * w * f
        score += contribution
        factors.append({"name": name, "value": value, "weight": round(w, 4), "contribution": round(contribution, 2)})
    notes = []
    if exposed is None:
        notes.append("exposure factor dropped (no Django project was analysed); other weights renormalised")
    if not sev_known:
        notes.append("severity unknown: a neutral value was used")
    return {
        "score": round(score, 1), "factors": factors, "cvss": cvss, "cvss_source": cvss_source,
        "epss": p, "kev": kev_entry, "notes": notes,
    }
