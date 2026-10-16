"""Trust score (0 to 100): should we believe this advisory?

Risk says how bad a vulnerability is IF it is real. Trust says how much to believe it is real and
applies to our dependency. The two are kept apart on purpose: a scary advisory backed by a single
source, retracted by its publisher, or contradicting NVD should read "verify first", not "fix now".

The score is a base number plus the points of each signal (config/scoring.yaml). Every signal is
returned with its value, points and a plain-language note, including signals that add nothing, so the
UI can always show the full list. There is no hidden term: score = clamp(base + sum of effects).
Rationale for each signal: docs/SCORING.md, section 2.
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable

from ..models import Match
from .cvss import cvss3_score
from .risk import cve_ids, kev_for

# Which database an advisory id prefix belongs to. Unknown prefixes are shown as they are.
SOURCE_NAMES = {
    "GHSA": "GitHub Advisory Database", "PYSEC": "PyPA advisory database", "GO": "Go vulnerability database",
    "BIT": "Bitnami", "OSV": "OSV", "RUSTSEC": "RustSec", "MAL": "OpenSSF malicious packages", "EEF": "Erlang Ecosystem Foundation",
    "GSD": "Global Security Database", "DSA": "Debian", "USN": "Ubuntu", "RHSA": "Red Hat",
}
_NVD_PENDING = {"Awaiting Analysis", "Undergoing Analysis", "Received", "Deferred"}
_NVD_ANALYSED = {"Analyzed", "Modified"}

# release_exists(ecosystem, package, version) -> True / False / "yanked" / None (None = could not check)
ReleaseCheck = Callable[[str, str, str], "bool | str | None"]


def _sig(name: str, value: str, effect: float, note: str) -> dict:
    return {"name": name, "value": value, "effect": effect, "note": note}


def _date(text: str | None) -> dt.date | None:
    try:
        return dt.date.fromisoformat((text or "")[:10])
    except ValueError:
        return None


def level(score: float, cfg: dict) -> str:
    t = cfg["trust"]["thresholds"]
    return "high" if score >= t["high"] else "medium" if score >= t["low"] else "low"


def compute_trust(match: Match, *, nvd: dict[str, dict], fixed_version: str | None, as_of: dt.date,
                  cfg: dict, release_exists: ReleaseCheck | None = None, kev: dict[str, dict] | None = None) -> dict:
    """Returns {score, level, signals}. `as_of` is the data snapshot date, so results are reproducible."""
    t = cfg["trust"]
    signals: list[dict] = []
    records = match.advisories
    live = [r for r in records if not r.get("withdrawn")]
    withdrawn = [r for r in records if r.get("withdrawn")]
    nvd_rec = next((nvd[c] for c in cve_ids(match) if c in nvd), None)

    # 1. independent sources -------------------------------------------------------------------------------
    names = set()
    for r in live:
        for i in [r["id"], *r.get("aliases", [])]:
            prefix = i.split("-")[0]
            if prefix != "CVE":
                names.add(SOURCE_NAMES.get(prefix, prefix))
    if nvd_rec and nvd_rec.get("vulnStatus") != "Rejected":
        names.add("NVD")
    n = min(len(names), max(t["sources"]))
    note = ", ".join(sorted(names)) if names else "no live advisory record lists it"
    signals.append(_sig("independent sources", f"{len(names)}", t["sources"][n], note))

    # 2. do version ranges agree? ----------------------------------------------------------------------------
    live_ids = {r["id"] for r in live}
    decided = [v for v in match.verdicts if v.advisory_id in live_ids and v.affected is not None]
    if len(decided) < 2:
        signals.append(_sig("version ranges", "one source", 0, "only one source gave a version range, so there is nothing to compare"))
    elif all(v.affected for v in decided):
        signals.append(_sig("version ranges", "agree", t["ranges_agree"], f"{len(decided)} sources all say {match.version} is affected"))
    else:
        no = [v.advisory_id for v in decided if not v.affected]
        signals.append(_sig("version ranges", "disagree", t["ranges_disagree"],
                            f"{', '.join(no)} say{'s' if len(no) == 1 else ''} {match.version} is NOT affected while others say it is"))
    fixes = {v.advisory_id: v.fixed_in for v in decided if v.affected and v.fixed_in}
    if len(set(fixes.values())) > 1:
        detail = "; ".join(f"{k} says {f}" for k, f in sorted(fixes.items()))
        signals.append(_sig("fixed versions", "differ", t["fix_versions_disagree"], f"sources name different fixes: {detail}"))
    else:
        signals.append(_sig("fixed versions", "consistent" if fixes else "n/a", 0, "no conflicting fixed versions"))

    # 3. status: withdrawn, rejected, disputed ---------------------------------------------------------------
    if withdrawn and not live:
        signals.append(_sig("withdrawn", "all records", t["withdrawn_all"], "every record for this advisory was withdrawn by its publisher"))
    elif withdrawn:
        signals.append(_sig("withdrawn", f"{len(withdrawn)} duplicate", t["withdrawn_some"],
                            f"{', '.join(r['id'] for r in withdrawn)} withdrawn; live records remain"))
    else:
        signals.append(_sig("withdrawn", "no", 0, "no record was withdrawn"))
    status = (nvd_rec or {}).get("vulnStatus")
    tags = set((nvd_rec or {}).get("tags", []))
    if status == "Rejected":
        signals.append(_sig("NVD status", "Rejected", t["nvd_rejected"], "NVD rejected this CVE"))
    elif status in _NVD_ANALYSED:
        signals.append(_sig("NVD status", status, t["nvd_analysed"], "NVD has analysed the CVE"))
    elif status in _NVD_PENDING:
        signals.append(_sig("NVD status", status, t["nvd_pending"], "NVD has not (fully) analysed the CVE"))
    else:
        signals.append(_sig("NVD status", "not in NVD", 0, "no NVD record (normal for advisories without a CVE id)"))
    summaries = " ".join(r.get("summary") or "" for r in live)
    if "disputed" in tags or "** DISPUTED **" in summaries:
        why = "NVD tags it disputed" if "disputed" in tags else "the advisory text is marked ** DISPUTED **"
        signals.append(_sig("disputed", "yes", t["disputed"], f"{why}: the vendor or others contest that it is a vulnerability"))
    else:
        signals.append(_sig("disputed", "no", 0, "not marked as disputed"))
    if "unsupported-when-assigned" in tags:
        signals.append(_sig("unsupported product", "yes", t["unsupported_when_assigned"], "NVD: the product was already unsupported when the CVE was assigned"))

    # 3b. observed exploitation: independent proof it is real --------------------------------------------
    hit = kev_for(match, kev or {})
    if hit:
        signals.append(_sig("known exploited", f"CISA KEV, added {hit['dateAdded']}", t["kev_listed"],
                            "CISA lists it as exploited in the wild: independent confirmation that the vulnerability is real"))
    else:
        signals.append(_sig("known exploited", "not in KEV", 0, "not on the CISA known-exploited list (most vulnerabilities are not)"))

    # 4. freshness -------------------------------------------------------------------------------------------
    dates = [d for d in [*(_date(r.get("modified")) for r in records), _date((nvd_rec or {}).get("lastModified"))] if d]
    if dates:
        age = (as_of - max(dates)).days
        if age <= t["fresh_days"]:
            signals.append(_sig("last modified", f"{age} days ago", t["fresh"], "recently reviewed or updated"))
        elif age >= t["stale_days"]:
            signals.append(_sig("last modified", f"{age // 365} years ago", t["stale"], "not revised for years: may be outdated"))
        else:
            signals.append(_sig("last modified", f"{age} days ago", 0, "neither recent nor stale"))
    else:
        signals.append(_sig("last modified", "unknown", 0, "no modification date in the data"))

    # 5. does a fix actually exist? --------------------------------------------------------------------------
    dep = match.dependency
    has_commit = any(r.get("fix_refs") for r in records)
    if fixed_version:
        on_registry = release_exists(dep.ecosystem, dep.name, fixed_version) if release_exists else None
        if on_registry == "yanked":
            signals.append(_sig("fix", f"{fixed_version} yanked", t["fix_yanked"],
                                f"{fixed_version} was yanked from the package registry, so it is not installable by default: "
                                f"a later release is needed"))
        elif on_registry is False:
            signals.append(_sig("fix", f"{fixed_version} not on registry", t["fix_not_on_registry"],
                                f"the advisory names {fixed_version} but the package registry has no such release"))
        else:
            how = "found on the package registry" if on_registry else "listed in the advisory (not checked against the registry)"
            signals.append(_sig("fix", fixed_version, t["fix_release_exists"], f"a patched release exists: {how}"))
    elif has_commit:
        signals.append(_sig("fix", "commit only", t["fix_commit_only"], "a fix commit is referenced but no fixed version is listed"))
    else:
        signals.append(_sig("fix", "none", t["no_fix"], "no patched release and no fix commit: the advisory may be unresolved or incomplete"))

    # 6. does the match itself hold up? ----------------------------------------------------------------------
    if match.contradicted:
        signals.append(_sig("scan-report claim", "contradicted", t["claim"]["contradicted"], "a scan report claims it, but advisory data says this version is not affected"))
    elif match.scanner_only:
        signals.append(_sig("scan-report claim", "unconfirmed", t["claim"]["unconfirmed"], "only a scan report claims it; no advisory confirms it"))
    signals.append(_sig("match confidence", match.confidence, t["confidence"][match.confidence],
                        "how sure we are the installed version is affected (SCORING.md section 2)"))

    # 7. do independent severity scores agree? ---------------------------------------------------------------
    nvd_score = next((float(s["score"]) for key in ("v31", "v30") if nvd_rec and (s := (nvd_rec.get("cvss") or {}).get(key)) and s.get("score") is not None), None)
    osv_score = next((sc for r in records for v in r.get("severity", []) if v.get("type") == "CVSS_V3" and (sc := cvss3_score(v.get("score", ""))) is not None), None)
    if nvd_score is not None and osv_score is not None:
        if abs(nvd_score - osv_score) <= t["severity_tolerance"]:
            signals.append(_sig("severity", f"NVD {nvd_score:g}, OSV {osv_score:g}", t["severity_agree"], "NVD and the advisory's own CVSS vector agree"))
        else:
            signals.append(_sig("severity", f"NVD {nvd_score:g}, OSV {osv_score:g}", t["severity_differ"], "NVD and the advisory's own CVSS vector disagree"))
    elif nvd_score is None and osv_score is None and not any(c.cvss for c in dep.claims) and not any(r.get("label") for r in records):
        signals.append(_sig("severity", "unknown", t["severity_unknown"], "no severity score or label is published"))
    else:
        signals.append(_sig("severity", "one source", 0, "only one source gives a severity, so nothing to compare"))

    score = float(max(0.0, min(100.0, t["base"] + sum(s["effect"] for s in signals))))  # always a float, like risk
    return {"score": round(score, 1), "level": level(score, cfg), "base": t["base"], "signals": signals}
