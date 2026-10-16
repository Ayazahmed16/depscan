"""Match dependencies to advisories and explain why each match was made.

Each package can have several OSV records for the same vulnerability (for example a GHSA and a
PYSEC record, linked by `aliases`). We group them, evaluate every record separately and keep
each record's verdict. That gives us the evidence text now, and the "do the sources agree?"
signal for the trust score later.
"""
from __future__ import annotations

from ..models import Dependency, Match, SourceVerdict
from .versions import evaluate_advisory


def _group(advisories: list[dict]) -> list[list[dict]]:
    """Union records that share an id or alias (GHSA-x <-> CVE-y <-> PYSEC-z)."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a in advisories:
        ids = [a["id"], *a.get("aliases", [])]
        for other in ids[1:]:
            parent[find(other)] = find(ids[0])
        find(ids[0])
    groups: dict[str, list[dict]] = {}
    for a in advisories:
        groups.setdefault(find(a["id"]), []).append(a)
    return list(groups.values())


def primary_id(records: list[dict]) -> str:
    """Prefer a CVE id, then GHSA, then whatever the first record uses."""
    ids = [i for r in records for i in [r["id"], *r.get("aliases", [])]]
    for prefix in ("CVE-", "GHSA-"):
        found = sorted(i for i in ids if i.startswith(prefix))
        if found:
            return found[0]
    return records[0]["id"]


def _matches_at(dep: Dependency, version: str, advisories: list[dict]) -> dict[str, Match]:
    """Matches for ONE specific version, keyed by primary id. Confidence is set by the caller."""
    found: dict[str, Match] = {}
    for records in _group(advisories):
        verdicts: list[SourceVerdict] = []
        for rec in records:
            affected, fixed, reason = evaluate_advisory(dep.ecosystem, version, rec.get("affected", []))
            verdicts.append(SourceVerdict(rec["id"], affected, reason, fixed))
        pid = primary_id(records)
        all_ids = sorted({i for r in records for i in [r["id"], *r.get("aliases", [])]} - {pid})
        hits = [v for v in verdicts if v.affected]
        misses = [v for v in verdicts if v.affected is False]
        if not hits:
            continue

        evidence = [f"{dep.name} {version}: {v.advisory_id}: {v.reason}" for v in hits]
        confidence = "base"  # replaced by the caller; 'uncertain' below overrides it
        # A withdrawn record is noted. The match only becomes uncertain if EVERY record that
        # affirms it has been withdrawn; a withdrawn duplicate next to live records changes nothing.
        withdrawn = {r["id"]: r["withdrawn"] for r in records if r.get("withdrawn")}
        for rid, when in withdrawn.items():
            evidence.append(f"{rid} was withdrawn on {when[:10]}: that record has been retracted")
        if all(v.advisory_id in withdrawn for v in hits):
            confidence = "uncertain"
        for m in misses:
            # Disagreement is recorded as evidence and as per-source verdicts. It lowers the TRUST score
            # (phase 5), not the match confidence, so a real hit is not demoted twice.
            evidence.append(f"sources disagree: {m.advisory_id} says this version is not affected ({m.reason})")

        found[pid] = Match(
            id=pid, aliases=all_ids, dependency=dep, confidence=confidence, evidence=evidence,
            verdicts=verdicts, advisories=records, version=version,
            fixed_versions=sorted({h.fixed_in for h in hits if h.fixed_in}),
        )
    return found


def _range_evidence(dep: Dependency, low: Match | None, new: Match | None) -> tuple[str, list[str]]:
    """Confidence and explanation for a dependency declared as a range (not exact).

    confirmed > likely > possible > probable:
      likely    newest satisfying release AND lowest allowed version are both affected
      possible  only one of the two is affected
      probable  registry unavailable: only the lowest allowed version could be tested
    """
    spec = dep.spec
    if dep.newest is None:  # registry did not resolve: old behaviour
        why = {"failed": "the package registry could not be reached, so the newest release was not looked up",
               None: "registry resolution was not attempted"}.get(dep.registry_status, "the registry returned no usable release")
        return "probable", [
            f"the file declares '{spec}', not an exact version; {dep.lower_bound} is the lowest version it allows "
            f"and the only one tested ({why}), so the installed version may differ (a lock file would settle it)"]
    if low and new:
        return "likely", [
            f"the file declares '{spec}'. The newest release that satisfies it is {dep.newest} (from the {dep.ecosystem} registry) "
            f"and the lowest version it allows ({dep.lower_bound}) is affected too: any install within the range gets an affected version"]
    if new:
        low_txt = f"the lowest allowed version {dep.lower_bound} is not affected" if dep.lower_bound else "no lower bound is declared"
        return "possible", [
            f"the file declares '{spec}'. The newest satisfying release {dep.newest} is affected, but {low_txt}: "
            f"whether it applies depends on which version gets installed"]
    return "possible", [
        f"the file declares '{spec}'. The lowest allowed version {dep.lower_bound} is affected, but the newest satisfying release "
        f"{dep.newest} is not: a fresh install resolves to the patched release, an older install may not"]


def match_dependency(dep: Dependency, advisories: list[dict]) -> list[Match]:
    """All matches for one dependency. `advisories` are the OSV records for dep.name."""
    matches: list[Match] = []
    if dep.exact:
        version = dep.version
        for m in _matches_at(dep, version, advisories).values():
            how = f"locked in {dep.source}" if dep.resolution == "lockfile" else f"pinned exactly in {dep.source or 'the manifest'}"
            m.evidence.append(f"installed version {version} is known exactly: {how}")
            m.confidence = "uncertain" if m.confidence == "uncertain" else "confirmed"
            matches.append(m)
    else:
        version = dep.newest or dep.lower_bound
        if version is None:
            return matches
        low = _matches_at(dep, dep.lower_bound, advisories) if dep.lower_bound else {}
        new = _matches_at(dep, dep.newest, advisories) if dep.newest else {}
        for pid in list(dict.fromkeys([*new, *low])):
            m = new.get(pid) or low[pid]        # report the affected version; prefer the newest
            confidence, notes = _range_evidence(dep, low.get(pid), new.get(pid))
            m.confidence = "uncertain" if m.confidence == "uncertain" else confidence
            m.evidence = m.evidence + notes
            matches.append(m)

    seen_ids = {i for m in matches for i in [m.id, *m.aliases]}

    # Scanner claims that our advisory data did not confirm: keep them, flagged, never silently dropped.
    version = dep.version or dep.newest or dep.lower_bound
    for claim in dep.claims:
        if claim.cve in seen_ids:
            for m in matches:
                if claim.cve == m.id or claim.cve in m.aliases:
                    m.evidence.append(
                        f"also reported by the {claim.source} (scanner identity confidence {claim.confidence or 'unknown'})"
                    )
            continue
        contradicting = [
            (r, evaluate_advisory(dep.ecosystem, version, r.get("affected", [])))
            for r in advisories if claim.cve in [r["id"], *r.get("aliases", [])]
        ]
        contradicted = any(res[0] is False for _, res in contradicting)
        if contradicted:
            reasons = dict.fromkeys(res[2] for _, res in contradicting if res[0] is False)  # same reason from 2 sources: say it once
            why = f"advisory data says {version} is NOT affected: " + "; ".join(reasons)
        else:
            why = f"no advisory in the OSV snapshot confirms it for {dep.name} {version}"
        matches.append(Match(
            id=claim.cve, aliases=[], dependency=dep, confidence="uncertain",
            evidence=[
                f"the {claim.source} reports {claim.cve} for {dep.name} {version} (scanner identity confidence {claim.confidence or 'unknown'})",
                why,
            ],
            verdicts=[], advisories=[r for r, _ in contradicting], scanner_only=True, contradicted=contradicted,
            version=version,
        ))
    return matches


def match_all(deps: list[Dependency], osv_by_eco: dict[str, dict[str, list[dict]]]) -> list[Match]:
    out: list[Match] = []
    for dep in deps:
        index = osv_by_eco.get(dep.ecosystem, {})
        out.extend(match_dependency(dep, index.get(dep.name, [])))
    return out
