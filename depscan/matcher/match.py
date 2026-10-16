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


def match_dependency(dep: Dependency, advisories: list[dict]) -> list[Match]:
    """All matches for one dependency. `advisories` are the OSV records for dep.name."""
    version = dep.candidate
    matches: list[Match] = []
    seen_ids: set[str] = set()
    if version is None:
        return matches

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
        seen_ids.update([pid, *all_ids])  # only matched ids count as "confirmed" for scanner claims

        evidence = [f"{dep.name} {version}: {v.advisory_id}: {v.reason}" for v in hits]
        confidence = "exact" if dep.exact else "probable"
        if not dep.exact:
            evidence.append(
                f"the file declares '{dep.spec}', not an exact version; {version} is the lowest version it allows, "
                f"so the installed version may differ (a lock file or scan report would settle it)"
            )
        withdrawn = [r for r in records if r.get("withdrawn")]
        if withdrawn:
            confidence = "uncertain"
            evidence.append(f"{withdrawn[0]['id']} was withdrawn on {withdrawn[0]['withdrawn'][:10]}: the advisory has been retracted")
        for m in misses:
            confidence = "uncertain"
            evidence.append(f"sources disagree: {m.advisory_id} says this version is not affected ({m.reason})")

        matches.append(Match(
            id=pid, aliases=all_ids, dependency=dep, confidence=confidence, evidence=evidence,
            verdicts=verdicts, advisories=records,
            fixed_versions=sorted({h.fixed_in for h in hits if h.fixed_in}),
        ))

    # Scanner claims that our advisory data did not confirm: keep them, flagged, never silently dropped.
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
            why = f"advisory data says {version} is NOT affected: " + "; ".join(res[2] for _, res in contradicting if res[0] is False)
        else:
            why = f"no advisory in the OSV snapshot confirms it for {dep.name} {version}"
        matches.append(Match(
            id=claim.cve, aliases=[], dependency=dep, confidence="uncertain",
            evidence=[
                f"the {claim.source} reports {claim.cve} for {dep.name} {version} (scanner identity confidence {claim.confidence or 'unknown'})",
                why,
            ],
            verdicts=[], advisories=[r for r, _ in contradicting], scanner_only=True, contradicted=contradicted,
        ))
    return matches


def match_all(deps: list[Dependency], osv_by_eco: dict[str, dict[str, list[dict]]]) -> list[Match]:
    out: list[Match] = []
    for dep in deps:
        index = osv_by_eco.get(dep.ecosystem, {})
        out.extend(match_dependency(dep, index.get(dep.name, [])))
    return out
