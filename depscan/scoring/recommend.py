"""Recommended next actions. These are text only: depscan never changes a dependency file."""
from __future__ import annotations

from ..matcher.versions import UnparsableVersion, is_prerelease, major_of, parse_version
from ..models import Match


def minimum_fix(match: Match) -> tuple[str | None, bool | None]:
    """The lowest listed fixed version above the tested one, and whether it is a major bump."""
    dep = match.dependency
    version = match.version or dep.candidate
    if not match.fixed_versions or version is None:
        return None, None
    try:
        v = parse_version(dep.ecosystem, version)
        higher = [f for f in match.fixed_versions if parse_version(dep.ecosystem, f) > v]
    except UnparsableVersion:
        return None, None
    if not higher:
        return None, None
    fixed = min(higher, key=lambda f: parse_version(dep.ecosystem, f))
    a, b = major_of(dep.ecosystem, version), major_of(dep.ecosystem, fixed)
    return fixed, (a != b) if a is not None and b is not None else None


def action_from_risk(score: float, cfg: dict, *, uncertain: bool = False) -> str:
    """Provisional action from risk alone. The trust layer (phase 5) refines it: high risk + low trust = verify first."""
    if uncertain:
        return "verify_first"
    if score >= cfg["risk"]["tiers"]["critical"]:
        return "fix_now"
    if score >= cfg["risk"]["tiers"]["high"]:
        return "monitor"
    return "no_action"


def decide_action(risk_score: float, trust_score: float, cfg: dict, *, uncertain: bool = False) -> str:
    """Next step from risk AND trust. High risk with low trust reads "verify first", not "fix now".

    uncertain match (withdrawn, unconfirmed or contradicted claim) -> verify_first
    risk in the critical tier -> fix_now if trust is high enough, else verify_first
    risk in the high tier     -> verify_first if trust is low, else monitor
    otherwise                 -> no_action
    """
    tiers, a = cfg["risk"]["tiers"], cfg["actions"]
    if uncertain:
        return "verify_first"
    if risk_score >= tiers["critical"]:
        return "fix_now" if trust_score >= a["fix_now_min_trust"] else "verify_first"
    if risk_score >= tiers["high"]:
        return "verify_first" if trust_score < a["verify_below_trust"] else "monitor"
    return "no_action"


def recommendation_text(match: Match, fixed: str | None, major: bool | None, action: str, fix_yanked: bool = False) -> str:
    dep = match.dependency
    name, version = dep.name, match.version or dep.candidate
    if match.scanner_only and match.contradicted:
        return (f"Likely a false positive: advisory data says {name} {version} is not affected. "
                f"Confirm against the advisory, then mark it as a false positive.")
    if match.scanner_only:
        return (f"The scan report flags this but the advisory data does not confirm it for {name} {version}. "
                f"Check the advisory's affected versions before acting.")
    parts = []
    if fixed:
        parts.append(f"Upgrade {name} from {version} to {fixed} or later"
                     + (" (major version bump: check the changelog for breaking changes)." if major else " (same major version).")
                     + (f" {fixed} is a pre-release: use the first stable release after it." if is_prerelease(dep.ecosystem, fixed) else ""))
    else:
        parts.append(f"No fixed version is listed for {name} {version}. Consider a mitigation, an alternative package, "
                     f"or monitor the advisory for a patch.")
    if fixed and fix_yanked:
        parts.append(f"Note: {fixed} was yanked from the package registry, so it cannot be installed by default. "
                     f"Choose a later release and check the changelog.")
    if dep.scope == "dev":
        parts.append("It is a dev-only dependency, so it is not part of the production runtime.")
    if not dep.direct:
        parts.append(f"It is a transitive dependency: upgrade the package that pulls in {name}.")
    if not dep.exact:
        parts.append(f"The file only declares '{dep.spec}'; pin or lock the version to be sure which one is installed.")
    if match.confidence == "uncertain":
        parts.append("The match itself is uncertain (see evidence). Verify it before changing anything.")
    return " ".join(parts)
