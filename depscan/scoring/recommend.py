"""Recommended next actions. These are text only: depscan never changes a dependency file."""
from __future__ import annotations

from ..matcher.versions import UnparsableVersion, major_of, parse_version
from ..models import Match


def minimum_fix(match: Match) -> tuple[str | None, bool | None]:
    """The lowest listed fixed version above the tested one, and whether it is a major bump."""
    dep = match.dependency
    version = dep.candidate
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


def recommendation_text(match: Match, fixed: str | None, major: bool | None, action: str) -> str:
    dep = match.dependency
    name, version = dep.name, dep.candidate
    if match.scanner_only and match.contradicted:
        return (f"Likely a false positive: advisory data says {name} {version} is not affected. "
                f"Confirm against the advisory, then mark it as a false positive.")
    if match.scanner_only:
        return (f"The scan report flags this but the advisory data does not confirm it for {name} {version}. "
                f"Check the advisory's affected versions before acting.")
    parts = []
    if fixed:
        parts.append(f"Upgrade {name} from {version} to {fixed} or later"
                     + (" (major version bump: check the changelog for breaking changes)." if major else " (same major version)."))
    else:
        parts.append(f"No fixed version is listed for {name} {version}. Consider a mitigation, an alternative package, "
                     f"or monitor the advisory for a patch.")
    if dep.scope == "dev":
        parts.append("It is a dev-only dependency, so it is not part of the production runtime.")
    if not dep.direct:
        parts.append(f"It is a transitive dependency: upgrade the package that pulls in {name}.")
    if not dep.exact:
        parts.append(f"The file only declares '{dep.spec}'; pin or lock the version to be sure which one is installed.")
    if match.confidence == "uncertain":
        parts.append("The match itself is uncertain (see evidence). Verify it before changing anything.")
    return " ".join(parts)
