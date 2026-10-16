"""The CI gate: should a scan make a build fail?

`depscan scan --fail-on LEVEL` exits with status 1 when any finding still needs attention at LEVEL or worse. The gate only
decides an exit code. It never changes a dependency file, and it is the build system, not depscan, that stops a deploy.

Levels follow the recommended action: fix_now (strictest to trigger), verify_first, monitor, and any (every finding).
A finding does not count when:
  * a person accepted the risk or marked it a false positive and that decision has not expired, or
  * a scan report claims it but the advisory data says the version is not affected (a likely false positive).
A `fix_now` decision does not exempt a finding: the work is still outstanding.
"""
from __future__ import annotations

SEVERITY = {"fix_now": 3, "verify_first": 2, "monitor": 1, "no_action": 0}
LEVELS = ("fix_now", "verify_first", "monitor", "any")
EXEMPT_REVIEWS = {"accept_risk", "false_positive"}


def counts(finding: dict) -> bool:
    """Does this finding count towards the gate at all?"""
    return finding.get("claim_status") != "contradicted" and finding.get("review_status") not in EXEMPT_REVIEWS


def failing(findings: list[dict], level: str) -> list[dict]:
    """The findings that trip the gate at `level`, in the scan's own order."""
    if level not in LEVELS:
        raise ValueError(f"level must be one of {', '.join(LEVELS)}")
    floor = 0 if level == "any" else SEVERITY[level]
    return [f for f in findings if counts(f) and (level == "any" or SEVERITY[f["action"]] >= floor)]


def summary(findings: list[dict], level: str) -> tuple[bool, str]:
    """(passed, one-line message). The message always carries the reminder that a pass is not proof of safety."""
    bad = failing(findings, level)
    where = "any finding" if level == "any" else f"a finding at {level.replace('_', ' ')} or worse"
    if not bad:
        return True, f"depscan gate passed: no finding needs attention ({where}). No findings does not prove a project is secure."
    top = ", ".join(f"{f['package']} {f['id']}" for f in bad[:3]) + (f" and {len(bad) - 3} more" if len(bad) > 3 else "")
    return False, f"depscan gate FAILED: {len(bad)} finding(s) ({where}): {top}"
