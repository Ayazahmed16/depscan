"""requirements.txt parser. Read-only: the file is parsed from text and never written."""
from __future__ import annotations

import re

from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

from ..matcher.versions import normalize_pypi_name
from ..models import Dependency, ParseResult


def _lower_bound(req: Requirement) -> tuple[str | None, str | None]:
    """Returns (exact version, lowest allowed version) from a specifier set."""
    exact = None
    lows: list[Version] = []
    for s in req.specifier:
        v = s.version.rstrip(".*")  # "1.2.*" means "from 1.2"
        try:
            parsed = Version(v)
        except InvalidVersion:
            continue
        if s.operator in ("==", "===") and not s.version.endswith(".*"):
            exact = s.version
        elif s.operator in ("==", ">=", ">", "~="):
            lows.append(parsed)
    if exact:
        return exact, exact
    return None, str(min(lows)) if lows else None


def parse_requirements(text: str, source: str = "requirements.txt") -> ParseResult:
    # requirements-dev.txt, test-requirements.txt, etc. hold build/test tooling, not runtime code
    lowered = source.lower()
    scope = "dev" if any(w in lowered for w in ("dev", "test", "lint", "docs")) else "runtime"
    deps: list[Dependency] = []
    warnings: list[str] = []

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split(" #")[0].strip()  # drop trailing comments
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r", "--requirement", "-c", "--constraint")):
            warnings.append(f"line {lineno}: '{line}' references another file; upload that file too")
            continue
        if line.startswith(("-e", "--editable", "git+", "http://", "https://", "file:", ".")) or "://" in line:
            warnings.append(f"line {lineno}: '{line}' is a URL or local path; version unknown, skipped")
            continue
        if line.startswith("-"):
            continue  # pip options like --index-url, --hash lines
        line = re.sub(r"\s--hash=\S+", "", line).rstrip("\\ ").strip()
        try:
            req = Requirement(line)
        except InvalidRequirement:
            warnings.append(f"line {lineno}: could not parse '{line}'")
            continue
        exact, low = _lower_bound(req)
        if low is None:
            warnings.append(f"line {lineno}: '{req.name}' has no version lower bound, cannot be matched")
        deps.append(Dependency(
            name=normalize_pypi_name(req.name), ecosystem="PyPI", spec=str(req.specifier) or "(any)",
            version=exact, lower_bound=low, direct=True, scope=scope, source=source, line=lineno,
        ))
    return ParseResult(deps, source, "requirements.txt", warnings)
