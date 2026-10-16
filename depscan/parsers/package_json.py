"""package.json and package-lock.json parsers (npm). Read-only."""
from __future__ import annotations

import json
import re

from ..matcher.versions import SemVer, UnparsableVersion
from ..models import Dependency, ParseResult

_URLISH = re.compile(r"^(git|http|https|file|link|workspace|npm|github):|^[\w.-]+/[\w.-]+$|^\.{0,2}/")


def npm_lower_bound(spec: str) -> tuple[str | None, str | None]:
    """Returns (exact version, lowest version the npm range allows).

    Handles exact pins, ^ ~ >= > and x-ranges. For `a || b` and hyphen ranges the lowest part wins.
    Anything else returns (None, None) and the caller reports it.
    """
    s = spec.strip()
    if s in ("", "*", "latest", "x"):
        return None, None
    s = s.split("||")[0].strip()          # worst case: the lowest alternative
    s = re.split(r"\s+-\s+", s)[0].strip()  # "1.2.3 - 2.0.0" -> 1.2.3
    s = s.split()[0] if s.split() else s    # ">=1.2.3 <2.0.0" -> >=1.2.3
    s = s.lstrip("^~>=v ").strip()
    parts = s.split(".")
    nums = []
    for p in parts[:3]:
        if p in ("x", "X", "*"):
            break
        nums.append(p)
    while len(nums) < 3:
        nums.append("0")
    candidate = ".".join(nums)
    try:
        SemVer(candidate)
    except UnparsableVersion:
        return None, None
    exact = candidate if re.fullmatch(r"v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", spec.strip()) else None
    return exact, candidate


def parse_package_json(text: str, source: str = "package.json") -> ParseResult:
    doc = json.loads(text)
    deps: list[Dependency] = []
    warnings: list[str] = []
    sections = (("dependencies", "runtime"), ("optionalDependencies", "runtime"), ("devDependencies", "dev"))
    for key, scope in sections:
        for name, spec in (doc.get(key) or {}).items():
            if not isinstance(spec, str) or _URLISH.match(spec):
                warnings.append(f"{name}: '{spec}' is a URL, path or alias; version unknown, skipped")
                continue
            exact, low = npm_lower_bound(spec)
            if low is None:
                warnings.append(f"{name}: '{spec}' has no usable lower bound, cannot be matched")
            deps.append(Dependency(
                name=name.lower(), ecosystem="npm", spec=spec, version=exact, lower_bound=low,
                direct=True, scope=scope, source=source,
            ))
    if (doc.get("peerDependencies") or {}):
        warnings.append("peerDependencies are not scanned (they are provided by the consuming project)")
    if deps:
        warnings.append("package.json holds ranges, not installed versions: upload package-lock.json for exact versions and transitive packages")
    return ParseResult(deps, source, "package.json", warnings)


def parse_package_lock(text: str, source: str = "package-lock.json") -> ParseResult:
    """lockfileVersion 2/3: a flat `packages` map keyed by install path. Gives exact + transitive."""
    doc = json.loads(text)
    packages = doc.get("packages")
    if not isinstance(packages, dict):
        return ParseResult([], source, "package-lock.json",
                           ["only lockfileVersion 2 or 3 (with a 'packages' map) is supported"])
    root = packages.get("", {})
    direct_runtime = set((root.get("dependencies") or {}) | (root.get("optionalDependencies") or {}))
    direct_dev = set(root.get("devDependencies") or {})
    deps: list[Dependency] = []
    for path, info in packages.items():
        if not path or "node_modules/" not in path or info.get("link"):
            continue
        name = path.rsplit("node_modules/", 1)[1]
        version = info.get("version")
        if not version:
            continue
        direct = path == f"node_modules/{name}" and (name in direct_runtime or name in direct_dev)
        dev = bool(info.get("dev")) or (direct and name in direct_dev and name not in direct_runtime)
        deps.append(Dependency(
            name=name.lower(), ecosystem="npm", spec=version, version=version, lower_bound=version,
            direct=direct, scope="dev" if dev else "runtime", source=source,
        ))
    return ParseResult(deps, source, "package-lock.json", [])
