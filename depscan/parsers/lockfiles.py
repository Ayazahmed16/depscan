"""Lock file parsers: yarn.lock, poetry.lock, Pipfile.lock. (package-lock.json lives in package_json.py.)

A lock file records the version that is actually installed, so matches made from it are `confirmed`.
Lock files mostly do not say which packages are direct; `combine()` in parsers/__init__.py fills that
in from the manifest when one is supplied alongside.
"""
from __future__ import annotations

import json
import re
import tomllib

from ..matcher.versions import normalize_pypi_name
from ..models import Dependency, ParseResult


def _dep(name: str, version: str, eco: str, source: str, scope: str = "runtime") -> Dependency:
    return Dependency(name=name, ecosystem=eco, spec=f"=={version}", version=version, lower_bound=version,
                      direct=True, scope=scope, source=source, resolution="lockfile")


# ---------------------------------------------------------------- yarn.lock (v1 and berry)
_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')
_YARN_DEP_SECTIONS = ("dependencies:", "optionalDependencies:")


def _yarn_split(spec: str) -> tuple[str, str] | None:
    """'"@scope/pkg@npm:^1.0.0"' -> ('@scope/pkg', '^1.0.0'). None for an alias or an unparsable spec."""
    spec = spec.strip().strip('"')
    at = spec.rfind("@")
    if at <= 0:
        return None
    name, rng = spec[:at].lower(), spec[at + 1:]
    rng = rng.removeprefix("npm:")
    return None if "@" in rng else (name, rng)


def _yarn_dep_line(line: str) -> tuple[str, str] | None:
    """A line inside `dependencies:`: v1 `name "range"`, berry `name: range`. Returns (name, range)."""
    body = line.strip()
    m = re.match(r'^("?)(@?[^"\s:]+)\1:?\s+"?([^"]*)"?\s*$', body)
    if not m:
        return None
    return m.group(2).lower(), m.group(3).removeprefix("npm:")


def parse_yarn_lock(text: str, source: str = "yarn.lock") -> ParseResult:
    warnings: list[str] = []
    entries: list[dict] = []
    cur: dict | None = None
    in_deps = False
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "	")) and line.rstrip().endswith(":"):
            raw = line.rstrip()[:-1].split(",")
            local = any("@workspace:" in x or "@patch:" in x or "@link:" in x for x in raw)  # no registry version
            cur = {"specs": [] if local else [sp for sp in (_yarn_split(x) for x in raw) if sp], "version": None, "deps": []}
            entries.append(cur)
            in_deps = False
            continue
        if cur is None:
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= 2:
            in_deps = line.strip() in _YARN_DEP_SECTIONS
            m = _YARN_VERSION.match(line)
            if m:
                cur["version"] = m.group(1)
        elif in_deps:
            dep = _yarn_dep_line(line)
            if dep:
                cur["deps"].append(dep)
    deps: dict[tuple[str, str], Dependency] = {}
    spec_version: dict[tuple[str, str], str] = {}
    for e in entries:
        if e["version"] and e["specs"]:
            for name, rng in e["specs"]:
                spec_version[(name, rng)] = e["version"]
                deps.setdefault((name, e["version"]), _dep(name, e["version"], "npm", source))
    for e in entries:                                                # who needs whom, with the range resolved to the version yarn chose
        if not (e["version"] and e["specs"]):
            continue
        resolved = {(n, spec_version[(n, r)]) for n, r in e["deps"] if (n, r) in spec_version}
        for name in {n for n, _ in e["specs"]}:
            d = deps[(name, e["version"])]
            d.requires_resolved = sorted(set(d.requires_resolved or []) | resolved)
            d.requires = sorted({n for n, _ in d.requires_resolved})
    if not deps:
        warnings.append("no packages found: unsupported yarn.lock layout?")
    return ParseResult(list(deps.values()), source, "yarn.lock", warnings)


# ---------------------------------------------------------------- poetry.lock (TOML)
def parse_poetry_lock(text: str, source: str = "poetry.lock") -> ParseResult:
    doc = tomllib.loads(text)
    deps = []
    for pkg in doc.get("package", []):
        name, version = pkg.get("name"), pkg.get("version")
        if not name or not version:
            continue
        # Older Poetry: category = "dev". Newer Poetry: groups = ["main", "dev", ...].
        groups = pkg.get("groups")
        dev = pkg.get("category") == "dev" or (isinstance(groups, list) and groups and "main" not in groups)
        d = _dep(normalize_pypi_name(name), version, "PyPI", source, "dev" if dev else "runtime")
        d.requires = sorted(normalize_pypi_name(r) for r in (pkg.get("dependencies") or {}))  # what it depends on, from the lock file
        deps.append(d)
    version_of = {}
    for d in deps:
        version_of.setdefault(d.name, d.version)
    for d in deps:                                                   # Poetry locks one version per name, so a name identifies its node
        d.requires_resolved = [(r, version_of[r]) for r in d.requires or [] if r in version_of]
    return ParseResult(deps, source, "poetry.lock", [])


# ---------------------------------------------------------------- Pipfile.lock (JSON)
def parse_pipfile_lock(text: str, source: str = "Pipfile.lock") -> ParseResult:
    doc = json.loads(text)
    deps: list[Dependency] = []
    warnings: list[str] = []
    for section, scope in (("default", "runtime"), ("develop", "dev")):
        for name, info in (doc.get(section) or {}).items():
            version = (info.get("version") or "").removeprefix("==")
            if not version:
                warnings.append(f"{name}: no version in Pipfile.lock (git or editable), skipped")
                continue
            deps.append(_dep(normalize_pypi_name(name), version, "PyPI", source, scope))
    return ParseResult(deps, source, "Pipfile.lock", warnings)
