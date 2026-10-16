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


def _yarn_name(spec: str) -> str | None:
    spec = spec.strip().strip('"').removeprefix("npm:")
    at = spec.rfind("@")
    return spec[:at].lower() if at > 0 else None


def parse_yarn_lock(text: str, source: str = "yarn.lock") -> ParseResult:
    deps: dict[tuple[str, str], Dependency] = {}
    warnings: list[str] = []
    header_names: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")) and line.rstrip().endswith(":"):
            specs = [s for s in line.rstrip()[:-1].split(",")]
            header_names = [n for n in (_yarn_name(s) for s in specs) if n]
            if any("@workspace:" in s or "@patch:" in s or "@link:" in s for s in specs):
                header_names = []  # local workspace / patched entries have no registry version
            continue
        m = _YARN_VERSION.match(line)
        if m and header_names:
            for name in set(header_names):
                deps.setdefault((name, m.group(1)), _dep(name, m.group(1), "npm", source))
            header_names = []
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
        deps.append(_dep(normalize_pypi_name(name), version, "PyPI", source, "dev" if dev else "runtime"))
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
