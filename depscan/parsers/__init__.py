"""Entry points: pick the right parser from a file's name and content, and combine manifest + lock file."""
from __future__ import annotations

import json
from dataclasses import replace

from ..models import Dependency, ParseResult
from .depcheck import parse_depcheck
from .gomod import parse_go_mod, parse_go_sum
from .lockfiles import parse_pipfile_lock, parse_poetry_lock, parse_yarn_lock
from .package_json import parse_package_json, parse_package_lock
from .requirements import parse_requirements

MANIFEST_KINDS = {"requirements.txt", "package.json"}
LOCK_KINDS = {"package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock"}


class UnsupportedFile(ValueError):
    pass


def parse_file(name: str, content: bytes) -> ParseResult:
    """Parse an uploaded dependency file or scan report. `content` is only read, never saved back."""
    text = content.decode("utf-8-sig", errors="replace")
    base = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    try:
        if base == "yarn.lock":
            return parse_yarn_lock(text, name)
        if base == "poetry.lock":
            return parse_poetry_lock(text, name)
        if base == "go.mod":
            return parse_go_mod(text, name)
        if base == "go.sum":
            return parse_go_sum(text, name)
        if base == "pipfile.lock":
            return parse_pipfile_lock(text, name)  # JSON, so check before the generic .json branch
    except (json.JSONDecodeError, ValueError) as e:  # tomllib.TOMLDecodeError is a ValueError
        raise UnsupportedFile(f"{name} could not be read: {e}") from e
    if base.endswith(".json"):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise UnsupportedFile(f"{name} is not valid JSON ({e.msg})") from e
        if not isinstance(doc, dict):
            raise UnsupportedFile(f"{name}: expected a JSON object")
        if "dependencies" in doc and isinstance(doc["dependencies"], list):
            return parse_depcheck(text, name)
        if "lockfileVersion" in doc or "packages" in doc:
            return parse_package_lock(text, name)
        if any(k in doc for k in ("dependencies", "devDependencies", "optionalDependencies", "name")):
            return parse_package_json(text, name)
        raise UnsupportedFile(f"{name}: not a package.json, package-lock.json or Dependency-Check report")
    if base.endswith(".txt"):
        return parse_requirements(text, name)
    raise UnsupportedFile(
        f"{name}: supported files are requirements.txt, package.json, package-lock.json, yarn.lock, "
        f"poetry.lock, Pipfile.lock, go.mod, go.sum and Dependency-Check JSON"
    )


def parse_files(files: list[tuple[str, bytes]]) -> ParseResult:
    return combine([parse_file(n, c) for n, c in files])


def combine(results: list[ParseResult]) -> ParseResult:
    """Prefer exact lock file versions over manifest ranges, ecosystem by ecosystem.

    The manifest still supplies which packages are direct and which are dev-only.
    Manifest entries missing from the lock file are kept as ranges, with a warning.
    """
    if len(results) == 1:
        return results[0]
    if any(r.kind == "go.mod" for r in results):  # go.mod already pins the selected versions; go.sum would add stale ones
        results = [r for r in results if r.kind != "go.sum"]
    passthrough = [r for r in results if r.kind not in MANIFEST_KINDS | LOCK_KINDS]
    warnings = [w for r in results for w in r.warnings]
    deps: list[Dependency] = [d for r in passthrough for d in r.dependencies]
    for eco in ("npm", "PyPI"):
        manifests = [d for r in results if r.kind in MANIFEST_KINDS for d in r.dependencies if d.ecosystem == eco]
        locks = [(r, d) for r in results if r.kind in LOCK_KINDS for d in r.dependencies if d.ecosystem == eco]
        if not locks:
            deps += manifests
            continue
        by_manifest = {d.name: d for d in manifests}
        seen: set[tuple[str, str | None]] = set()
        locked_names: set[str] = set()
        for r, d in locks:
            if (d.name, d.version) in seen:
                continue
            seen.add((d.name, d.version))
            locked_names.add(d.name)
            m = by_manifest.get(d.name)
            if m:
                d = replace(d, direct=True, scope=m.scope, spec=m.spec, line=m.line)
            elif r.kind != "package-lock.json" and manifests:
                d = replace(d, direct=False)  # package-lock knows directness itself; others learn it from the manifest
            deps.append(d)
        for d in manifests:
            if d.name not in locked_names:
                deps.append(d)
                warnings.append(f"{d.name} is in the manifest but not in the lock file; tested as a range")
        if not manifests:
            warnings.append("no manifest supplied with the lock file: direct vs transitive is unknown for some packages")
    warnings = list(dict.fromkeys(w for w in warnings if "upload package-lock.json" not in w or not any(r.kind in LOCK_KINDS for r in results)))
    return ParseResult(deps, ", ".join(r.source for r in results), "combined", warnings)
