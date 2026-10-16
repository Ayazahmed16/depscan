"""go.mod and go.sum parsers (ecosystem "Go"). Read-only.

go.mod lists the module versions the build selects (Go's minimal version selection), including
indirect ones since Go 1.17, so its versions are exact: matches are `confirmed`.
go.sum lists hashes for every module version that was ever downloaded, which can include older
versions that are no longer selected. It is only used when no go.mod is supplied, and says so.

OSV writes Go versions without the leading "v", so we strip it (and a "+incompatible" suffix).
"""
from __future__ import annotations

import re

from ..models import Dependency, ParseResult

_REQUIRE = re.compile(r"^(?P<path>\S+)\s+(?P<version>v\S+?)(?P<indirect>\s*//\s*indirect)?\s*$")


def go_version(v: str) -> str:
    return v.removeprefix("v").removesuffix("+incompatible")


def _dep(path: str, version: str, source: str, direct: bool, resolution: str) -> Dependency:
    v = go_version(version)
    return Dependency(name=path, ecosystem="Go", spec=f"=={v}", version=v, lower_bound=v, direct=direct,
                      scope="runtime", source=source, resolution=resolution)


def parse_go_mod(text: str, source: str = "go.mod") -> ParseResult:
    deps: list[Dependency] = []
    warnings: list[str] = []
    block: str | None = None  # "require" while inside a require ( ... ) block
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        if block is None and re.match(r"^(require|replace|exclude|retract)\s*\($", line):
            block = line.split()[0]
            continue
        if block is not None and line == ")":
            block = None
            continue
        directive, body = (block, line) if block else (line.split(None, 1)[0], line.split(None, 1)[1] if " " in line else "")
        if directive == "require":
            m = _REQUIRE.match(body)
            if m:
                deps.append(_dep(m["path"], m["version"], source, direct=not m["indirect"], resolution="pin"))
            else:
                warnings.append(f"line {lineno}: could not read '{line}'")
        elif directive == "replace":
            warnings.append(f"line {lineno}: replace directive '{body}': the replaced module may use a different version or source than go.mod says")
        elif directive in ("exclude", "retract"):
            continue
    if not deps:
        warnings.append("no require directives found")
    warnings.append("the Go toolchain / standard library version is not scanned (the 'go' directive is a language minimum, not an installed version)")
    return ParseResult(deps, source, "go.mod", warnings)


def parse_go_sum(text: str, source: str = "go.sum") -> ParseResult:
    seen: dict[tuple[str, str], Dependency] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 3 or not parts[1].startswith("v") or parts[1].endswith("/go.mod"):
            continue  # "/go.mod" lines only hash the module file, not downloaded source
        seen.setdefault((parts[0], parts[1]), _dep(parts[0], parts[1], source, direct=True, resolution="lockfile"))
    warnings = ["go.sum lists every module version ever downloaded, which can include versions go.mod no longer selects; "
                "supply go.mod too for the versions actually built. Direct vs indirect is unknown, so all are treated as direct."]
    return ParseResult(list(seen.values()), source, "go.sum", warnings)
