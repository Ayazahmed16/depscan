"""The one place that knows which ecosystems depscan supports.

Adding an ecosystem whose versions order like semver (Go, Cargo, Hex, Pub, ...) takes two things:
  1. a row in ECOSYSTEMS below (its OSV name, how names are normalised, how versions order), and
  2. one manifest parser in depscan/parsers/, registered in parsers/__init__.py.
Vulnerability lookup needs nothing else: advisories come from OSV, either the bulk snapshot
(scripts/fetch_data.py --ecosystems <Name>) or, if there is no local index, the OSV.dev API.

Ecosystems with their own version ordering (Maven, NuGet, Debian, ...) additionally need a comparator
in matcher/versions.py. That is the honest limit of "one parser plus one mapping".
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Ecosystem:
    name: str                          # exactly the name OSV uses: "PyPI", "npm", "Go", ...
    scheme: str                        # version ordering: "pep440" or "semver"
    normalize: Callable[[str], str]    # package name -> the key used in the index and by parsers


def _pypi_name(n: str) -> str:
    return re.sub(r"[-_.]+", "-", n).lower()  # PEP 503


ECOSYSTEMS: dict[str, Ecosystem] = {
    e.name: e for e in (
        Ecosystem("PyPI", "pep440", _pypi_name),
        Ecosystem("npm", "semver", str.lower),
        Ecosystem("Go", "semver", lambda n: n),  # module paths are case-sensitive
    )
}


def get(name: str) -> Ecosystem:
    try:
        return ECOSYSTEMS[name]
    except KeyError:
        raise ValueError(f"unsupported ecosystem '{name}' (known: {', '.join(ECOSYSTEMS)})") from None


def normalize_name(ecosystem: str, name: str) -> str:
    return get(ecosystem).normalize(name)
