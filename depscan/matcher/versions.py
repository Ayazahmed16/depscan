"""Version comparison for PyPI (PEP 440) and npm (semver), and OSV range evaluation.

OSV expresses affected versions as events inside a range:
    {"introduced": "1.0"}, {"fixed": "1.4.2"}   -> affected from 1.0 up to (not including) 1.4.2
    {"last_affected": "1.9"}                     -> affected up to and including 1.9
We walk the events in version order, the way the OSV spec describes.
"""
from __future__ import annotations

import re
from functools import cmp_to_key

from packaging.version import InvalidVersion, Version

from ..ecosystems import get as get_ecosystem


class UnparsableVersion(ValueError):
    pass


def normalize_pypi_name(name: str) -> str:
    """PEP 503: case and runs of - _ . are insignificant."""
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------- semver
_SEMVER = re.compile(
    r"^v?(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$"
)


class SemVer:
    """Minimal semver with the precedence rules from semver.org (build metadata ignored)."""

    def __init__(self, text: str):
        m = _SEMVER.match(text.strip())
        if not m:
            raise UnparsableVersion(text)
        self.major, self.minor, self.patch = int(m["major"]), int(m["minor"]), int(m["patch"])
        self.pre = m["pre"].split(".") if m["pre"] else []
        self.text = text

    def _key(self, other: "SemVer") -> int:
        for a, b in ((self.major, other.major), (self.minor, other.minor), (self.patch, other.patch)):
            if a != b:
                return -1 if a < b else 1
        if not self.pre and not other.pre:
            return 0
        if not self.pre:   # a release is higher than any of its prereleases
            return 1
        if not other.pre:
            return -1
        for a, b in zip(self.pre, other.pre):
            if a == b:
                continue
            a_num, b_num = a.isdigit(), b.isdigit()
            if a_num and b_num:
                return -1 if int(a) < int(b) else 1
            if a_num != b_num:  # numeric identifiers sort below alphanumeric ones
                return -1 if a_num else 1
            return -1 if a < b else 1
        return (len(self.pre) > len(other.pre)) - (len(self.pre) < len(other.pre))

    def __lt__(self, o): return self._key(o) < 0
    def __le__(self, o): return self._key(o) <= 0
    def __gt__(self, o): return self._key(o) > 0
    def __ge__(self, o): return self._key(o) >= 0
    def __eq__(self, o): return isinstance(o, SemVer) and self._key(o) == 0
    def __hash__(self): return hash((self.major, self.minor, self.patch, tuple(self.pre)))


def parse_version(ecosystem: str, text: str):
    """Returns an orderable version object, or raises UnparsableVersion."""
    try:
        return Version(text) if get_ecosystem(ecosystem).scheme == "pep440" else SemVer(text)
    except InvalidVersion as e:
        raise UnparsableVersion(text) from e


def is_prerelease(ecosystem: str, text: str) -> bool:
    try:
        v = parse_version(ecosystem, text)
    except UnparsableVersion:
        return False
    return bool(v.is_prerelease if isinstance(v, Version) else v.pre)


def major_of(ecosystem: str, text: str) -> int | None:
    try:
        v = parse_version(ecosystem, text)
    except UnparsableVersion:
        return None
    return v.major  # both Version and SemVer expose .major


# ---------------------------------------------------------------- OSV range evaluation
def _event_key(ecosystem: str):
    def key(ev: dict):
        value = next(iter(ev.values()))
        # "0" means "from the very beginning" and must sort first
        return (0, None) if value == "0" else (1, parse_version(ecosystem, value))
    return cmp_to_key(lambda a, b: (key_cmp(key(a), key(b))))


def key_cmp(a, b) -> int:
    if a[0] != b[0]:
        return -1 if a[0] < b[0] else 1
    if a[1] is None:
        return 0
    return -1 if a[1] < b[1] else (1 if a[1] > b[1] else 0)


def evaluate_range(ecosystem: str, version: str, rng: dict) -> tuple[bool, str | None, str]:
    """Is `version` inside one OSV range?

    Returns (affected, fixed_in, explanation). `fixed_in` is the fix that ends the matched
    interval. Raises UnparsableVersion if the version or an event is not a valid version.
    """
    v = parse_version(ecosystem, version)
    events = [e for e in rng.get("events", []) if any(k in e for k in ("introduced", "fixed", "last_affected"))]
    events = sorted(events, key=_event_key(ecosystem))

    affected = False
    interval_start: str | None = None
    fixed_in: str | None = None
    for ev in events:
        kind, value = next(iter(ev.items()))
        bound = None if value == "0" else parse_version(ecosystem, value)
        if kind == "introduced":
            if bound is None or v >= bound:
                affected = True
                interval_start = value
        elif kind == "fixed":
            if bound is not None and v >= bound:
                affected = False
            elif affected and fixed_in is None:
                fixed_in = value  # first fix above our version
        elif kind == "last_affected":
            if bound is not None and v > bound:
                affected = False
    if not affected:
        return False, None, f"{version} is outside the listed range(s)"
    if fixed_in:
        return True, fixed_in, f"{version} is inside the range introduced {interval_start}, fixed {fixed_in}"
    return True, None, f"{version} is inside a range introduced {interval_start} with no fixed version listed"


def evaluate_advisory(ecosystem: str, version: str, affected_entries: list[dict]) -> tuple[bool | None, str | None, str]:
    """Combine all affected entries of ONE advisory record for ONE package.

    Returns (affected | None, fixed_in, reason). None means the record cannot decide
    (for example only git commit ranges, or versions we cannot parse).
    """
    decided = False
    last_reason = "advisory has no version information we can use"
    for entry in affected_entries:
        # An explicit version list is the strongest evidence.
        if version in entry.get("versions", []):
            return True, _first_fix_after(ecosystem, version, entry), f"{version} is listed explicitly in the advisory's affected versions"
        for rng in entry.get("ranges", []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue  # GIT ranges use commit hashes: not comparable to a package version
            try:
                hit, fixed, why = evaluate_range(ecosystem, version, rng)
            except UnparsableVersion as e:
                return None, None, f"could not compare version {e}"
            decided = True
            if hit:
                return True, fixed, why
            last_reason = why
    if decided:
        return False, None, last_reason
    return None, None, last_reason


def _first_fix_after(ecosystem: str, version: str, entry: dict) -> str | None:
    v = parse_version(ecosystem, version)
    fixes = []
    for rng in entry.get("ranges", []):
        for ev in rng.get("events", []):
            if "fixed" in ev:
                try:
                    if parse_version(ecosystem, ev["fixed"]) > v:
                        fixes.append(ev["fixed"])
                except UnparsableVersion:
                    pass
    return min(fixes, key=lambda f: parse_version(ecosystem, f)) if fixes else None
