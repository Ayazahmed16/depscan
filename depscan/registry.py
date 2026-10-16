"""Resolve a version range to the newest real release, using the package registry.

PyPI:  https://pypi.org/pypi/<name>/json          (releases -> versions, SpecifierSet picks the newest)
npm:   https://registry.npmjs.org/<name>          (versions -> semantic_version NpmSpec picks the newest)

Registry data is the only live lookup besides the optional OSV.dev API, so it is built to be safe
offline:
  * cache first (on disk, 7 days); a stale cache is still used when the network is down
  * short timeout, and after the first network failure the registry is treated as down for the
    rest of the run (no repeated waits)
  * every failure returns None, and the caller falls back to the lowest allowed version ("probable")
Pre-releases and yanked releases are never chosen.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from semantic_version import NpmSpec, Version as NpmVersion

from .models import Dependency

USER_AGENT = "depscan-hackathon/0.1 (range resolution, read-only)"
TTL_SECONDS = 7 * 24 * 3600

HttpGet = Callable[[str, float], bytes]


def default_get(url: str, timeout: float) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _pypi_versions(body: bytes) -> list[str]:
    releases = json.loads(body).get("releases", {})
    # keep a version only if at least one of its files has not been yanked
    return [v for v, files in releases.items() if any(not f.get("yanked") for f in files)]


def _npm_versions(body: bytes) -> list[str]:
    return list(json.loads(body).get("versions", {}))


# ecosystem -> (URL for a package name, parser of the response body)
SOURCES: dict[str, tuple[Callable[[str], str], Callable[[bytes], list[str]]]] = {
    "PyPI": (lambda n: f"https://pypi.org/pypi/{urllib.parse.quote(n)}/json", _pypi_versions),
    "npm": (lambda n: "https://registry.npmjs.org/" + n.replace("/", "%2F"), _npm_versions),  # @scope%2Fname
}


class Registry:
    def __init__(self, cache_dir: Path, *, get: HttpGet | None = None, timeout: float = 6.0, offline: bool = False):
        self.cache_dir = cache_dir / "registry"
        self.get = get or default_get
        self.timeout = timeout
        self.down = offline  # offline=True never touches the network, cache only
        self.network_calls = 0

    # ---- cache
    def _path(self, eco: str, name: str) -> Path:
        safe = name.replace("/", "__").replace("@", "_at_")
        return self.cache_dir / eco / f"{safe}.json"

    def _read_cache(self, eco: str, name: str) -> tuple[list[str], float] | None:
        p = self._path(eco, name)
        try:
            doc = json.loads(p.read_text("utf-8"))
            return doc["versions"], float(doc["fetched_at"])
        except (OSError, ValueError, KeyError):
            return None

    def versions(self, eco: str, name: str) -> list[str] | None:
        """Released versions, or None if unknown (unsupported ecosystem, offline with no cache, error)."""
        if eco not in SOURCES:
            return None
        cached = self._read_cache(eco, name)
        if cached and time.time() - cached[1] < TTL_SECONDS:
            return cached[0]
        if not self.down:
            url_for, parse = SOURCES[eco]
            try:
                self.network_calls += 1
                versions = parse(self.get(url_for(name), self.timeout))
            except urllib.error.HTTPError as e:
                if e.code == 404:           # package does not exist on the registry: not an outage
                    return None
                self.down = True
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
                self.down = True            # circuit breaker: stop waiting on every package
            except (ValueError, KeyError):
                return None                 # malformed response for this package only
            else:
                p = self._path(eco, name)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(json.dumps({"fetched_at": time.time(), "versions": versions}), "utf-8")
                return versions
        return cached[0] if cached else None  # stale cache beats nothing when the network is down

    # ---- selection
    def newest_satisfying(self, eco: str, name: str, spec: str) -> str | None:
        versions = self.versions(eco, name)
        if not versions:
            return None
        try:
            if eco == "PyPI":
                ok = []
                for v in versions:
                    try:
                        ok.append(Version(v))
                    except InvalidVersion:
                        pass
                best = list(SpecifierSet("" if spec in ("(any)", "") else spec).filter(ok, prereleases=False))
                return str(max(best)) if best else None
            parsed = []
            for v in versions:
                try:
                    parsed.append(NpmVersion(v))
                except ValueError:
                    pass
            chosen = NpmSpec("*" if spec.strip() in ("", "latest") else spec).select(parsed)  # npm rules: no pre-releases
            return str(chosen) if chosen is not None else None
        except (InvalidSpecifier, ValueError):
            return None  # a spec we cannot read: fall back to the lowest bound


def resolve_ranges(deps: list[Dependency], registry: Registry) -> list[str]:
    """Fill dep.newest / dep.registry_status for range dependencies. Returns warnings for the report."""
    ranged = [d for d in deps if not d.exact and d.ecosystem in SOURCES]
    resolved = failed = 0
    for d in ranged:
        newest = registry.newest_satisfying(d.ecosystem, d.name, d.spec)
        if newest:
            d.newest, d.registry_status = newest, "resolved"
            resolved += 1
        else:
            d.registry_status = "failed"
            failed += 1
    warnings = []
    if failed:
        warnings.append(f"{failed} of {len(ranged)} version ranges could not be resolved against the registry "
                        f"(offline, unknown package or unreadable range); they were tested at their lowest allowed version")
    return warnings
