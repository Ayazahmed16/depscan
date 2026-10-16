"""Step 2 tests: ranges are resolved against the registry (HTTP mocked) and labelled likely / possible / probable."""
import json
import urllib.error

import pytest

from depscan.parsers import parse_file
from depscan.pipeline import DataBundle, scan_files
from depscan.registry import Registry, resolve_ranges


def pypi_body(*versions, yanked=()):
    return json.dumps({"releases": {v: [{"yanked": v in yanked}] for v in versions}}).encode()


def npm_body(*versions):
    return json.dumps({"versions": {v: {} for v in versions}}).encode()


class FakeNet:
    """Stands in for the network: url -> body, and counts calls. Missing url = connection error."""
    def __init__(self, pages):
        self.pages, self.calls = pages, []

    def __call__(self, url, timeout):
        self.calls.append(url)
        if url not in self.pages:
            raise urllib.error.URLError("no route")
        body = self.pages[url]
        if isinstance(body, Exception):
            raise body
        return body


def reg(tmp_path, pages, **kw):
    return Registry(tmp_path, get=FakeNet(pages), **kw)


# ---------------------------------------------------------------- selection
def test_pypi_newest_satisfying_skips_prereleases_and_yanked(tmp_path):
    r = reg(tmp_path, {"https://pypi.org/pypi/pkg/json": pypi_body("1.0", "1.4", "1.5", "1.6rc1", "2.0", "2.1", yanked={"1.5"})})
    assert r.newest_satisfying("PyPI", "pkg", ">=1.0,<2.0") == "1.4"      # 1.5 yanked, 1.6rc1 is a pre-release
    assert r.newest_satisfying("PyPI", "pkg", ">=1.0") == "2.1"
    assert r.newest_satisfying("PyPI", "pkg", "~=1.0") == "1.4"
    assert r.newest_satisfying("PyPI", "pkg", "(any)") == "2.1"
    assert r.newest_satisfying("PyPI", "pkg", ">=9") is None               # nothing satisfies it


def test_npm_newest_satisfying_uses_semver_rules(tmp_path):
    r = reg(tmp_path, {"https://registry.npmjs.org/lib": npm_body("1.2.0", "1.9.0", "1.10.0-beta.1", "1.10.0", "2.0.0")})
    assert r.newest_satisfying("npm", "lib", "^1.2.0") == "1.10.0"          # numeric, not string, ordering; stays below 2
    assert r.newest_satisfying("npm", "lib", "~1.2.0") == "1.2.0"
    assert r.newest_satisfying("npm", "lib", ">=1.0.0 <1.10.0") == "1.9.0"  # beta excluded
    assert r.newest_satisfying("npm", "lib", "1.x") == "1.10.0"
    assert r.newest_satisfying("npm", "lib", "*") == "2.0.0"


def test_scoped_npm_package_url(tmp_path):
    net = FakeNet({"https://registry.npmjs.org/@scope%2Fname": npm_body("1.0.0")})
    assert Registry(tmp_path, get=net).newest_satisfying("npm", "@scope/name", "^1.0.0") == "1.0.0"


def test_unreadable_spec_returns_none_not_a_crash(tmp_path):
    r = reg(tmp_path, {"https://pypi.org/pypi/pkg/json": pypi_body("1.0")})
    assert r.newest_satisfying("PyPI", "pkg", ">>garbage") is None


# ---------------------------------------------------------------- cache and failure handling
def test_cache_means_one_network_call(tmp_path):
    net = FakeNet({"https://pypi.org/pypi/pkg/json": pypi_body("1.0", "2.0")})
    Registry(tmp_path, get=net).newest_satisfying("PyPI", "pkg", ">=1")
    Registry(tmp_path, get=net).newest_satisfying("PyPI", "pkg", ">=1")   # a new object reads the disk cache
    assert len(net.calls) == 1


def test_stale_cache_is_used_when_the_network_is_down(tmp_path):
    good = FakeNet({"https://pypi.org/pypi/pkg/json": pypi_body("1.0", "2.0")})
    Registry(tmp_path, get=good).newest_satisfying("PyPI", "pkg", ">=1")
    cache = tmp_path / "registry" / "PyPI" / "pkg.json"
    doc = json.loads(cache.read_text())
    doc["fetched_at"] = 0                                                 # make it ancient
    cache.write_text(json.dumps(doc))
    assert Registry(tmp_path, get=FakeNet({})).newest_satisfying("PyPI", "pkg", ">=1") == "2.0"


def test_first_failure_trips_the_breaker_so_later_packages_do_not_wait(tmp_path):
    net = FakeNet({})
    r = Registry(tmp_path, get=net)
    assert r.newest_satisfying("PyPI", "a", ">=1") is None and r.down
    assert r.newest_satisfying("PyPI", "b", ">=1") is None
    assert len(net.calls) == 1


def test_404_is_a_missing_package_not_an_outage(tmp_path):
    err = urllib.error.HTTPError("u", 404, "nf", {}, None)
    r = reg(tmp_path, {"https://pypi.org/pypi/ghost/json": err, "https://pypi.org/pypi/real/json": pypi_body("1.0")})
    assert r.newest_satisfying("PyPI", "ghost", ">=1") is None and not r.down
    assert r.newest_satisfying("PyPI", "real", ">=1") == "1.0"


def test_offline_flag_never_calls_the_network(tmp_path):
    net = FakeNet({"https://pypi.org/pypi/pkg/json": pypi_body("1.0")})
    assert Registry(tmp_path, get=net, offline=True).newest_satisfying("PyPI", "pkg", ">=1") is None
    assert net.calls == []


# ---------------------------------------------------------------- end to end (alpha < 1.5 vulnerable, epsilon 2.0-2.99 vulnerable)
def scan(data_dir, tmp_path, reqs, pages, **kw):
    registry = Registry(tmp_path / "cache", get=FakeNet(pages), **kw)
    return scan_files([("requirements.txt", reqs)], DataBundle(data_dir, registry))


def conf(r, id):
    return next(f["match"]["confidence"] for f in r["findings"] if f["id"] == id)


def test_both_ends_affected_is_likely(data_dir, tmp_path):
    pages = {"https://pypi.org/pypi/alpha/json": pypi_body("0.5", "1.0", "1.4", "1.6")}
    r = scan(data_dir, tmp_path, b"alpha>=0.5,<1.5\n", pages)   # lowest 0.5 and newest satisfying 1.4 are both < 1.5
    assert conf(r, "CVE-2030-0001") == "likely"
    f = r["findings"][0]
    assert f["version"] == "1.4" and any("newest release that satisfies it is 1.4" in e for e in f["match"]["evidence"])


def test_only_lowest_affected_is_possible(data_dir, tmp_path):
    pages = {"https://pypi.org/pypi/alpha/json": pypi_body("0.5", "1.0", "1.4", "1.6")}
    r = scan(data_dir, tmp_path, b"alpha>=0.5\n", pages)         # newest is 1.6 (patched), lowest 0.5 is affected
    assert conf(r, "CVE-2030-0001") == "possible"
    assert any("fresh install resolves to the patched release" in e for e in r["findings"][0]["match"]["evidence"])


def test_only_newest_affected_is_possible(data_dir, tmp_path):
    pages = {"https://pypi.org/pypi/epsilon/json": pypi_body("1.0", "2.5", "2.9")}
    r = scan(data_dir, tmp_path, b"epsilon>=1.0\n", pages)       # lowest 1.0 is outside 2.0-3.0, newest 2.9 is inside
    assert conf(r, "CVE-2030-0005") == "possible"


def test_neither_end_affected_gives_no_finding(data_dir, tmp_path):
    pages = {"https://pypi.org/pypi/alpha/json": pypi_body("1.5", "1.6")}
    assert scan(data_dir, tmp_path, b"alpha>=1.5\n", pages)["findings"] == []


def test_registry_failure_falls_back_to_lowest_and_is_probable(data_dir, tmp_path):
    r = scan(data_dir, tmp_path, b"alpha>=0.5\n", {})            # every call fails
    assert conf(r, "CVE-2030-0001") == "probable"
    assert any("could not be reached" in e for e in r["findings"][0]["match"]["evidence"])
    assert any("could not be resolved against the registry" in w for w in r["warnings"])


def test_exact_pin_never_touches_the_registry(data_dir, tmp_path):
    net = FakeNet({})
    registry = Registry(tmp_path / "cache", get=net)
    r = scan_files([("requirements.txt", b"alpha==1.0\n")], DataBundle(data_dir, registry))
    assert conf(r, "CVE-2030-0001") == "confirmed" and net.calls == []


def test_registry_is_off_by_default_in_the_bundle(data_dir):
    r = scan_files([("requirements.txt", b"alpha>=0.5\n")], DataBundle(data_dir))   # no registry given
    assert conf(r, "CVE-2030-0001") == "probable"


def test_resolve_ranges_reports_how_many_failed(tmp_path):
    res = parse_file("requirements.txt", b"a>=1\nb==2\n")
    warnings = resolve_ranges(res.dependencies, Registry(tmp_path, get=FakeNet({}), offline=True))
    assert len(warnings) == 1 and "1 of 1" in warnings[0]    # the pinned dependency is not counted


@pytest.mark.parametrize("spec,expected", [(">=1.0", "2.0"), ("(any)", "2.0"), ("~=1.0", "1.0")])  # ~=1.0 means >=1.0,==1.*
def test_open_ended_and_compatible_release_specs(tmp_path, spec, expected):
    r = reg(tmp_path, {"https://pypi.org/pypi/pkg/json": pypi_body("1.0", "2.0")})
    assert r.newest_satisfying("PyPI", "pkg", spec) == expected
