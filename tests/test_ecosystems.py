"""Step 3 tests: Go parser, the ecosystem registry, and OSV.dev API lookup (HTTP mocked)."""
import json
import urllib.error

import pytest

from depscan import ecosystems
from depscan.ecosystems import Ecosystem, normalize_name
from depscan.matcher import match_dependency
from depscan.matcher.versions import evaluate_range, parse_version
from depscan.models import Dependency
from depscan.osv_api import OsvApiIndex
from depscan.parsers import UnsupportedFile, parse_file, parse_files
from depscan.pipeline import DataBundle, scan_files

GO_MOD = """module example.com/app

go 1.21

require github.com/single/line v1.0.0

require (
\tgithub.com/gin-gonic/gin v1.6.0
\tgolang.org/x/crypto v0.1.0 // indirect
\tgithub.com/old/thing v2.0.0+incompatible
\tgolang.org/x/text v0.0.0-20210101000000-abcdef123456
)

replace github.com/foo/bar => ../bar
exclude github.com/bad/mod v1.0.0
"""

GO_SUM = """github.com/gin-gonic/gin v1.6.0 h1:abc=
github.com/gin-gonic/gin v1.6.0/go.mod h1:def=
github.com/gin-gonic/gin v1.5.0 h1:ghi=
golang.org/x/crypto v0.1.0/go.mod h1:jkl=
"""


# ---------------------------------------------------------------- Go parsers
def test_go_mod_requires_indirect_and_version_forms():
    res = parse_file("go.mod", GO_MOD.encode())
    by = {d.name: d for d in res.dependencies}
    assert by["github.com/single/line"].version == "1.0.0"                        # 'v' stripped to match OSV
    assert by["github.com/gin-gonic/gin"].direct and not by["golang.org/x/crypto"].direct
    assert by["github.com/old/thing"].version == "2.0.0"                          # +incompatible dropped
    assert by["golang.org/x/text"].version == "0.0.0-20210101000000-abcdef123456"  # pseudo-version kept
    assert all(d.exact and d.ecosystem == "Go" and d.resolution == "pin" for d in res.dependencies)
    assert "github.com/bad/mod" not in by                                          # exclude is not a dependency
    assert any("replace directive" in w for w in res.warnings)


def test_go_sum_skips_gomod_hash_lines_and_warns():
    res = parse_file("go.sum", GO_SUM.encode())
    assert {(d.name, d.version) for d in res.dependencies} == {("github.com/gin-gonic/gin", "1.6.0"), ("github.com/gin-gonic/gin", "1.5.0")}
    assert any("ever downloaded" in w for w in res.warnings)


def test_go_mod_wins_over_go_sum_when_both_supplied():
    res = parse_files([("go.mod", GO_MOD.encode()), ("go.sum", GO_SUM.encode())])
    gin = [d for d in res.dependencies if d.name == "github.com/gin-gonic/gin"]
    assert [d.version for d in gin] == ["1.6.0"]                                   # stale 1.5.0 from go.sum ignored


def test_unknown_file_still_rejected():
    with pytest.raises(UnsupportedFile):
        parse_file("pom.xml", b"<project/>")


# ---------------------------------------------------------------- ecosystem registry
def test_registry_normalisation_and_errors():
    assert normalize_name("PyPI", "Foo_Bar") == "foo-bar"
    assert normalize_name("npm", "Lodash") == "lodash"
    assert normalize_name("Go", "github.com/Foo/Bar") == "github.com/Foo/Bar"     # case-sensitive module paths
    with pytest.raises(ValueError, match="unsupported ecosystem"):
        normalize_name("Maven", "x")


def test_go_versions_order_as_semver():
    r = {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.7.7"}]}
    assert evaluate_range("Go", "1.6.0", r)[0] and not evaluate_range("Go", "1.7.7", r)[0]
    assert parse_version("Go", "0.0.0-20210101000000-abcdef123456") < parse_version("Go", "0.0.0")


def test_adding_a_semver_ecosystem_is_one_table_row(monkeypatch):
    """Cargo is NOT supported by depscan today. This proves what adding it would take: one row, no other code."""
    monkeypatch.setitem(ecosystems.ECOSYSTEMS, "crates.io", Ecosystem("crates.io", "semver", str.lower))
    adv = {"id": "RUSTSEC-1", "aliases": ["CVE-2031-1"], "modified": "2031-01-01T00:00:00Z",
           "affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}], "versions": []}]}
    dep = Dependency(name="serde", ecosystem="crates.io", spec="==1.0.0", version="1.0.0", lower_bound="1.0.0")
    [m] = match_dependency(dep, [adv])
    assert m.confidence == "confirmed" and m.fixed_versions == ["1.2.3"]


# ---------------------------------------------------------------- OSV.dev API (mocked)
GO_ADVISORY = {
    "id": "GO-2031-0001", "aliases": ["CVE-2031-0001"], "summary": "bad thing in mod", "modified": "2031-01-01T00:00:00Z",
    "affected": [{"package": {"name": "example.com/mod", "ecosystem": "Go"},
                  "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.5.0"}]}]}],
}


class FakeOsv:
    def __init__(self, fail=False, page=False):
        self.calls, self.fail, self.page = [], fail, page

    def __call__(self, method, url, body, timeout):
        self.calls.append((method, url.rsplit("/v1", 1)[1]))
        if self.fail:
            raise urllib.error.URLError("offline")
        if url.endswith("/querybatch"):
            results = []
            for q in body["queries"]:
                if q["package"]["name"] != "example.com/mod":
                    results.append({})                                     # OSV returns {} for no vulns
                elif self.page:
                    results.append({"vulns": [], "next_page_token": "t1"})
                else:
                    results.append({"vulns": [{"id": "GO-2031-0001", "modified": "2031-01-01T00:00:00Z"}]})
            return {"results": results}
        if url.endswith("/query"):
            assert body["page_token"] == "t1" and body["package"]["ecosystem"] == "Go"
            return {"vulns": [{"id": "GO-2031-0001", "modified": "2031-01-01T00:00:00Z"}]}
        if url.endswith("/vulns/GO-2031-0001"):
            return GO_ADVISORY
        raise AssertionError(url)


def go_scan(data_dir, transport, **kw):
    gomod = b"module x\n\nrequire (\n\texample.com/mod v1.0.0\n\texample.com/clean v1.0.0\n)\n"
    return scan_files([("go.mod", gomod)], DataBundle(data_dir, osv_api=True, osv_transport=transport, **kw))


def test_go_matched_through_the_api_with_one_batched_request(data_dir):
    net = FakeOsv()
    r = go_scan(data_dir, net)
    [f] = r["findings"]
    assert f["id"] == "CVE-2031-0001" and f["package"] == "example.com/mod" and f["match"]["confidence"] == "confirmed"
    assert f["fixed_version"] == "1.5.0" and f["ecosystem"] == "Go"
    assert [c for c in net.calls if c[1] == "/querybatch"] == [("POST", "/querybatch")]   # both modules, one request
    assert not any("could NOT be checked" in w for w in r["warnings"])


def test_api_results_are_cached_so_a_later_offline_run_still_works(data_dir):
    go_scan(data_dir, FakeOsv())
    net = FakeOsv(fail=True)                       # now the network is gone
    r = go_scan(data_dir, net, offline=True)
    assert len(r["findings"]) == 1 and net.calls == []


def test_api_pagination_is_followed(data_dir):
    net = FakeOsv(page=True)
    assert len(go_scan(data_dir, net)["findings"]) == 1
    assert ("POST", "/query") in net.calls


def test_api_outage_is_reported_not_shown_as_clean(data_dir):
    r = go_scan(data_dir, FakeOsv(fail=True))
    assert r["findings"] == []
    assert any("could NOT be checked" in w and "not a clean result" in w for w in r["warnings"])


def test_missing_index_without_api_gives_a_helpful_error(data_dir):
    with pytest.raises(FileNotFoundError, match="fetch_data.py"):
        scan_files([("go.mod", b"module x\n\nrequire example.com/mod v1.0.0\n")], DataBundle(data_dir))


def test_api_index_get_returns_compact_records(tmp_path):
    idx = OsvApiIndex("Go", tmp_path, transport=FakeOsv())
    [a] = idx.get("example.com/mod")
    assert a["id"] == "GO-2031-0001" and a["affected"][0]["ranges"][0]["events"][1] == {"fixed": "1.5.0"}
    assert json.loads((tmp_path / "osv_api" / "Go.names.json").read_text())["example.com/mod"]["vulns"]
