"""The dependency graph: lock-file links (checked against what npm and yarn really installed) and the paths built on them."""
import json
from pathlib import Path

from depscan.depgraph import ROOT, build_dependency_graph
from depscan.models import Dependency
from depscan.parsers import parse_files
from depscan.parsers.lockfiles import parse_poetry_lock, parse_yarn_lock
from depscan.parsers.package_json import parse_package_lock
from depscan.pipeline import DataBundle, scan_files

HERE = Path(__file__).parent
REAL = HERE / "fixtures" / "real-npm"
BENCH_SNAPSHOT = HERE.parent / "benchmark" / "snapshot"


def edges(result):
    return {(f"{d.name}@{d.version}", f"{n}@{v}") for d in result.dependencies for n, v in (d.requires_resolved or [])}


# ------------------------------------------------------------------ real lock files against real installs
def test_package_lock_links_equal_what_npm_ls_reports_on_a_real_lock():
    """251 real packages, 21 of them nested copies. `npm ls --all --json` (npm's own resolver) is the oracle."""
    mine = edges(parse_package_lock((REAL / "package-lock.json").read_text("utf-8")))
    oracle = set()

    def walk(deps, parent):
        for name, info in (deps or {}).items():
            child = f"{name.lower()}@{info['version']}"
            if parent:
                oracle.add((parent, child))
            walk(info.get("dependencies"), child)

    walk(json.loads((REAL / "npm-ls.json").read_text("utf-8"))["dependencies"], None)
    assert len(mine) == len(oracle) == 550 and mine == oracle


def test_yarn_lock_links_equal_the_node_modules_yarn_installed_on_a_real_lock():
    oracle = {tuple(e) for e in json.loads((REAL / "yarn-disk-edges.json").read_text("utf-8"))["edges"]}
    mine = edges(parse_yarn_lock((REAL / "yarn.lock").read_text("utf-8")))
    assert len(mine) > 500 and mine == oracle


# ------------------------------------------------------------------ npm resolution, on a small lock written by hand
LOCK = {
    "lockfileVersion": 3,
    "packages": {
        "": {"dependencies": {"app": "1.0.0", "lodash": "4.17.15"}},
        "node_modules/app": {"version": "1.0.0", "dependencies": {"lodash": "^4.0.0", "util": "1.0.0"}},
        "node_modules/lodash": {"version": "4.17.21"},
        "node_modules/app/node_modules/lodash": {"version": "4.17.15"},
        "node_modules/util": {"version": "1.0.0", "dependencies": {"lodash": "*"}, "peerDependencies": {"opt": "1", "must": "1"},
                              "peerDependenciesMeta": {"opt": {"optional": True}}},
        "node_modules/must": {"version": "2.0.0"},
        "node_modules/opt": {"version": "1.0.0"},                                       # installed, but only an optional peer of util
        "node_modules/@scope/pkg": {"version": "3.0.0", "dependencies": {"missing-optional": "1"}, "optionalDependencies": {"gone": "1"}},
    },
}


def test_a_nested_copy_is_resolved_for_its_own_parent_and_the_root_copy_for_everyone_else():
    r = {d.name + "@" + d.version: d for d in parse_package_lock(json.dumps(LOCK)).dependencies}
    assert ("lodash", "4.17.15") in r["app@1.0.0"].requires_resolved                 # app's own nested copy
    assert ("lodash", "4.17.21") in r["util@1.0.0"].requires_resolved                # util sees the root copy
    assert ("lodash", "4.17.15") not in r["util@1.0.0"].requires_resolved


def test_peer_dependencies_count_unless_optional_and_missing_packages_are_skipped():
    r = {d.name: d for d in parse_package_lock(json.dumps(LOCK)).dependencies}
    assert ("must", "2.0.0") in r["util"].requires_resolved
    assert not any(n == "opt" for n, _ in r["util"].requires_resolved)               # an optional peer is not a link even when present
    assert r["@scope/pkg"].requires_resolved == []                                  # neither dependency is in the lock


def test_a_nested_copy_of_a_direct_dependencys_name_stays_transitive():
    """Regression: combining package.json with the lock marked every copy of a manifest name as direct."""
    manifest = json.dumps({"dependencies": {"lodash": "4.17.15"}})
    res = parse_files([("package.json", manifest.encode()), ("package-lock.json", json.dumps(LOCK).encode())])
    by = {(d.name, d.version): d for d in res.dependencies}
    assert by[("lodash", "4.17.21")].direct is True                                  # the root copy is the direct one
    assert by[("lodash", "4.17.15")].direct is False                                 # app's nested copy is not


# ------------------------------------------------------------------ yarn and poetry
def test_yarn_v1_links_are_resolved_through_the_ranges_each_entry_was_locked_for():
    text = '''
"@scope/a@^1.0.0", "@scope/a@^1.2.0":
  version "1.2.0"
  dependencies:
    b "^2.0.0"
    "@scope/c" "~3.1.0"

b@^2.0.0:
  version "2.5.0"

b@^1.0.0:
  version "1.9.0"

"@scope/c@~3.1.0":
  version "3.1.4"
'''
    d = {(x.name, x.version): x for x in parse_yarn_lock(text).dependencies}
    assert d[("@scope/a", "1.2.0")].requires_resolved == [("@scope/c", "3.1.4"), ("b", "2.5.0")]     # ^2.0.0 -> 2.5.0, not 1.9.0


def test_yarn_berry_format():
    text = '''
"a@npm:^1.0.0":
  version: 1.0.0
  dependencies:
    b: ^2.0.0
    "@s/c": npm:^3.0.0
  languageName: node

"b@npm:^2.0.0":
  version: 2.1.0

"@s/c@npm:^3.0.0":
  version: 3.0.0

"app@workspace:.":
  version: 0.0.0-use.local
  dependencies:
    a: ^1.0.0
'''
    res = parse_yarn_lock(text)
    d = {x.name: x for x in res.dependencies}
    assert d["a"].requires_resolved == [("@s/c", "3.0.0"), ("b", "2.1.0")]
    assert "app" not in d                                                              # the workspace itself is not a package


def test_poetry_links_resolve_to_the_single_locked_version():
    text = '''
[[package]]
name = "Requests"
version = "2.31.0"
[package.dependencies]
urllib3 = ">=1.21"
certifi = ">=2017"

[[package]]
name = "urllib3"
version = "2.0.7"

[[package]]
name = "certifi"
version = "2023.7.22"
'''
    d = {x.name: x for x in parse_poetry_lock(text).dependencies}
    assert d["requests"].requires_resolved == [("certifi", "2023.7.22"), ("urllib3", "2.0.7")]


# ------------------------------------------------------------------ the graph
def dep(name, version, requires=None, direct=False, scope="runtime", eco="npm"):
    d = Dependency(name=name, ecosystem=eco, version=version, lower_bound=version, direct=direct, scope=scope, resolution="lockfile")
    d.requires_resolved = requires
    return d


def finding(name, version, risk=50.0, eco="npm"):
    return {"ecosystem": eco, "package": name, "version": version, "risk": {"score": risk}}


def chain():
    return build_dependency_graph([
        dep("app", "1", [("mid", "1")], direct=True), dep("mid", "1", [("leaf", "1")]), dep("leaf", "1", []),
        dep("other", "1", [("leaf", "1")], direct=True), dep("dev-tool", "1", [("leaf", "1")], direct=True, scope="dev"),
    ])


def test_a_transitive_finding_names_the_route_and_every_direct_parent():
    g = chain()
    p = g.path_for(finding("leaf", "1"))
    assert p["known"] and not p["direct"]
    assert p["path_labels"][-1] == "leaf@1" and len(p["path_labels"]) in (2, 3)
    assert p["direct_parents"] == ["app", "dev-tool", "other"]
    assert "cannot be fixed by editing your manifest" in p["note"] and "those dependencies" in p["note"]


def test_the_shortest_route_wins_and_a_runtime_route_beats_a_dev_one():
    g = chain()
    assert g.path_for(finding("leaf", "1"))["path_labels"] == ["other@1", "leaf@1"]      # 2 hops beat app -> mid -> leaf
    only = build_dependency_graph([dep("a", "1", [("x", "1")], direct=True, scope="dev"), dep("b", "1", [("x", "1")], direct=True),
                                   dep("x", "1", [])])
    assert only.path_for(finding("x", "1"))["path_labels"][0] == "b@1"                    # same length: the runtime parent first


def test_a_direct_dependency_has_no_parents_to_blame():
    p = chain().path_for(finding("app", "1"))
    assert p["known"] and p["direct"] and p["direct_parents"] == [] and p["path_labels"] == ["app@1"]


def test_copies_of_one_package_merge_keeping_the_strongest_direct_and_scope_flags():
    for order in (False, True):
        copies = [dep("a", "1", [], direct=True, scope="dev"), dep("a", "1", [], direct=False, scope="runtime")]
        g = build_dependency_graph(copies[::-1] if order else copies)
        attrs = g.g.nodes["npm:a@1"]
        assert attrs["direct"] is True and attrs["scope"] == "runtime"                   # direct anywhere = direct; runtime anywhere = runtime


def test_two_versions_of_one_package_are_different_nodes_with_their_own_routes():
    g = build_dependency_graph([
        dep("a", "1", [("lodash", "4.17.15")], direct=True), dep("b", "1", [("lodash", "4.17.21")], direct=True),
        dep("lodash", "4.17.15", []), dep("lodash", "4.17.21", [])])
    assert g.path_for(finding("lodash", "4.17.15"))["path_labels"] == ["a@1", "lodash@4.17.15"]
    assert g.path_for(finding("lodash", "4.17.21"))["path_labels"] == ["b@1", "lodash@4.17.21"]


def test_without_any_links_a_transitive_package_says_what_is_missing_and_nothing_is_invented():
    g = build_dependency_graph([dep("a", "1", None, direct=True), dep("t", "1", None)])
    p = g.path_for(finding("t", "1"))
    assert not p["known"] and p["path"] == [] and "package-lock.json" in p["note"]
    r = g.render([finding("t", "1")])
    assert r["stats"]["links_known"] is False and r["links"] == [] and r["stats"]["unlinked_transitive"] == 1


def test_a_package_the_links_never_reach_is_reported_as_unlinked_when_links_exist_elsewhere():
    g = build_dependency_graph([dep("a", "1", [("b", "1")], direct=True), dep("b", "1", []), dep("orphan", "1", [])])
    p = g.path_for(finding("orphan", "1"))
    assert not p["known"] and "does not link it" in p["note"]


def test_cycles_do_not_hang_and_a_missing_link_target_is_ignored():
    g = build_dependency_graph([dep("a", "1", [("b", "1")], direct=True), dep("b", "1", [("a", "1"), ("ghost", "9")])])
    assert g.path_for(finding("b", "1"))["path_labels"] == ["a@1", "b@1"]
    assert "ghost" not in " ".join(g.g.nodes)


def test_an_unknown_package_is_not_found_rather_than_an_error():
    p = chain().path_for(finding("nope", "1"))
    assert not p["known"] and "Not found" in p["note"]


def test_a_range_dependency_is_found_by_name_when_the_versions_differ():
    d = Dependency(name="r", ecosystem="npm", spec="^1.0.0", version=None, lower_bound="1.0.0", direct=True)
    g = build_dependency_graph([d])
    assert g.path_for(finding("r", "1.4.0"))["direct"] is True


def test_render_draws_only_direct_dependencies_vulnerable_packages_and_their_routes():
    deps = [dep("app", "1", [("mid", "1"), ("safe", "1")], direct=True), dep("mid", "1", [("leaf", "1")]), dep("leaf", "1", []), dep("safe", "1", [])]
    r = build_dependency_graph(deps).render([finding("leaf", "1", risk=77.7), finding("leaf", "1", risk=40.0)])
    ids = {n["label"]: n for n in r["nodes"]}
    assert set(ids) == {"app@1", "mid@1", "leaf@1"} and "safe@1" not in ids          # the safe sibling is not drawn
    assert ids["leaf@1"]["kind"] == "vulnerable" and ids["leaf@1"]["findings"] == 2 and ids["leaf@1"]["max_risk"] == 77.7
    assert ids["app@1"]["kind"] == "direct" and ids["mid@1"]["kind"] == "transitive" and ids["mid@1"]["depth"] == 2
    assert {(lk["source"], lk["target"]) for lk in r["links"]} == {("npm:app@1", "npm:mid@1"), ("npm:mid@1", "npm:leaf@1")}
    s = r["stats"]
    assert (s["packages"], s["direct"], s["transitive"], s["vulnerable_packages"], s["max_depth"], s["shown"]) == (4, 1, 3, 1, 3, 3)      # app (1) -> mid (2) -> leaf (3)
    assert ROOT not in json.dumps(r) and "lock files" in r["limitation"]


def test_a_large_graph_is_drawn_as_a_small_subgraph():
    deps = [dep("root", "1", [(f"p{i}", "1") for i in range(500)], direct=True)] + [dep(f"p{i}", "1", []) for i in range(500)]
    r = build_dependency_graph(deps).render([finding("p7", "1")])
    assert r["stats"]["packages"] == 501 and r["stats"]["shown"] == 2 and len(r["links"]) == 1


# ------------------------------------------------------------------ through the scan pipeline
def test_a_scan_attaches_the_route_to_each_vulnerable_transitive_package():
    manifest = json.dumps({"dependencies": {"app": "1.0.0"}}).encode()
    lock = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"app": "1.0.0"}},
        "node_modules/app": {"version": "1.0.0", "dependencies": {"lodash": "^4"}},
        "node_modules/lodash": {"version": "4.17.15"}}}).encode()
    res = scan_files([("package.json", manifest), ("package-lock.json", lock)], DataBundle(BENCH_SNAPSHOT))
    lod = [f for f in res["findings"] if f["package"] == "lodash"]
    assert lod and all(f["dependency_path"]["path_labels"] == ["app@1.0.0", "lodash@4.17.15"] and f["direct"] is False for f in lod)
    assert res["dependency_graph"]["stats"]["vulnerable_packages"] == 1 and res["dependency_graph"]["stats"]["links_known"] is True
    assert "Dependency path: app@1.0.0 → lodash@4.17.15" in __import__("depscan.report", fromlist=["x"]).render_markdown(res)


def test_a_manifest_alone_still_scans_and_reports_no_links():
    res = scan_files([("package.json", json.dumps({"dependencies": {"lodash": "4.17.15"}}).encode())], DataBundle(BENCH_SNAPSHOT))
    assert res["dependency_graph"]["stats"]["links_known"] is False
    assert all(f["dependency_path"]["direct"] for f in res["findings"])


def test_the_real_lock_scans_end_to_end():
    res = scan_files([("package.json", (REAL / "package.json").read_bytes()), ("package-lock.json", (REAL / "package-lock.json").read_bytes())],
                     DataBundle(BENCH_SNAPSHOT))
    stats = res["dependency_graph"]["stats"]
    assert stats["packages"] == 251 and stats["direct"] == 5 and stats["unlinked_transitive"] == 0
    json.dumps(res)                                                                 # serialisable
    nested = [f for f in res["findings"] if f["dependency_path"]["known"] and not f["dependency_path"]["direct"]]
    assert nested and all(f["dependency_path"]["path_labels"][-1] == f"{f['package']}@{f['version']}" for f in nested)
