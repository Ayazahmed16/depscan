"""The scan result must match what the frontend (frontend/src/lib/types.ts) reads.

types.ts is the contract for the web API (phase 9). This test parses it and checks real scan output against
it, so a renamed or missing field is caught here and not as a blank screen in the UI.
"""
import re
from pathlib import Path

import pytest

from depscan.pipeline import DataBundle, scan_files

TYPES = (Path(__file__).resolve().parent.parent / "frontend" / "src" / "lib" / "types.ts").read_text("utf-8")
SAMPLE = Path(__file__).parent / "sample"


def interface_fields(name: str) -> dict[str, bool]:
    """{field name: required?} for `export interface <name> { ... }` (top level fields only)."""
    body = re.search(rf"export interface {name} \{{\n(.*?)\n\}}", TYPES, re.S).group(1)
    return {m.group(1): m.group(2) != "?" for m in re.finditer(r"^  (\w+)(\??):", body, re.M)}


@pytest.fixture(scope="module")
def result():
    return scan_files([("requirements.txt", (SAMPLE / "requirements.txt").read_bytes())], DataBundle(SAMPLE / "snapshot"))


def check(obj: dict, interface: str, where: str):
    missing = [k for k, required in interface_fields(interface).items() if required and k not in obj]
    assert not missing, f"{where} is missing {missing} required by `interface {interface}` in types.ts"


def test_scan_result_has_the_fields_the_frontend_reads(result):
    check(result, "ScanResult", "scan result")


def test_every_finding_matches_the_finding_interface(result):
    for f in result["findings"]:
        check(f, "Finding", f"finding {f['id']}")


def test_nested_objects_match_their_interfaces(result):
    f = result["findings"][0]
    for factor in f["risk"]["factors"]:
        check(factor, "RiskFactor", "risk factor")
    for signal in f["trust"]["signals"]:
        check(signal, "TrustSignal", "trust signal")
    assert all(isinstance(s["value"], str) and isinstance(s["effect"], (int, float)) for s in f["trust"]["signals"])
    assert all(isinstance(r["value"], str) for r in f["risk"]["factors"])


def test_enumerated_values_are_ones_the_frontend_knows(result):
    action = set(re.search(r"export type Action = (.*)", TYPES).group(1).replace("'", "").split(" | "))
    confidence = set(re.search(r"export type MatchConfidence = (.*)", TYPES).group(1).replace("'", "").split(" | "))
    assert {f["action"] for f in result["findings"]} <= action
    assert {f["match"]["confidence"] for f in result["findings"]} <= confidence


def test_field_types_that_the_ui_formats_are_numbers_or_null(result):
    for f in result["findings"]:
        assert f["cvss"] is None or isinstance(f["cvss"], float)
        assert f["epss"] is None or isinstance(f["epss"], float)
        assert isinstance(f["risk"]["score"], float) and isinstance(f["trust"]["score"], float)
        assert isinstance(f["direct"], bool) and f["scope"] in ("runtime", "dev")


def test_the_parser_itself_works():
    fields = interface_fields("Finding")
    assert fields["trust"] and fields["id"] and fields["claim_status"] is False   # claim_status is optional in types.ts


def test_audit_entries_match_the_audit_entry_interface(tmp_path):
    import datetime as dt

    from depscan.review import ReviewStore
    from depscan.scoring.config import load_config
    cfg, now = load_config(), dt.datetime(2030, 3, 1, 12, tzinfo=dt.UTC)
    store = ReviewStore(tmp_path / "r.sqlite")
    store.record("p", "k1", "accept_risk", "a perfectly good reason", "Ana", "2030-03-20", cfg=cfg, now=now)
    store.record("p", "k2", "fix_now", "scheduling the upgrade now", "Ana", None, cfg=cfg, now=now)
    store.revoke("p", "k2", "plans changed, review again", "Ben", cfg=cfg, now=now)
    store.sweep_expired("p", now=dt.datetime(2030, 4, 1, tzinfo=dt.UTC))
    entries = store.audit("p")
    assert {e["action"] for e in entries} == {"accept_risk", "fix_now", "revoked", "expired"}
    audit_block = re.search(r"export interface AuditEntry \{(.*?)\n\}", TYPES, re.S).group(1)       # not Finding's own `action`
    known = set(re.search(r"action: (.*)", audit_block).group(1).replace("ReviewDecision", "fix_now|accept_risk|false_positive").replace("'", "").replace(" ", "").split("|"))
    assert known == {"fix_now", "accept_risk", "false_positive", "revoked", "expired"}
    for e in entries:
        check(e, "AuditEntry", f"audit entry {e['id']}")
        assert e["action"] in known


def test_findings_carry_the_review_fields_the_frontend_needs(result):
    for f in result["findings"]:
        assert f["key"].count("|") == 3 and f["review_status"] == "pending" and f["review"] is None
    status = set(re.search(r"export type ReviewStatus = (.*)", TYPES).group(1).replace("ReviewDecision", "fix_now|accept_risk|false_positive").replace("'", "").replace(" ", "").split("|"))
    from depscan.pipeline import REVIEW_STATUSES
    assert set(REVIEW_STATUSES) == status                                  # backend and frontend agree on every status
    assert set(result["review_summary"]) == status | {"needs_review"}


def test_history_points_and_advisories_match_their_interfaces(result):
    seen = 0
    for f in result["findings"]:
        for point in f["history"]:
            check(point, "HistoryPoint", f"history point of {f['id']}")
            seen += 1
        for adv in f["advisories"]:
            check(adv, "Advisory", f"advisory {adv['id']}")
            assert all(set(link) == {"label", "url"} for link in adv["links"])
    assert seen > 0


def test_weights_view_matches_its_interface(tmp_path):
    from fastapi.testclient import TestClient

    from depscan.server import create_app
    c = TestClient(create_app(SAMPLE / "snapshot", tmp_path / "r.sqlite", dist=tmp_path / "none"))
    required = {k for k, req in interface_fields("WeightsView").items() if req}
    assert required <= set(c.get("/api/config/weights").json())
    health = c.get("/api/health").json()
    assert set(interface_fields("Health")) <= set(health)


def test_dependency_paths_and_graph_match_their_interfaces(result):
    for f in result["findings"]:
        check(f["dependency_path"], "DependencyPath", f"dependency path of {f['id']}")
    graph = result["dependency_graph"]
    check(graph, "DependencyGraph", "dependency graph")
    assert graph["nodes"]
    for node in graph["nodes"]:
        check(node, "DepNode", f"dependency node {node['id']}")
        assert node["kind"] in ("direct", "transitive", "vulnerable") and node["scope"] in ("runtime", "dev")
    stats = interface_fields("DependencyGraph")
    assert "stats" in stats and "limitation" in stats


def test_a_transitive_finding_matches_the_dependency_path_interface():
    import json
    real = Path(__file__).parent / "fixtures" / "real-npm"
    snap = Path(__file__).resolve().parent.parent / "benchmark" / "snapshot"
    res = scan_files([("package.json", (real / "package.json").read_bytes()), ("package-lock.json", (real / "package-lock.json").read_bytes())], DataBundle(snap))
    transitive = [f for f in res["findings"] if not f["dependency_path"]["direct"]]
    assert transitive
    for f in transitive:
        check(f["dependency_path"], "DependencyPath", f"dependency path of {f['id']}")
        assert f["dependency_path"]["known"] and f["dependency_path"]["direct_parents"]
    json.dumps(res["dependency_graph"])
