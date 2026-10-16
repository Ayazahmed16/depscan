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
