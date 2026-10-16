"""Phase 2 tests: parsers read the supported formats and report what they cannot read."""
import json
from pathlib import Path

import pytest

from depscan.parsers import UnsupportedFile, parse_file
from depscan.parsers.package_json import npm_lower_bound

FIXTURES = Path(__file__).parent / "fixtures"


def test_requirements_pins_ranges_and_skips():
    text = "\n".join([
        "# comment",
        "Django==3.0  # pinned",
        "Flask_Login>=0.5,<1.0",
        "requests[security]~=2.25.1; python_version>='3.8'",
        "numpy",
        "-r other.txt",
        "git+https://example.test/x.git#egg=x",
        "PyYAML==5.3 --hash=sha256:abc",
    ])
    res = parse_file("requirements.txt", text.encode())
    by = {d.name: d for d in res.dependencies}
    assert by["django"].version == "3.0" and by["django"].exact
    assert by["flask-login"].version is None and by["flask-login"].lower_bound == "0.5"  # name normalised
    assert by["requests"].lower_bound == "2.25.1" and not by["requests"].exact
    assert by["numpy"].lower_bound is None
    assert by["pyyaml"].version == "5.3"
    joined = " ".join(res.warnings)
    assert "other.txt" in joined and "git+https" in joined and "numpy" in joined
    assert all(d.scope == "runtime" and d.ecosystem == "PyPI" for d in res.dependencies)


def test_requirements_dev_file_is_dev_scope():
    res = parse_file("requirements-dev.txt", b"pytest==8.0.0\n")
    assert res.dependencies[0].scope == "dev"


@pytest.mark.parametrize("spec,expected", [
    ("4.17.21", ("4.17.21", "4.17.21")),
    ("^4.17.0", (None, "4.17.0")),
    ("~1.2", (None, "1.2.0")),
    (">=2.0.0 <3.0.0", (None, "2.0.0")),
    ("1.x", (None, "1.0.0")),
    ("1.2.3 - 2.0.0", (None, "1.2.3")),
    ("^1.0.0 || ^2.0.0", (None, "1.0.0")),
    ("*", (None, None)),
    ("latest", (None, None)),
])
def test_npm_lower_bound(spec, expected):
    assert npm_lower_bound(spec) == expected


def test_package_json_sections_and_skips():
    doc = {"dependencies": {"lodash": "4.17.15", "express": "^4.17.0", "local": "file:../x", "fork": "user/repo"},
           "devDependencies": {"jest": "~29.0.0"}}
    res = parse_file("package.json", json.dumps(doc).encode())
    by = {d.name: d for d in res.dependencies}
    assert by["lodash"].exact and by["express"].lower_bound == "4.17.0"
    assert by["jest"].scope == "dev" and by["lodash"].scope == "runtime"
    assert "local" not in by and "fork" not in by
    assert any("lock" in w for w in res.warnings)  # tells the user a lock file would be better


def test_package_lock_gives_exact_and_transitive():
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"a": "^1.0.0"}, "devDependencies": {"t": "^2.0.0"}},
        "node_modules/a": {"version": "1.2.3"},
        "node_modules/a/node_modules/b": {"version": "0.1.0"},
        "node_modules/t": {"version": "2.0.1", "dev": True},
    }}
    res = parse_file("package-lock.json", json.dumps(lock).encode())
    by = {d.name: d for d in res.dependencies}
    assert by["a"].direct and by["a"].exact and by["a"].scope == "runtime"
    assert not by["b"].direct and by["b"].version == "0.1.0"
    assert by["t"].direct and by["t"].scope == "dev"


def test_depcheck_sample_extracts_claims_and_skips_non_pypi_npm():
    res = parse_file("report.json", (FIXTURES / "depcheck-sample.json").read_bytes())
    by = {d.name: d for d in res.dependencies}
    assert set(by) == {"django", "requests"}  # the maven jar is skipped
    assert by["django"].version == "3.0"
    assert [c.cve for c in by["django"].claims] == ["CVE-2020-7471", "CVE-2999-0001"]
    assert by["django"].claims[0].cvss == 9.8
    assert any("somelib" in w for w in res.warnings)


def test_unsupported_and_bad_input_raise_clear_errors():
    with pytest.raises(UnsupportedFile):
        parse_file("notes.docx", b"x")
    with pytest.raises(UnsupportedFile, match="not valid JSON"):
        parse_file("package.json", b"{nope")
    with pytest.raises(UnsupportedFile):
        parse_file("thing.json", b"[1,2]")
