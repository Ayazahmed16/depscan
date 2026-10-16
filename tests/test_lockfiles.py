"""Step 1 tests: lock files and exact pins give `confirmed` matches and beat manifest ranges."""
import json

from depscan.parsers import combine, parse_file, parse_files
from depscan.pipeline import DataBundle, collect_files, scan_files

YARN_V1 = '''# yarn lockfile v1

"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.12.3"
  resolved "https://example.test/core.tgz"

lodash@^4.17.0:
  version "4.17.21"

left-pad@1.3.0, left-pad@^1.0.0:
  version "1.3.0"
'''

YARN_BERRY = '''__metadata:
  version: 6

"lodash@npm:^4.17.0":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"app@workspace:.":
  version: 0.0.0-use.local
'''

POETRY = '''[[package]]
name = "Alpha_Pkg"
version = "1.0.0"
category = "main"

[[package]]
name = "pytest"
version = "8.0.0"
category = "dev"

[[package]]
name = "newer-dev"
version = "2.0.0"
groups = ["dev"]
'''

PIPFILE_LOCK = {"default": {"alpha": {"version": "==1.0"}, "gitdep": {"git": "https://example.test/x.git"}},
                "develop": {"pytest": {"version": "==8.0.0"}}}


def test_yarn_lock_v1_and_berry():
    v1 = {(d.name, d.version) for d in parse_file("yarn.lock", YARN_V1.encode()).dependencies}
    assert v1 == {("@babel/core", "7.12.3"), ("lodash", "4.17.21"), ("left-pad", "1.3.0")}
    berry = {(d.name, d.version) for d in parse_file("yarn.lock", YARN_BERRY.encode()).dependencies}
    assert berry == {("lodash", "4.17.21")}  # the workspace entry has no registry version
    assert all(d.exact and d.resolution == "lockfile" for d in parse_file("yarn.lock", YARN_V1.encode()).dependencies)


def test_poetry_lock_names_versions_and_dev_scope():
    by = {d.name: d for d in parse_file("poetry.lock", POETRY.encode()).dependencies}
    assert by["alpha-pkg"].version == "1.0.0" and by["alpha-pkg"].scope == "runtime"  # name normalised
    assert by["pytest"].scope == "dev" and by["newer-dev"].scope == "dev"


def test_pipfile_lock_runtime_dev_and_skips_unversioned():
    res = parse_file("Pipfile.lock", json.dumps(PIPFILE_LOCK).encode())
    by = {d.name: d for d in res.dependencies}
    assert by["alpha"].version == "1.0" and by["pytest"].scope == "dev" and "gitdep" not in by
    assert any("gitdep" in w for w in res.warnings)


def test_combine_lock_wins_over_range_and_manifest_gives_directness():
    reqs = parse_file("requirements.txt", b"alpha>=0.5\nbeta>=1.0\n")
    lock = parse_file("Pipfile.lock", json.dumps({"default": {"alpha": {"version": "==1.0"}, "transitive": {"version": "==3.1"}}}).encode())
    out = combine([reqs, lock])
    by = {d.name: d for d in out.dependencies}
    assert by["alpha"].version == "1.0" and by["alpha"].direct and by["alpha"].spec == ">=0.5"
    assert by["transitive"].direct is False                      # in the lock, not in the manifest
    assert by["beta"].version is None                            # manifest-only stays a range...
    assert any("beta is in the manifest but not in the lock file" in w for w in out.warnings)  # ...and says so


def test_package_json_plus_package_lock_gives_exact_versions():
    pkg = json.dumps({"dependencies": {"a": "^1.0.0"}}).encode()
    lock = json.dumps({"lockfileVersion": 3, "packages": {"": {"dependencies": {"a": "^1.0.0"}},
                                                          "node_modules/a": {"version": "1.4.2"}}}).encode()
    out = parse_files([("package.json", pkg), ("package-lock.json", lock)])
    [a] = out.dependencies
    assert a.version == "1.4.2" and a.resolution == "lockfile" and a.direct
    assert not any("upload package-lock.json" in w for w in out.warnings)  # the hint is moot now


# ---------------------------------------------------------------- end to end (synthetic advisories: alpha < 1.5 is vulnerable)
def scan(data_dir, files):
    return scan_files(files, DataBundle(data_dir))


def test_exact_pin_in_requirements_is_confirmed(data_dir):
    [f] = [x for x in scan(data_dir, [("requirements.txt", b"alpha==1.0\n")])["findings"]]
    assert f["match"]["confidence"] == "confirmed"
    assert any("pinned exactly in requirements.txt" in e for e in f["match"]["evidence"])


def test_lockfile_version_is_confirmed_and_says_where_it_came_from(data_dir):
    lock = json.dumps({"default": {"alpha": {"version": "==1.0"}}}).encode()
    r = scan(data_dir, [("requirements.txt", b"alpha>=0.5\n"), ("Pipfile.lock", lock)])
    [f] = r["findings"]
    assert f["match"]["confidence"] == "confirmed" and f["version"] == "1.0"
    assert any("locked in Pipfile.lock" in e for e in f["match"]["evidence"])


def test_lockfile_that_is_already_patched_removes_a_range_based_finding(data_dir):
    # Range alone would flag alpha (lowest allowed 0.5 is affected). The lock says 1.7 is installed: not affected.
    lock = json.dumps({"default": {"alpha": {"version": "==1.7"}}}).encode()
    assert scan(data_dir, [("requirements.txt", b"alpha>=0.5\n")])["findings"]
    assert scan(data_dir, [("requirements.txt", b"alpha>=0.5\n"), ("Pipfile.lock", lock)])["findings"] == []


def test_cli_finds_a_lock_file_next_to_the_manifest(data_dir, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("alpha>=0.5\n")
    (proj / "Pipfile.lock").write_text(json.dumps({"default": {"alpha": {"version": "==1.0"}}}))
    names = [n for n, _ in collect_files([proj / "requirements.txt"])]
    assert names == ["requirements.txt", "Pipfile.lock"]
    assert [n for n, _ in collect_files([proj])] == ["requirements.txt", "Pipfile.lock"]  # folder form, no duplicates
