"""Phase 1 tests: loaders work on tiny synthetic files, plus a smoke test on the real cache if present."""
import gzip
import json
import time
import zipfile
from pathlib import Path

import pytest

from depscan.data.feeds import load_epss, load_kev, load_nvd, read_epss_file, snapshot_dates
from depscan.data.osv import build_osv_index, load_osv_index, normalize_name

REAL_DATA = Path(__file__).resolve().parent.parent / "data"


def make_osv_zip(path: Path) -> None:
    advisories = {
        "PYSEC-1.json": {
            "id": "PYSEC-1", "aliases": ["CVE-2020-0001"], "summary": "bad thing",
            "published": "2020-01-01T00:00:00Z", "modified": "2020-06-01T00:00:00Z",
            "references": [{"type": "FIX", "url": "https://example.test/fix"}, {"type": "WEB", "url": "https://example.test/web"}],
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "Some_Pkg"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}],
                "versions": ["1.0", "1.1"],
            }],
        },
        "PYSEC-2.json": {
            "id": "PYSEC-2", "withdrawn": "2021-01-01T00:00:00Z", "modified": "2021-01-01T00:00:00Z",
            "affected": [{"package": {"ecosystem": "npm", "name": "other"}, "ranges": []}],
        },
    }
    with zipfile.ZipFile(path, "w") as z:
        for name, doc in advisories.items():
            z.writestr(name, json.dumps(doc))


def test_normalize_name_pypi_vs_npm():
    assert normalize_name("PyPI", "Some_Pkg.Name") == "some-pkg-name"
    assert normalize_name("npm", "@Scope/Pkg") == "@scope/pkg"


def test_build_and_load_osv_index_keeps_only_requested_ecosystem(tmp_path):
    zpath = tmp_path / "PyPI.zip"
    make_osv_zip(zpath)
    out = tmp_path / "osv"
    out.mkdir()
    n, pkgs, newest = build_osv_index(zpath, out / "PyPI.index.json", "PyPI")
    assert (n, pkgs) == (2, 1)  # both records read, only one is a PyPI package
    assert newest == "2021-01-01T00:00:00Z"
    index = load_osv_index(tmp_path, "PyPI")
    adv = index["some-pkg"][0]
    assert adv["id"] == "PYSEC-1" and adv["aliases"] == ["CVE-2020-0001"]
    assert adv["fix_refs"] == ["https://example.test/fix"]  # only FIX-typed references
    assert adv["affected"][0]["ranges"][0]["events"][1] == {"fixed": "1.2.0"}


def test_missing_snapshots_raise_a_helpful_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="fetch_data.py"):
        load_kev(tmp_path)
    with pytest.raises(FileNotFoundError, match="fetch_data.py"):
        load_osv_index(tmp_path, "PyPI")
    assert load_nvd(tmp_path) == {}  # NVD is optional: callers handle empty
    assert snapshot_dates(tmp_path) == {"osv": None, "nvd": None, "kev": None, "epss": None}


def test_kev_and_epss_parsing(tmp_path):
    (tmp_path / "kev.json").write_text(json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2021-0001", "dateAdded": "2022-01-02", "dueDate": "2022-01-23", "knownRansomwareCampaignUse": "Known"}]}))
    assert load_kev(tmp_path)["CVE-2021-0001"]["dateAdded"] == "2022-01-02"

    (tmp_path / "epss").mkdir()
    csv_text = "#model_version:v1,score_date:2026-01-05T12:00:00Z\ncve,epss,percentile\nCVE-2021-0001,0.5,0.9\n"
    f = tmp_path / "epss" / "epss_2026-01-05.csv.gz"
    f.write_bytes(gzip.compress(csv_text.encode()))
    assert read_epss_file(f) == ("2026-01-05", {"CVE-2021-0001": (0.5, 0.9)})
    assert load_epss(tmp_path)[0] == "2026-01-05"


@pytest.mark.skipif(not (REAL_DATA / "osv" / "PyPI.index.json").exists(), reason="run scripts/fetch_data.py first")
def test_real_cache_smoke():
    """Not a correctness proof, just 'the real downloads load and look sane'."""
    start = time.time()
    pypi = load_osv_index(REAL_DATA, "PyPI")
    assert "django" in pypi and len(pypi["django"]) > 10
    sample = pypi["django"][0]
    assert sample["id"] and sample["affected"]
    kev = load_kev(REAL_DATA)
    assert len(kev) > 1000 and all(v["dateAdded"] for v in list(kev.values())[:50])
    date, epss = load_epss(REAL_DATA)
    assert date and len(epss) > 100_000
    print(f"real cache loaded in {time.time() - start:.1f}s")
