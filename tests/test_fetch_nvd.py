"""NVD yearly-feed download: checksum verification, filtering, incremental refresh (all HTTP mocked)."""
import datetime as dt
import gzip
import hashlib
import importlib.util
import json
import urllib.error
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "fetch_data.py"
spec = importlib.util.spec_from_file_location("fetch_data", SCRIPT)
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)

THIS_YEAR = dt.date.today().year


def cve(id, score, status="Analyzed"):
    return {"cve": {"id": id, "published": "2026-01-01T00:00:00.000", "lastModified": "2026-02-01T00:00:00.000",
                    "vulnStatus": status, "cveTags": [],
                    "metrics": {"cvssMetricV31": [{"type": "Primary", "source": "nvd@nist.gov",
                                                   "cvssData": {"baseScore": score, "vectorString": "CVSS:3.1/AV:N"}}]}}}


def feed_bytes(*items):
    raw = json.dumps({"resultsPerPage": len(items), "totalResults": len(items), "format": "NVD_CVE",
                      "version": "2.0", "vulnerabilities": list(items)}).encode()
    return raw, gzip.compress(raw)


class FakeNvd:
    """Serves the 2026 feed (and its .meta); every other year answers 404 like a year with no feed."""
    def __init__(self, items, lie_about_sha=False, modified="2026-10-16T03:04:33-04:00"):
        raw, self.gz = feed_bytes(*items)
        sha = "0" * 64 if lie_about_sha else hashlib.sha256(raw).hexdigest().upper()
        self.meta = f"lastModifiedDate:{modified}\nsize:{len(raw)}\nzipSize:{len(self.gz)}\ngzSize:{len(self.gz)}\nsha256:{sha}\n"
        self.feed_downloads = 0

    def __call__(self, url, **kw):
        year = int(url.rsplit("-", 1)[1].split(".")[0])
        if year != THIS_YEAR:
            raise urllib.error.HTTPError(url, 404, "nf", {}, None)
        if url.endswith(".meta"):
            return self.meta.encode()
        self.feed_downloads += 1
        return self.gz


def run(data_dir, net, monkeypatch, force=False):
    monkeypatch.setattr(fetch, "http_get", net)
    manifest = fetch.Manifest(data_dir)
    fetch.fetch_nvd_feeds(data_dir, ["PyPI"], manifest, force)
    return json.loads((data_dir / "nvd.json").read_text())


def test_cve_tags_are_flattened_to_plain_tag_names():
    raw = cve("CVE-2030-0001", 5.0, status="Rejected")["cve"]
    raw["cveTags"] = [{"sourceIdentifier": "a@b", "tags": ["disputed"]}, {"sourceIdentifier": "c@d", "tags": ["disputed", "unsupported-when-assigned"]}]
    rec = fetch.compact_nvd(raw)
    assert rec["tags"] == ["disputed", "unsupported-when-assigned"] and rec["vulnStatus"] == "Rejected"


def test_parse_meta():
    assert fetch.parse_meta("lastModifiedDate:2026-10-16T03:04:33-04:00\nsha256:ABC\n") == {
        "lastModifiedDate": "2026-10-16T03:04:33-04:00", "sha256": "ABC"}


def test_keeps_only_wanted_cves_and_reports_absent_ones(data_dir, monkeypatch):
    net = FakeNvd([cve("CVE-2030-0001", 9.8), cve("CVE-9999-0001", 5.0)])   # second one is not in any OSV record
    out = run(data_dir, net, monkeypatch)
    assert set(out["records"]) == {"CVE-2030-0001"}
    rec = out["records"]["CVE-2030-0001"]
    assert rec["cvss"]["v31"]["score"] == 9.8 and rec["vulnStatus"] == "Analyzed"      # float, not Decimal
    manifest = json.loads((data_dir / "manifest.json").read_text())["nvd"]
    assert manifest["wanted_not_in_nvd"] == 3 and manifest["method"] == "yearly feeds"  # 0002, 0004, 0005 not in the feed
    assert not list((data_dir / "nvd").glob("*.gz"))                                    # raw feed removed after extraction


def test_checksum_mismatch_discards_the_year(data_dir, monkeypatch):
    net = FakeNvd([cve("CVE-2030-0001", 9.8)], lie_about_sha=True)
    with pytest.raises(RuntimeError, match="NVD years failed"):
        run(data_dir, net, monkeypatch)
    out = json.loads((data_dir / "nvd.json").read_text())
    assert out["records"] == {}                                                          # nothing unverified was kept
    assert not (data_dir / "nvd" / f"{THIS_YEAR}.json").exists()


def test_second_run_downloads_nothing_when_unchanged(data_dir, monkeypatch):
    net = FakeNvd([cve("CVE-2030-0001", 9.8)])
    run(data_dir, net, monkeypatch)
    assert net.feed_downloads == 1
    run(data_dir, net, monkeypatch)
    assert net.feed_downloads == 1                                                       # only the tiny .meta files were fetched


def test_changed_meta_triggers_a_redownload_and_force_always_does(data_dir, monkeypatch):
    run(data_dir, FakeNvd([cve("CVE-2030-0001", 9.8)]), monkeypatch)
    newer = FakeNvd([cve("CVE-2030-0001", 7.0)], modified="2026-10-17T03:00:00-04:00")
    out = run(data_dir, newer, monkeypatch)
    assert newer.feed_downloads == 1 and out["records"]["CVE-2030-0001"]["cvss"]["v31"]["score"] == 7.0
    assert run(data_dir, newer, monkeypatch, force=True) and newer.feed_downloads == 2


def test_nvd_data_reaches_the_risk_score(data_dir, monkeypatch):
    """End to end: the downloaded NVD score is preferred over the OSV vector (here deliberately different)."""
    run(data_dir, FakeNvd([cve("CVE-2030-0001", 4.0)]), monkeypatch)
    from depscan.pipeline import DataBundle, scan_files
    r = scan_files([("requirements.txt", b"alpha==1.0\n")], DataBundle(data_dir))
    assert r["findings"][0]["cvss"] == 4.0                                               # OSV's own vector says 9.8
