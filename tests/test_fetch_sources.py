"""scripts/fetch_data.py: the OSV, KEV and EPSS downloads, retries, integrity checks and the NVD API fallback.

All HTTP is mocked. The point is the failure handling: a bad download must never replace a good snapshot,
and one failing source must not stop the others.
"""
import base64
import gzip
import hashlib
import importlib.util
import io
import json
import urllib.error
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "fetch_data.py"


@pytest.fixture()
def fetch(monkeypatch):
    spec = importlib.util.spec_from_file_location("fetch_data_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)  # never actually wait in tests
    return mod


def md5_b64(body: bytes) -> str:
    return base64.b64encode(hashlib.md5(body).digest()).decode()


def osv_zip(*records) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for r in records:
            z.writestr(f"{r['id']}.json", json.dumps(r))
    return buf.getvalue()


ADV = {"id": "PYSEC-1", "aliases": ["CVE-2030-0001"], "modified": "2030-05-06T00:00:00Z",
       "affected": [{"package": {"ecosystem": "PyPI", "name": "alpha"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.5"}]}]}]}


def serve(monkeypatch, fetch, body, headers=None):
    monkeypatch.setattr(fetch, "http_fetch", lambda url, **kw: (body, headers or {}))


# ---------------------------------------------------------------- http_fetch / retries
class FakeResponse:
    def __init__(self, body, headers):
        self._body, self.headers = body, headers

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeHeaders:
    def __init__(self, pairs):
        self.pairs = pairs

    def items(self):
        return self.pairs


def test_http_fetch_retries_then_succeeds_and_joins_repeated_headers(fetch, monkeypatch):
    calls = []

    def urlopen(req, timeout):
        calls.append(1)
        if len(calls) < 3:
            raise urllib.error.URLError("flaky")
        return FakeResponse(b"ok", FakeHeaders([("X-Goog-Hash", "crc32c=aa"), ("x-goog-hash", "md5=bb"), ("Content-Type", "x")]))

    monkeypatch.setattr(fetch.urllib.request, "urlopen", urlopen)
    body, hdrs = fetch.http_fetch("https://example.test/x")
    assert body == b"ok" and len(calls) == 3
    assert hdrs["x-goog-hash"] == "crc32c=aa,md5=bb"                      # both header lines kept, keys lower-cased


def test_http_404_is_raised_immediately_not_retried(fetch, monkeypatch):
    calls = []

    def urlopen(req, timeout):
        calls.append(1)
        raise urllib.error.HTTPError("u", 404, "nf", {}, None)

    monkeypatch.setattr(fetch.urllib.request, "urlopen", urlopen)
    with pytest.raises(urllib.error.HTTPError):
        fetch.http_get("https://example.test/x")
    assert len(calls) == 1


def test_http_gives_up_with_a_clear_error_and_retries_rate_limits(fetch, monkeypatch):
    calls = []

    def urlopen(req, timeout):
        calls.append(1)
        raise urllib.error.HTTPError("u", 429, "slow down", {}, None)

    monkeypatch.setattr(fetch.urllib.request, "urlopen", urlopen)
    with pytest.raises(RuntimeError, match="giving up on https://example.test/x"):
        fetch.http_get("https://example.test/x", retries=3)
    assert len(calls) == 3


def test_write_atomic_replaces_and_leaves_no_part_file(fetch, tmp_path):
    p = tmp_path / "sub" / "f.bin"
    fetch.write_atomic(p, b"one")
    fetch.write_atomic(p, b"two")
    assert p.read_bytes() == b"two" and not list(p.parent.glob("*.part"))


# ---------------------------------------------------------------- OSV
def test_osv_download_verifies_md5_builds_index_and_records_manifest(fetch, monkeypatch, tmp_path):
    body = osv_zip(ADV)
    serve(monkeypatch, fetch, body, {"x-goog-hash": f"crc32c=zzz, md5={md5_b64(body)}"})
    manifest = fetch.Manifest(tmp_path)
    fetch.fetch_osv(tmp_path, ["PyPI"], manifest)
    assert (tmp_path / "osv" / "PyPI.zip").read_bytes() == body
    idx = json.loads((tmp_path / "osv" / "PyPI.index.json").read_text())["packages"]
    assert idx["alpha"][0]["id"] == "PYSEC-1"
    rec = json.loads((tmp_path / "manifest.json").read_text())["osv:PyPI"]
    assert rec["advisories"] == 1 and rec["snapshot_date"] == "2030-05-06" and len(rec["sha256"]) == 64


def test_osv_checksum_mismatch_raises_and_keeps_the_old_snapshot(fetch, monkeypatch, tmp_path):
    (tmp_path / "osv").mkdir()
    (tmp_path / "osv" / "PyPI.zip").write_bytes(b"GOOD OLD SNAPSHOT")
    serve(monkeypatch, fetch, osv_zip(ADV), {"x-goog-hash": "md5=AAAAAAAAAAAAAAAAAAAAAA=="})
    with pytest.raises(RuntimeError, match="checksum mismatch"):
        fetch.fetch_osv(tmp_path, ["PyPI"], fetch.Manifest(tmp_path))
    assert (tmp_path / "osv" / "PyPI.zip").read_bytes() == b"GOOD OLD SNAPSHOT"


def test_osv_without_a_published_checksum_still_checks_the_zip(fetch, monkeypatch, tmp_path, capsys):
    serve(monkeypatch, fetch, osv_zip(ADV), {})
    fetch.fetch_osv(tmp_path, ["PyPI"], fetch.Manifest(tmp_path))
    assert "no checksum published" in capsys.readouterr().out


@pytest.mark.parametrize("body", [b"<html>error page</html>", osv_zip()])
def test_osv_rejects_non_zip_and_empty_zip(fetch, monkeypatch, tmp_path, body):
    serve(monkeypatch, fetch, body, {})
    with pytest.raises(RuntimeError, match="not a valid, non-empty zip"):
        fetch.fetch_osv(tmp_path, ["PyPI"], fetch.Manifest(tmp_path))
    assert not (tmp_path / "osv" / "PyPI.zip").exists()


# ---------------------------------------------------------------- KEV
KEV_DOC = {"dateReleased": "2030-02-03T10:00:00Z", "catalogVersion": "2030.02.03",
           "vulnerabilities": [{"cveID": "CVE-2030-0001", "dateAdded": "2030-02-01"}]}


def test_kev_download_validates_writes_and_records(fetch, monkeypatch, tmp_path):
    serve(monkeypatch, fetch, json.dumps(KEV_DOC).encode())
    fetch.fetch_kev(tmp_path, fetch.Manifest(tmp_path))
    assert json.loads((tmp_path / "kev.json").read_text())["vulnerabilities"][0]["cveID"] == "CVE-2030-0001"
    rec = json.loads((tmp_path / "manifest.json").read_text())["kev"]
    assert rec["snapshot_date"] == "2030-02-03" and rec["count"] == 1 and rec["catalogVersion"] == "2030.02.03"


@pytest.mark.parametrize("doc", [
    {"vulnerabilities": []},                                   # empty
    {"something": "else"},                                     # wrong shape
    {"vulnerabilities": [{"name": "no id or date"}]},          # entries missing the fields we rely on
    [1, 2, 3],                                                 # not an object
])
def test_kev_bad_formats_raise_and_keep_the_old_file(fetch, monkeypatch, tmp_path, doc):
    (tmp_path / "kev.json").write_text("OLD")
    serve(monkeypatch, fetch, json.dumps(doc).encode())
    with pytest.raises(RuntimeError, match="unexpected format"):
        fetch.fetch_kev(tmp_path, fetch.Manifest(tmp_path))
    assert (tmp_path / "kev.json").read_text() == "OLD"


# ---------------------------------------------------------------- EPSS
def epss_gz(score_date="2030-03-01", rows=1500, columns="cve,epss,percentile") -> bytes:
    body = "".join(f"CVE-2030-{i:04d},0.5,0.9\n" for i in range(rows))
    return gzip.compress(f"#model_version:v1,score_date:{score_date}T00:00:00Z\n{columns}\n{body}".encode())


def test_epss_current_plus_history_skips_bad_and_missing_dates(fetch, monkeypatch, tmp_path):
    import datetime as dt
    today = dt.date.today()
    d30, d90, d180 = (str(today - dt.timedelta(days=n)) for n in (30, 90, 180))

    def get(url, **kw):
        tag = url.rsplit("epss_scores-", 1)[1].removesuffix(".csv.gz")
        if tag == "current":
            return epss_gz("2030-03-01")
        if tag == d30:
            return epss_gz(d30)
        if tag == d90:
            raise urllib.error.HTTPError(url, 404, "nf", {}, None)     # a date NIST-style feeds do not have
        return epss_gz(d180, columns="wrong,header")                    # corrupt file

    monkeypatch.setattr(fetch, "http_get", get)
    fetch.fetch_epss(tmp_path, fetch.Manifest(tmp_path), [30, 90, 180])
    names = sorted(p.name for p in (tmp_path / "epss").glob("*.csv.gz"))
    assert names == sorted([f"epss_{d30}.csv.gz", "epss_2030-03-01.csv.gz"])
    m = json.loads((tmp_path / "manifest.json").read_text())
    assert m["epss"]["snapshot_date"] == "2030-03-01" and f"epss:{d30}" in m and f"epss:{d90}" not in m and f"epss:{d180}" not in m


def test_epss_current_must_be_valid_or_the_step_fails(fetch, monkeypatch, tmp_path):
    monkeypatch.setattr(fetch, "http_get", lambda url, **kw: epss_gz(rows=10))   # far too few rows
    with pytest.raises(ValueError, match="not an EPSS score file"):
        fetch.fetch_epss(tmp_path, fetch.Manifest(tmp_path), [])
    assert not list((tmp_path / "epss").glob("*.csv.gz"))


def test_epss_files_load_back_through_the_real_loader(fetch, monkeypatch, tmp_path):
    from depscan.data.feeds import load_epss
    monkeypatch.setattr(fetch, "http_get", lambda url, **kw: epss_gz("2030-03-01"))
    fetch.fetch_epss(tmp_path, fetch.Manifest(tmp_path), [])
    date, scores = load_epss(tmp_path)
    assert date == "2030-03-01" and scores["CVE-2030-0007"] == (0.5, 0.9)


# ---------------------------------------------------------------- main(): one failing source must not stop the rest
def test_main_continues_after_a_failure_and_reports_it(fetch, monkeypatch, tmp_path, capsys):
    ran = []
    monkeypatch.setattr(fetch, "fetch_kev", lambda *a: (_ for _ in ()).throw(RuntimeError("kev is down")))
    monkeypatch.setattr(fetch, "fetch_epss", lambda *a: ran.append("epss"))
    monkeypatch.setattr(fetch.sys, "argv", ["fetch_data.py", "--data-dir", str(tmp_path), "--only", "kev", "epss"])
    assert fetch.main() == 1
    out = capsys.readouterr().out
    assert ran == ["epss"] and "[kev] FAILED: kev is down" in out and "done with failures: kev" in out


def test_main_returns_zero_when_everything_works(fetch, monkeypatch, tmp_path):
    monkeypatch.setattr(fetch, "fetch_kev", lambda *a: None)
    monkeypatch.setattr(fetch.sys, "argv", ["fetch_data.py", "--data-dir", str(tmp_path), "--only", "kev"])
    assert fetch.main() == 0


# ---------------------------------------------------------------- NVD API fallback (slow path)
def api_cve(id, score):
    return {"cve": {"id": id, "published": "x", "lastModified": "y", "vulnStatus": "Analyzed", "cveTags": [],
                    "metrics": {"cvssMetricV31": [{"type": "Primary", "source": "nvd", "cvssData": {"baseScore": score, "vectorString": "V"}}]}}}


def test_nvd_api_pages_filters_and_cleans_up_its_checkpoint(fetch, monkeypatch, data_dir):
    seen = []
    pages = {0: {"totalResults": 3, "resultsPerPage": 2, "timestamp": "2030-03-02T00:00:00",
                 "vulnerabilities": [api_cve("CVE-2030-0001", 9.8), api_cve("CVE-9999-0001", 1.0)]},
             2: {"totalResults": 3, "resultsPerPage": 1, "timestamp": "2030-03-02T00:00:00",
                 "vulnerabilities": [api_cve("CVE-2030-0002", 5.3)]}}

    def get(url, **kw):
        start = int(url.split("startIndex=")[1])
        seen.append((start, (kw.get("headers") or {}).get("apiKey")))
        return json.dumps(pages[start]).encode()

    monkeypatch.setattr(fetch, "http_get", get)
    monkeypatch.setenv("NVD_API_KEY", "secret")
    fetch.fetch_nvd_api(data_dir, ["PyPI"], fetch.Manifest(data_dir), resume=False)
    assert [s for s, _ in seen] == [0, 2] and all(k == "secret" for _, k in seen)   # paged, key sent as a header
    out = json.loads((data_dir / "nvd.json").read_text())
    assert set(out["records"]) == {"CVE-2030-0001", "CVE-2030-0002"}                   # unwanted CVE dropped
    assert not (data_dir / "nvd.partial.json").exists()


def test_nvd_api_resumes_from_a_checkpoint(fetch, monkeypatch, data_dir):
    (data_dir / "nvd.partial.json").write_text(json.dumps({"kept": {"CVE-2030-0001": {"id": "CVE-2030-0001"}}, "next_index": 2}))
    starts = []

    def get(url, **kw):
        starts.append(int(url.split("startIndex=")[1]))
        return json.dumps({"totalResults": 3, "resultsPerPage": 1, "timestamp": "t", "vulnerabilities": [api_cve("CVE-2030-0002", 5.0)]}).encode()

    monkeypatch.setattr(fetch, "http_get", get)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    fetch.fetch_nvd_api(data_dir, ["PyPI"], fetch.Manifest(data_dir), resume=True)
    assert starts == [2]                                                               # did not start over
    assert set(json.loads((data_dir / "nvd.json").read_text())["records"]) == {"CVE-2030-0001", "CVE-2030-0002"}


def test_nvd_steps_do_nothing_without_an_osv_index(fetch, tmp_path, capsys):
    fetch.fetch_nvd_api(tmp_path, ["PyPI"], fetch.Manifest(tmp_path), resume=False)
    fetch.fetch_nvd_feeds(tmp_path, ["PyPI"], fetch.Manifest(tmp_path), False)
    assert capsys.readouterr().out.count("run the osv step first") == 2
    assert not (tmp_path / "nvd.json").exists()


def test_wanted_cves_collects_ids_and_aliases(fetch, data_dir):
    assert fetch.wanted_cves(data_dir, ["PyPI"]) >= {"CVE-2030-0001", "CVE-2030-0002", "CVE-2030-0005"}
