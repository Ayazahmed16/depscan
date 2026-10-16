"""Shared fixture: a tiny synthetic data directory with known answers (no network, no real data)."""
import gzip
import json
import zipfile

import pytest

from depscan.data.osv import build_osv_index

# The fixture Django app is read by the exposure analysis, never run: do not let pytest collect or import its files.
collect_ignore_glob = ["sample/django_app/*"]


def _adv(id, aliases, pkg, events, **extra):
    return {"id": id, "aliases": aliases, "summary": f"{id} summary", "modified": "2025-01-01T00:00:00Z",
            "published": "2024-01-01T00:00:00Z",
            "severity": extra.pop("severity", []),
            "affected": [{"package": {"ecosystem": "PyPI", "name": pkg},
                          "ranges": [{"type": "ECOSYSTEM", "events": events}]}], **extra}


# Known answers used across tests:
#   alpha 1.0   -> CVE-2030-0001  fixed 1.5 (same major), CVSS 9.8 vector, in KEV, EPSS 0.9
#   beta  2.0   -> CVE-2030-0002  fixed 3.0 (major bump), CVSS 5.3 vector, EPSS 0.001
#   gamma 1.0   -> no advisory (clean)
#   delta 1.0   -> advisory range fixed at 0.9 => version 1.0 NOT affected (used for false-positive tests)
#   epsilon     -> CVE-2030-0005 affects 2.0 up to (not incl.) 3.0 (used for range-resolution tests)
@pytest.fixture()
def data_dir(tmp_path):
    advisories = [
        _adv("GHSA-aaaa-0001", ["CVE-2030-0001"], "alpha", [{"introduced": "0"}, {"fixed": "1.5"}],
             severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]),
        _adv("GHSA-bbbb-0002", ["CVE-2030-0002"], "beta", [{"introduced": "0"}, {"fixed": "3.0"}],
             severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}]),
        _adv("GHSA-dddd-0004", ["CVE-2030-0004"], "delta", [{"introduced": "0"}, {"fixed": "0.9"}]),
        _adv("GHSA-eeee-0005", ["CVE-2030-0005"], "epsilon", [{"introduced": "2.0"}, {"fixed": "3.0"}]),
    ]
    z = tmp_path / "PyPI.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for a in advisories:
            zf.writestr(f"{a['id']}.json", json.dumps(a))
    (tmp_path / "osv").mkdir()
    build_osv_index(z, tmp_path / "osv" / "PyPI.index.json", "PyPI")
    (tmp_path / "kev.json").write_text(json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2030-0001", "dateAdded": "2030-02-01", "dueDate": "2030-02-22", "knownRansomwareCampaignUse": "Unknown"}]}))
    (tmp_path / "epss").mkdir()
    csv = "#model_version:v1,score_date:2030-03-01T00:00:00Z\ncve,epss,percentile\nCVE-2030-0001,0.9,0.99\nCVE-2030-0002,0.001,0.1\n"
    (tmp_path / "epss" / "epss_2030-03-01.csv.gz").write_bytes(gzip.compress(csv.encode()))
    (tmp_path / "manifest.json").write_text(json.dumps({
        "kev": {"snapshot_date": "2030-03-01"}, "epss": {"snapshot_date": "2030-03-01"},
        "osv:PyPI": {"snapshot_date": "2030-03-01"}}))
    return tmp_path
