#!/usr/bin/env python3
"""Freeze a tiny, deterministic snapshot of REAL data for the known test sample.

The live cache in ./data changes every day (new advisories, EPSS moves). Tests with fixed expected
rankings need data that does not move, so this extracts only the records for a handful of packages
from the cache into tests/sample/snapshot/, which is committed. Run it again only if you want to
re-baseline the sample (then re-read the expected rankings in tests/test_known_sample.py).

    python scripts/make_sample_snapshot.py

Nothing is invented: every record, KEV entry and EPSS score below was copied from the real feeds.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from depscan.data.feeds import epss_files, load_kev, read_epss_file  # noqa: E402

PACKAGES = ["pyspark", "pyyaml", "flask", "requests", "jinja2", "six"]  # six has no advisories on purpose (clean case)
SRC = ROOT / "data"
OUT = ROOT / "tests" / "sample" / "snapshot"


def main() -> None:
    index = json.loads((SRC / "osv" / "PyPI.index.json").read_text("utf-8"))["packages"]
    chosen = {p: index.get(p, []) for p in PACKAGES}
    cves = {i for advs in chosen.values() for a in advs for i in [a["id"], *a["aliases"]] if i.startswith("CVE-")}

    (OUT / "osv").mkdir(parents=True, exist_ok=True)
    (OUT / "osv" / "PyPI.index.json").write_text(json.dumps({"ecosystem": "PyPI", "packages": chosen}, indent=1, sort_keys=True), "utf-8")

    kev = {c: v for c, v in load_kev(SRC).items() if c in cves}
    (OUT / "kev.json").write_text(json.dumps({"vulnerabilities": [
        {"cveID": c, "dateAdded": v["dateAdded"], "dueDate": v["dueDate"], "knownRansomwareCampaignUse": v["ransomware"]}
        for c, v in sorted(kev.items())]}, indent=1), "utf-8")

    (OUT / "epss").mkdir(exist_ok=True)
    dates = []
    for f in epss_files(SRC):
        date, scores = read_epss_file(f)
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["cve", "epss", "percentile"])
        for c in sorted(cves):
            if c in scores:
                w.writerow([c, scores[c][0], scores[c][1]])
        text = f"#model_version:sample-extract,score_date:{date}T00:00:00Z\n{buf.getvalue()}"
        (OUT / "epss" / f"epss_{date}.csv.gz").write_bytes(gzip.compress(text.encode(), mtime=0))  # mtime=0: stable bytes
        dates.append(date)

    full = json.loads((SRC / "manifest.json").read_text("utf-8"))
    (OUT / "manifest.json").write_text(json.dumps({
        "note": "Extract of the live cache for the packages listed in scripts/make_sample_snapshot.py. No NVD data (so severity comes from OSV CVSS vectors).",
        "osv:PyPI": {"snapshot_date": full["osv:PyPI"]["snapshot_date"]},
        "kev": {"snapshot_date": full["kev"]["snapshot_date"]},
        "epss": {"snapshot_date": max(dates)},
    }, indent=1), "utf-8")
    print(f"packages {PACKAGES}: {sum(len(v) for v in chosen.values())} advisory records, {len(cves)} CVEs, "
          f"{len(kev)} in KEV, EPSS dates {sorted(dates)}")


if __name__ == "__main__":
    main()
