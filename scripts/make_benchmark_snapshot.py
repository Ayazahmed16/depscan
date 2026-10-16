#!/usr/bin/env python3
"""Freeze the data the benchmark fixtures need, copied from the live cache in ./data (nothing invented).

The benchmark compares rankings on fixed inputs, so the data behind it must not move when the live feeds update.
This extracts, for every package named by a fixture in benchmark/fixtures/, its OSV advisory records, plus the KEV
entries and EPSS scores of their CVEs, into benchmark/snapshot/ (committed). There is no NVD data in the extract, so
severity comes from the OSV CVSS vectors, as in tests/sample/snapshot.

    python scripts/make_benchmark_snapshot.py

Run it again only to re-baseline; then re-run `python scripts/benchmark.py --write` and re-read the labels.
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
from depscan.parsers import parse_files  # noqa: E402

SRC = ROOT / "data"
OUT = ROOT / "benchmark" / "snapshot"
FIXTURES = ROOT / "benchmark" / "fixtures"


def fixture_packages() -> dict[str, set[str]]:
    wanted: dict[str, set[str]] = {}
    for folder in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        files = [(f.name, f.read_bytes()) for f in sorted(folder.iterdir()) if f.is_file()]
        for dep in parse_files(files).dependencies:
            wanted.setdefault(dep.ecosystem, set()).add(dep.name)
    return wanted


def main() -> None:
    wanted = fixture_packages()
    (OUT / "osv").mkdir(parents=True, exist_ok=True)
    full = json.loads((SRC / "manifest.json").read_text("utf-8"))
    cves: set[str] = set()
    manifest: dict = {"note": "Extract of the live cache for the packages named by benchmark/fixtures. No NVD data (severity comes from OSV CVSS vectors)."}
    for eco, names in sorted(wanted.items()):
        index = json.loads((SRC / "osv" / f"{eco}.index.json").read_text("utf-8"))["packages"]
        chosen = {n: index.get(n, []) for n in sorted(names)}
        cves |= {i for advs in chosen.values() for a in advs for i in [a["id"], *a["aliases"]] if i.startswith("CVE-")}
        (OUT / "osv" / f"{eco}.index.json").write_text(json.dumps({"ecosystem": eco, "packages": chosen}, indent=1, sort_keys=True), "utf-8")
        manifest[f"osv:{eco}"] = {"snapshot_date": full[f"osv:{eco}"]["snapshot_date"]}
        print(f"{eco}: {len(names)} packages, {sum(len(v) for v in chosen.values())} advisory records")

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
        text = f"#model_version:benchmark-extract,score_date:{date}T00:00:00Z\n{buf.getvalue()}"
        (OUT / "epss" / f"epss_{date}.csv.gz").write_bytes(gzip.compress(text.encode(), mtime=0))
        dates.append(date)
    manifest["kev"] = {"snapshot_date": full["kev"]["snapshot_date"]}
    manifest["epss"] = {"snapshot_date": max(dates)}
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=1), "utf-8")
    print(f"{len(cves)} CVEs, {len(kev)} in KEV, EPSS dates {sorted(dates)}")


if __name__ == "__main__":
    main()
