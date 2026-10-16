"""Loaders for the small feeds: CISA KEV, FIRST/Empirical EPSS, and the compact NVD file."""
from __future__ import annotations

import csv
import datetime as dt
import gzip
import io
import json
from pathlib import Path


def load_kev(data_dir: Path) -> dict[str, dict]:
    """{CVE id: {dateAdded, dueDate, ransomware}} from the CISA KEV catalog."""
    path = data_dir / "kev.json"
    if not path.exists():
        raise FileNotFoundError(f"{path} missing: run `python scripts/fetch_data.py --only kev`")
    doc = json.loads(path.read_text("utf-8"))
    return {
        v["cveID"]: {
            "dateAdded": v.get("dateAdded"),
            "dueDate": v.get("dueDate"),
            "ransomware": v.get("knownRansomwareCampaignUse"),
        }
        for v in doc["vulnerabilities"]
    }


def read_epss_file(path: Path) -> tuple[str | None, dict[str, tuple[float, float]]]:
    """Returns (score_date, {CVE: (epss, percentile)}) for one dated EPSS file."""
    text = gzip.decompress(path.read_bytes()).decode("utf-8")
    first, _, rest = text.partition("\n")
    score_date = first.split("score_date:")[-1][:10] if "score_date:" in first else None
    scores = {
        row["cve"]: (float(row["epss"]), float(row["percentile"]))
        for row in csv.DictReader(io.StringIO(rest))
    }
    return score_date, scores


def epss_files(data_dir: Path) -> list[Path]:
    """All cached EPSS files, oldest first (file names carry the score date)."""
    return sorted((data_dir / "epss").glob("epss_*.csv.gz"))


def load_epss(data_dir: Path) -> tuple[str | None, dict[str, tuple[float, float]]]:
    """The newest cached EPSS snapshot."""
    files = epss_files(data_dir)
    if not files:
        raise FileNotFoundError(f"no EPSS files in {data_dir / 'epss'}: run `python scripts/fetch_data.py --only epss`")
    return read_epss_file(files[-1])


def load_epss_history(data_dir: Path, cves: set[str]) -> dict[str, list[tuple[str, float]]]:
    """{CVE: [(score_date, epss), ...]} across every cached file: REAL history for the timeline."""
    history: dict[str, list[tuple[str, float]]] = {c: [] for c in cves}
    for f in epss_files(data_dir):
        date, scores = read_epss_file(f)
        if not date:
            continue
        for c in cves:
            if c in scores:
                history[c].append((date, scores[c][0]))
    return history


def load_nvd(data_dir: Path) -> dict[str, dict]:
    """{CVE id: compact NVD record}. Empty if the NVD step has not been run (callers must cope)."""
    path = data_dir / "nvd.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text("utf-8"))["records"]


def snapshot_dates(data_dir: Path) -> dict[str, str | None]:
    """Date of each snapshot, for the UI footer. None means that snapshot is missing."""
    path = data_dir / "manifest.json"
    m = json.loads(path.read_text("utf-8")) if path.exists() else {}
    osv_dates = [v.get("snapshot_date") for k, v in m.items() if k.startswith("osv:") and v.get("snapshot_date")]
    return {
        "osv": min(osv_dates) if osv_dates else None,
        "nvd": (m.get("nvd") or {}).get("snapshot_date"),
        "kev": (m.get("kev") or {}).get("snapshot_date"),
        "epss": (m.get("epss") or {}).get("snapshot_date"),
    }


def snapshot_warnings(snapshots: dict[str, str | None], today: dt.date, stale_days: int) -> list[str]:
    """Plain-language warnings about old or missing data, so a stale scan is never mistaken for a current one."""
    out = []
    old = []
    for name, date in snapshots.items():
        if not date:
            continue
        try:
            age = (today - dt.date.fromisoformat(date)).days
        except ValueError:
            continue
        if age > stale_days:
            old.append(f"{name} {date} ({age} days old)")
    if old:
        out.append("advisory data is out of date: " + ", ".join(old) + ". Vulnerabilities published since are not covered; "
                   "run `python scripts/fetch_data.py` to refresh.")
    if not snapshots.get("nvd"):
        out.append("NVD snapshot missing: severity comes from OSV CVSS vectors and labels instead of NVD scores, "
                   "and NVD rejected/disputed status is not checked.")
    return out
