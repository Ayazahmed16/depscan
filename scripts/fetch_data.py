#!/usr/bin/env python3
"""Download vulnerability data snapshots into ./data so depscan can run offline.

This is the ONLY part of depscan that uses the network. Run it once before a demo:

    python scripts/fetch_data.py                 # everything
    python scripts/fetch_data.py --only kev epss # just the small ones
    python scripts/fetch_data.py --only nvd      # NVD crawl (slow without a key)

Sources (checked against the live endpoints, see docs/PLAN.md):
    OSV   https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip
    KEV   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    EPSS  https://epss.empiricalsecurity.com/epss_scores-<current|YYYY-MM-DD>.csv.gz
    NVD   https://services.nvd.nist.gov/rest/json/cves/2.0   (optional NVD_API_KEY env var)

Standard library only, so it runs the same on Windows, macOS and Linux.
Nothing here touches a project's dependency files.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

# Make `import depscan` work when run as a script from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from depscan.data.osv import build_osv_index  # noqa: E402

OSV_URL = "https://storage.googleapis.com/osv-vulnerabilities/{eco}/all.zip"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{tag}.csv.gz"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "depscan-hackathon/0.1 (offline snapshot fetcher)"

ALL_SOURCES = ("osv", "kev", "epss", "nvd")


def log(msg: str) -> None:
    print(msg, flush=True)


def http_get(url: str, *, retries: int = 4, timeout: int = 120, headers: dict | None = None) -> bytes:
    """GET with a few retries and a clear error. Returns the body bytes."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    last: Exception | None = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (403, 429, 503):  # rate limited or briefly unavailable: wait and retry
                time.sleep(8 * (attempt + 1))
            elif e.code == 404:
                raise
            else:
                time.sleep(2 * (attempt + 1))
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = e
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"giving up on {url}: {last}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Manifest:
    """data/manifest.json: what we downloaded, when, from where. The UI footer reads it."""

    def __init__(self, data_dir: Path):
        self.path = data_dir / "manifest.json"
        self.data = json.loads(self.path.read_text("utf-8")) if self.path.exists() else {}

    def record(self, key: str, *, url: str, file: Path, snapshot_date: str | None, extra: dict | None = None) -> None:
        self.data[key] = {
            "url": url,
            "file": file.name,
            "bytes": file.stat().st_size,
            "sha256": sha256(file),
            "fetched_at": now_iso(),
            "snapshot_date": snapshot_date,
            **(extra or {}),
        }
        self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True), "utf-8")


# ---------------------------------------------------------------- OSV
def fetch_osv(data_dir: Path, ecosystems: list[str], manifest: Manifest) -> None:
    for eco in ecosystems:
        url = OSV_URL.format(eco=eco)
        target = data_dir / "osv" / f"{eco}.zip"
        target.parent.mkdir(parents=True, exist_ok=True)
        log(f"[osv] downloading {url}")
        body = http_get(url, timeout=600)
        tmp = target.with_suffix(".part")
        tmp.write_bytes(body)
        if not zipfile.is_zipfile(tmp):
            tmp.unlink()
            raise RuntimeError(f"[osv] {eco}: download is not a zip file")
        tmp.replace(target)
        log(f"[osv] {eco}: {len(body) / 1e6:.1f} MB, building compact index")
        n_adv, n_pkg, newest = build_osv_index(target, data_dir / "osv" / f"{eco}.index.json", eco)
        manifest.record(
            f"osv:{eco}",
            url=url,
            file=target,
            snapshot_date=(newest or "")[:10] or None,  # newest advisory `modified` date in the snapshot
            extra={"advisories": n_adv, "packages": n_pkg},
        )
        log(f"[osv] {eco}: {n_adv} advisories, {n_pkg} packages, newest modified {newest}")


# ---------------------------------------------------------------- KEV
def fetch_kev(data_dir: Path, manifest: Manifest) -> None:
    log(f"[kev] downloading {KEV_URL}")
    body = http_get(KEV_URL)
    doc = json.loads(body)  # fail loudly if it is not JSON
    if "vulnerabilities" not in doc:
        raise RuntimeError("[kev] unexpected format: no 'vulnerabilities' key")
    target = data_dir / "kev.json"
    target.write_bytes(body)
    released = str(doc.get("dateReleased", ""))[:10] or None
    manifest.record("kev", url=KEV_URL, file=target, snapshot_date=released,
                    extra={"count": len(doc["vulnerabilities"]), "catalogVersion": doc.get("catalogVersion")})
    log(f"[kev] {len(doc['vulnerabilities'])} entries, released {released}")


# ---------------------------------------------------------------- EPSS
def fetch_epss(data_dir: Path, manifest: Manifest, history_days: list[int]) -> None:
    """Current scores plus a few dated files, which feed the temporal view with REAL history."""
    folder = data_dir / "epss"
    folder.mkdir(parents=True, exist_ok=True)
    today = dt.date.today()
    wanted = [("current", None)] + [(str((today - dt.timedelta(days=d))), d) for d in history_days]
    for tag, days_back in wanted:
        url = EPSS_URL.format(tag=tag)
        try:
            body = http_get(url, timeout=300)
        except urllib.error.HTTPError as e:
            log(f"[epss] {tag}: not available ({e.code}), skipped")
            continue
        header = gzip.decompress(body).split(b"\n", 1)[0].decode()
        score_date = header.split("score_date:")[-1][:10] if "score_date:" in header else (tag if days_back else None)
        name = f"epss_{score_date or tag}.csv.gz"
        target = folder / name
        target.write_bytes(body)
        key = "epss" if tag == "current" else f"epss:{score_date}"
        manifest.record(key, url=url, file=target, snapshot_date=score_date)
        log(f"[epss] {tag} -> {name} ({len(body) / 1e6:.1f} MB)")


# ---------------------------------------------------------------- NVD
def wanted_cves(data_dir: Path, ecosystems: list[str]) -> set[str]:
    """Only CVEs that an OSV advisory in our ecosystems points at are worth keeping from NVD."""
    cves: set[str] = set()
    for eco in ecosystems:
        idx = data_dir / "osv" / f"{eco}.index.json"
        if not idx.exists():
            continue
        packages = json.loads(idx.read_text("utf-8"))["packages"]
        for advisories in packages.values():
            for a in advisories:
                cves.update(x for x in [a["id"], *a.get("aliases", [])] if x.startswith("CVE-"))
    return cves


def compact_nvd(cve: dict) -> dict:
    """Keep only what scoring and trust use. Raw NVD records are huge."""
    cvss = {}
    for key, label in (("cvssMetricV40", "v40"), ("cvssMetricV31", "v31"), ("cvssMetricV30", "v30"), ("cvssMetricV2", "v2")):
        metrics = cve.get("metrics", {}).get(key)
        if metrics:
            # Prefer the primary (NVD) score, else the first one listed.
            m = next((x for x in metrics if x.get("type") == "Primary"), metrics[0])
            data = m["cvssData"]
            cvss[label] = {"score": data.get("baseScore"), "vector": data.get("vectorString"), "source": m.get("source")}
    return {
        "id": cve["id"],
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "vulnStatus": cve.get("vulnStatus"),
        "tags": [t for t in cve.get("cveTags", [])],
        "cvss": cvss,
    }


def fetch_nvd(data_dir: Path, ecosystems: list[str], manifest: Manifest, resume: bool) -> None:
    wanted = wanted_cves(data_dir, ecosystems)
    if not wanted:
        log("[nvd] no OSV index found, run the osv step first (needed to know which CVEs to keep)")
        return
    api_key = os.environ.get("NVD_API_KEY")
    delay = 0.8 if api_key else 6.5  # NVD public rate limit: about 5 requests per 30 s without a key
    page = 2000
    ckpt = data_dir / "nvd.partial.json"
    kept: dict[str, dict] = {}
    start = 0
    if resume and ckpt.exists():
        saved = json.loads(ckpt.read_text("utf-8"))
        kept, start = saved["kept"], saved["next_index"]
        log(f"[nvd] resuming at index {start} with {len(kept)} kept")
    log(f"[nvd] keeping records for {len(wanted)} CVEs; {'API key set' if api_key else 'no API key: this is slow (about 25 min)'}")
    total = None
    stamp = None
    while total is None or start < total:
        params = urllib.parse.urlencode({"resultsPerPage": page, "startIndex": start})
        body = http_get(f"{NVD_URL}?{params}", timeout=180, headers={"apiKey": api_key} if api_key else None)
        doc = json.loads(body)
        total, stamp = doc["totalResults"], doc.get("timestamp", stamp)
        for item in doc["vulnerabilities"]:
            if item["cve"]["id"] in wanted:
                kept[item["cve"]["id"]] = compact_nvd(item["cve"])
        start += doc["resultsPerPage"]
        ckpt.write_text(json.dumps({"kept": kept, "next_index": start}), "utf-8")
        log(f"[nvd] {min(start, total)}/{total}, kept {len(kept)}")
        if start < total:
            time.sleep(delay)
    target = data_dir / "nvd.json"
    target.write_text(json.dumps({"timestamp": stamp, "records": kept}), "utf-8")
    ckpt.unlink(missing_ok=True)
    manifest.record("nvd", url=NVD_URL, file=target, snapshot_date=(stamp or "")[:10] or None,
                    extra={"records": len(kept), "total_in_nvd": total})
    log(f"[nvd] wrote {len(kept)} records")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default="data", type=Path)
    ap.add_argument("--only", nargs="+", choices=ALL_SOURCES, default=list(ALL_SOURCES))
    ap.add_argument("--ecosystems", nargs="+", default=["PyPI", "npm"])
    ap.add_argument("--epss-history", nargs="*", type=int, default=[30, 90, 180, 365],
                    help="also fetch EPSS files from N days ago (real history for the timeline)")
    ap.add_argument("--resume", action="store_true", help="continue an interrupted NVD crawl")
    args = ap.parse_args()

    data_dir: Path = args.data_dir
    data_dir.mkdir(parents=True, exist_ok=True)
    manifest = Manifest(data_dir)
    steps = {
        "osv": lambda: fetch_osv(data_dir, args.ecosystems, manifest),
        "kev": lambda: fetch_kev(data_dir, manifest),
        "epss": lambda: fetch_epss(data_dir, manifest, args.epss_history),
        "nvd": lambda: fetch_nvd(data_dir, args.ecosystems, manifest, args.resume),
    }
    failed = []
    for name in ALL_SOURCES:  # fixed order: osv before nvd
        if name in args.only:
            try:
                steps[name]()
            except Exception as e:  # keep going so one source failing does not lose the others
                failed.append(name)
                log(f"[{name}] FAILED: {e}")
    log("done" if not failed else f"done with failures: {', '.join(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
