"""OSV loader: turn the big per-ecosystem all.zip into a small index keyed by package name.

Each advisory in the index keeps only what matching, scoring and trust need.
The index is built once by scripts/fetch_data.py and loaded from disk at demo time.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

from ..ecosystems import normalize_name  # noqa: F401  (re-exported: tests and callers import it from here)


def compact_advisory(raw: dict, ecosystem: str, package: str) -> dict:
    """One advisory, reduced to the fields depscan uses, for ONE package."""
    affected = []
    for a in raw.get("affected", []):
        pkg = a.get("package", {})
        if pkg.get("ecosystem") != ecosystem or normalize_name(ecosystem, pkg.get("name", "")) != package:
            continue
        affected.append({
            "ranges": [r for r in a.get("ranges", []) if r.get("type") in ("ECOSYSTEM", "SEMVER", "GIT")],
            "versions": a.get("versions", []),
        })
    refs = raw.get("references", [])
    return {
        "id": raw["id"],
        "aliases": raw.get("aliases", []),
        "summary": raw.get("summary") or (raw.get("details", "")[:200]),
        "published": raw.get("published"),
        "modified": raw.get("modified"),
        "withdrawn": raw.get("withdrawn"),
        "severity": raw.get("severity", []),  # CVSS vectors, no numeric score
        "label": (raw.get("database_specific") or {}).get("severity"),  # GHSA: LOW / MODERATE / HIGH / CRITICAL
        "fix_refs": [r["url"] for r in refs if r.get("type") == "FIX"][:5],
        "affected": affected,
    }


def build_osv_index(zip_path: Path, out_path: Path, ecosystem: str) -> tuple[int, int, str | None]:
    """Returns (advisory count, package count, newest `modified` timestamp)."""
    packages: dict[str, list[dict]] = {}
    n = 0
    newest: str | None = None
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            if not name.endswith(".json"):
                continue
            raw = json.loads(z.read(name))
            n += 1
            mod = raw.get("modified")
            if mod and (newest is None or mod > newest):
                newest = mod
            for pkg in {
                normalize_name(ecosystem, a["package"]["name"])
                for a in raw.get("affected", [])
                if a.get("package", {}).get("ecosystem") == ecosystem
            }:
                packages.setdefault(pkg, []).append(compact_advisory(raw, ecosystem, pkg))
    out_path.write_text(json.dumps({"ecosystem": ecosystem, "packages": packages}), "utf-8")
    return n, len(packages), newest


def load_osv_index(data_dir: Path, ecosystem: str) -> dict[str, list[dict]]:
    path = data_dir / "osv" / f"{ecosystem}.index.json"
    if not path.exists():
        raise FileNotFoundError(f"{path} missing: run `python scripts/fetch_data.py --only osv`")
    return json.loads(path.read_text("utf-8"))["packages"]
