"""The scan pipeline: file -> parse -> match -> score -> recommend. Read-only and offline."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from .data.feeds import load_epss, load_kev, load_nvd, snapshot_dates
from .data.osv import load_osv_index
from .matcher import match_all
from .matcher.versions import UnparsableVersion, parse_version
from .models import Match
from .parsers import parse_files
from .registry import Registry, resolve_ranges
from .scoring.config import load_config
from .scoring.recommend import action_from_risk, minimum_fix, recommendation_text
from .scoring.risk import compute_risk

DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class DataBundle:
    """All cached snapshots, loaded once and reused across scans."""

    def __init__(self, data_dir: Path = DEFAULT_DATA_DIR, registry: Registry | None = None):
        self.data_dir = data_dir
        self.registry = registry   # None = never resolve ranges (tests, strictly offline runs)
        self._osv: dict[str, dict] = {}
        self.kev = load_kev(data_dir)
        self.epss_date, self.epss = load_epss(data_dir)
        self.nvd = load_nvd(data_dir)          # may be empty if the NVD step was not run
        self.snapshots = snapshot_dates(data_dir)

    def osv(self, ecosystem: str) -> dict[str, list[dict]]:
        if ecosystem not in self._osv:
            self._osv[ecosystem] = load_osv_index(self.data_dir, ecosystem)
        return self._osv[ecosystem]


def _summary(match: Match) -> str:
    for adv in match.advisories:
        if adv.get("summary"):
            return adv["summary"]
    claim = next((c for c in match.dependency.claims if c.cve == match.id), None)
    return f"{match.id} (reported by the {claim.source})" if claim else match.id


def build_finding(match: Match, bundle: DataBundle, cfg: dict, exposed: bool | None = None) -> dict:
    dep = match.dependency
    fixed, major = minimum_fix(match)
    risk = compute_risk(match, nvd=bundle.nvd, kev=bundle.kev, epss=bundle.epss,
                        fixed_version=fixed, major_bump=major, cfg=cfg, exposed=exposed)
    uncertain = match.confidence == "uncertain"
    action = action_from_risk(risk["score"], cfg, uncertain=uncertain)
    return {
        "id": match.id,
        "aliases": match.aliases,
        "package": dep.name,
        "version": match.version or dep.candidate,
        "ecosystem": dep.ecosystem,
        "direct": dep.direct,
        "scope": dep.scope,
        "summary": _summary(match),
        "cvss": risk["cvss"],
        "epss": risk["epss"],
        "kev": risk["kev"] is not None,
        "fixed_version": fixed,
        "major_bump": major,
        "match": {"confidence": match.confidence, "evidence": match.evidence},
        "risk": {"score": risk["score"], "factors": risk["factors"], "notes": risk["notes"]},
        "action": action,
        "recommendation": recommendation_text(match, fixed, major, action),
        "exposure": None,
        "history": [],
        "watch": None,
        "review": None,
        # Trust (phase 5) is added by the trust layer. Not present yet, on purpose: no placeholder numbers.
    }


def package_actions(findings: list[dict]) -> list[dict]:
    """One upgrade target per package: the lowest version that clears every finding that has a fix."""
    by_pkg: dict[tuple[str, str, str], list[dict]] = {}
    for f in findings:
        by_pkg.setdefault((f["ecosystem"], f["package"], f["version"]), []).append(f)
    out = []
    for (eco, name, version), items in by_pkg.items():
        fixable = [f for f in items if f["fixed_version"]]
        target = None
        if fixable:
            try:
                target = max((f["fixed_version"] for f in fixable), key=lambda v: parse_version(eco, v))
            except UnparsableVersion:
                target = None
        out.append({
            "package": name, "ecosystem": eco, "version": version, "target_version": target,
            "clears": len(fixable) if target else 0, "total": len(items),
            "top_risk": max(f["risk"]["score"] for f in items),
        })
    return sorted(out, key=lambda a: -a["top_risk"])


# Lock files that sit next to a manifest and settle which versions are really installed.
SIBLING_LOCKS = {
    "package.json": ["package-lock.json", "yarn.lock"],
    "requirements.txt": ["Pipfile.lock", "poetry.lock"],
}
KNOWN_FILES = ["requirements.txt", "package.json", "package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock"]


def collect_files(paths: list[Path]) -> list[tuple[str, bytes]]:
    """Read the given files (or the known files in a given folder), plus lock files beside a manifest.

    Files are only read. Order is kept so the first lock file found wins.
    """
    chosen: list[Path] = []
    for p in paths:
        chosen += [p / n for n in KNOWN_FILES if (p / n).is_file()] if p.is_dir() else [p]
    have = {p.resolve() for p in chosen}
    for p in list(chosen):
        siblings = SIBLING_LOCKS.get(p.name.lower()) or (SIBLING_LOCKS["requirements.txt"] if p.suffix == ".txt" else [])
        for lock in siblings:
            cand = p.with_name(lock)
            if cand.is_file() and cand.resolve() not in have:
                chosen.append(cand)
                have.add(cand.resolve())
    return [(p.name, p.read_bytes()) for p in chosen]


def scan_bytes(name: str, content: bytes, bundle: DataBundle, cfg: dict | None = None) -> dict:
    return scan_files([(name, content)], bundle, cfg)


def scan_files(files: list[tuple[str, bytes]], bundle: DataBundle, cfg: dict | None = None) -> dict:
    cfg = cfg or load_config()
    name = ", ".join(n for n, _ in files)
    parsed = parse_files(files)
    if bundle.registry is not None:
        parsed.warnings += resolve_ranges(parsed.dependencies, bundle.registry)
    ecosystems = {d.ecosystem for d in parsed.dependencies}
    matches = match_all(parsed.dependencies, {e: bundle.osv(e) for e in ecosystems})
    findings = [build_finding(m, bundle, cfg) for m in matches]
    findings.sort(key=lambda f: (-f["risk"]["score"], f["id"], f["package"]))
    return {
        "source": name,
        "scanned_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "kind": parsed.kind,
        "dependencies_read": len(parsed.dependencies),
        "warnings": parsed.warnings,
        "snapshots": bundle.snapshots,
        "findings": findings,
        "package_actions": package_actions(findings),
    }
