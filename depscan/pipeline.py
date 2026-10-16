"""The scan pipeline: file -> parse -> match -> score -> recommend. Read-only and offline."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from .data.feeds import load_epss, load_kev, load_nvd, snapshot_dates, snapshot_warnings
from .data.osv import load_osv_index
from .graph import analyze_project
from .matcher import match_all
from .matcher.versions import UnparsableVersion, parse_version
from .models import Match
from .osv_api import OsvApiIndex
from .parsers import parse_files
from .registry import Registry, resolve_ranges
from .review import ReviewStore, finding_key
from .scoring.config import load_config
from .scoring.recommend import decide_action, minimum_fix, recommendation_text
from .scoring.risk import compute_risk
from .scoring.trust import compute_trust

DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DEFAULT_REVIEW_DB = Path(__file__).resolve().parent.parent / "state" / "review.sqlite"


class DataBundle:
    """All cached snapshots, loaded once and reused across scans."""

    def __init__(self, data_dir: Path = DEFAULT_DATA_DIR, registry: Registry | None = None,
                 osv_api: bool = False, offline: bool = False, osv_transport=None):
        self.data_dir = data_dir
        self.osv_api, self.offline, self.osv_transport = osv_api, offline, osv_transport
        self.registry = registry   # None = never resolve ranges (tests, strictly offline runs)
        self._osv: dict[str, dict] = {}
        self.kev = load_kev(data_dir)
        self.epss_date, self.epss = load_epss(data_dir)
        self.nvd = load_nvd(data_dir)          # may be empty if the NVD step was not run
        self.snapshots = snapshot_dates(data_dir)
        # Trust (freshness) is measured at the data snapshot date, so a scan is reproducible from its snapshot.
        try:
            self.as_of = dt.date.fromisoformat(self.snapshots["osv"] or "")
        except ValueError:
            self.as_of = dt.date.today()

    def osv(self, ecosystem: str) -> dict[str, list[dict]]:
        """Local bulk index if there is one (fully offline), else the OSV.dev API (cached), else an error."""
        if ecosystem not in self._osv:
            if (self.data_dir / "osv" / f"{ecosystem}.index.json").exists():
                self._osv[ecosystem] = load_osv_index(self.data_dir, ecosystem)
            elif self.osv_api:
                self._osv[ecosystem] = OsvApiIndex(ecosystem, self.data_dir, transport=self.osv_transport, offline=self.offline)
            else:
                raise FileNotFoundError(
                    f"no local advisory index for {ecosystem}: run `python scripts/fetch_data.py --only osv --ecosystems {ecosystem}`")
        return self._osv[ecosystem]


def _tidy(text: str) -> str:
    """The index cuts a missing summary out of `details` at exactly 200 characters, often mid-word. End it cleanly."""
    if len(text) == 200:
        text = text[:text.rfind(" ")].rstrip(" ,;:") + "…"
    return text


def _summary(match: Match) -> str:
    for adv in match.advisories:
        if adv.get("summary"):
            return _tidy(adv["summary"])
    claim = next((c for c in match.dependency.claims if c.cve == match.id), None)
    return f"{match.id} (reported by the {claim.source})" if claim else match.id


def make_release_check(registry: Registry | None):
    """Does this version really exist on the package registry? True / False / "yanked" / None (could not check)."""
    cache: dict[tuple[str, str], tuple[list[str], list[str]] | None] = {}

    def check(eco: str, name: str, version: str) -> bool | str | None:
        if registry is None:
            return None
        if (eco, name) not in cache:
            cache[(eco, name)] = registry.releases(eco, name)
        releases = cache[(eco, name)]
        if releases is None:
            return None
        try:
            target = parse_version(eco, version)
        except UnparsableVersion:
            return None
        released, yanked = releases
        if any(parse_version(eco, v) == target for v in released if _parsable(eco, v)):
            return True
        if any(parse_version(eco, v) == target for v in yanked if _parsable(eco, v)):
            return "yanked"
        return False

    return check


def _parsable(eco: str, v: str) -> bool:
    try:
        parse_version(eco, v)
        return True
    except UnparsableVersion:
        return False


def build_finding(match: Match, bundle: DataBundle, cfg: dict, exposure: dict | None = None, release_exists=None) -> dict:
    dep = match.dependency
    fixed, major = minimum_fix(match)
    risk = compute_risk(match, nvd=bundle.nvd, kev=bundle.kev, epss=bundle.epss,
                        fixed_version=fixed, major_bump=major, cfg=cfg,
                        exposed=exposure["level"] if exposure else None)
    fix_yanked = bool(fixed and release_exists and release_exists(dep.ecosystem, dep.name, fixed) == "yanked")
    trust = compute_trust(match, nvd=bundle.nvd, kev=bundle.kev, fixed_version=fixed, as_of=bundle.as_of, cfg=cfg, release_exists=release_exists)
    action = decide_action(risk["score"], trust["score"], cfg, uncertain=match.confidence == "uncertain")
    finding = {
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
        "trust": trust,
        "action": action,
        # matched = found by our advisory data; unconfirmed = only a scan report claims it; contradicted = advisory data says it is NOT affected
        "claim_status": "contradicted" if match.contradicted else "unconfirmed" if match.scanner_only else "matched",
        "recommendation": recommendation_text(match, fixed, major, action, fix_yanked=fix_yanked),
        "exposure": exposure,       # from the project graph (phase 7), None when no project was analysed or it cannot be known
        "history": [],
        "watch": None,
        "review": None,             # filled in by apply_reviews when a person has decided
        "review_status": "pending",  # pending | fix_now | accept_risk | false_positive | expired
    }
    finding["key"] = finding_key(finding)  # stable identity that reviewer decisions attach to
    return finding


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
KNOWN_FILES = ["requirements.txt", "package.json", "package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock", "go.mod"]


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


def _noon(day: dt.date) -> dt.datetime:
    return dt.datetime.combine(day, dt.time(12), tzinfo=dt.UTC)


REVIEW_STATUSES = ("pending", "expired", "fix_now", "accept_risk", "false_positive")


def apply_reviews(findings: list[dict], store: ReviewStore | None, project: str, now=None) -> dict:
    """Attach each finding's current reviewer decision, and return the counts.

    Nothing is hidden or re-scored: a finding with a decision is still listed, with the decision beside it.
    A suppression whose expiry passed is `expired` and counts as needing review again (and is logged once).
    """
    current = {}
    if store is not None:
        store.sweep_expired(project, now=now)
        current = store.current(project, now=now)
    counts = dict.fromkeys(REVIEW_STATUSES, 0)
    for f in findings:
        rec = current.get(f["key"])
        if rec:
            f["review"] = {k: rec[k] for k in ("decision", "note", "reviewer", "at", "expires")}
            f["review_status"] = rec["status"]
        else:
            f["review"], f["review_status"] = None, "pending"
        counts[f["review_status"]] += 1
    counts["needs_review"] = counts["pending"] + counts["expired"]
    return counts


def scan_bytes(name: str, content: bytes, bundle: DataBundle, cfg: dict | None = None) -> dict:
    return scan_files([(name, content)], bundle, cfg)


def scan_files(files: list[tuple[str, bytes]], bundle: DataBundle, cfg: dict | None = None, today: dt.date | None = None,
               review_store: ReviewStore | None = None, project: str = "default", project_dir: Path | None = None) -> dict:
    cfg = cfg or load_config()
    name = ", ".join(n for n, _ in files)
    parsed = parse_files(files)
    parsed.warnings += snapshot_warnings(bundle.snapshots, today or dt.date.today(), cfg["data"]["stale_days"])
    if bundle.registry is not None:
        parsed.warnings += resolve_ranges(parsed.dependencies, bundle.registry)
    ecosystems = {d.ecosystem for d in parsed.dependencies}
    indexes = {e: bundle.osv(e) for e in ecosystems}
    for e, idx in indexes.items():
        if isinstance(idx, OsvApiIndex):
            idx.prefetch([d.name for d in parsed.dependencies if d.ecosystem == e])  # one batched request
    matches = match_all(parsed.dependencies, indexes)
    for e, idx in indexes.items():
        if isinstance(idx, OsvApiIndex) and idx.failed:
            parsed.warnings.append(
                f"{len(idx.failed)} {e} package(s) could NOT be checked: OSV.dev was unreachable and nothing was cached. "
                f"Their absence from the findings is not a clean result.")
    release_exists = make_release_check(bundle.registry)
    analysis = analyze_project(project_dir, parsed.dependencies) if project_dir else None   # reads the .py files, never runs them
    if analysis:
        parsed.warnings += analysis.warnings
    findings = [
        build_finding(m, bundle, cfg, release_exists=release_exists,
                      exposure=analysis.exposure(m.dependency.name) if analysis and m.dependency.ecosystem == "PyPI" else None)
        for m in matches
    ]
    if analysis and any(f["ecosystem"] != "PyPI" for f in findings):
        parsed.warnings.append("exposure analysis covers Python (Django) packages only: findings for other ecosystems have no exposure factor")
    # Order: our own matches, then unconfirmed scanner claims, then likely false positives; by risk within each.
    # The risk SCORE is untouched. This only stops a contradicted claim from outranking a confirmed finding.
    tier = {"matched": 0, "unconfirmed": 1, "contradicted": 2}
    findings.sort(key=lambda f: (tier[f["claim_status"]], -f["risk"]["score"], f["id"], f["package"]))
    return {
        "source": name,
        "scanned_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "kind": parsed.kind,
        "dependencies_read": len(parsed.dependencies),
        "warnings": parsed.warnings,
        "snapshots": bundle.snapshots,
        "findings": findings,
        "project": project,
        "graph": analysis.render({f["package"] for f in findings if f["ecosystem"] == "PyPI"}) if analysis else None,
        "review_summary": apply_reviews(findings, review_store, project, now=_noon(today) if today else None),
        "package_actions": package_actions(findings),
    }
