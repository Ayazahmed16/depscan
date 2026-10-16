"""The benchmark: how depscan compares with two simpler approaches on small, labelled, frozen fixtures.

  naive      reports every advisory that mentions a package's name, whatever the version (for a scan report: every claim)
  cvss-only  the same findings as depscan, but ranked by CVSS score alone (no EPSS, KEV, fix, use or exposure)
  depscan    version-aware matching, risk/trust ranking, and findings that need checking held back from the main list

Nothing here is invented: the advisory, KEV and EPSS data are frozen extracts of the real feeds, and every number in
docs/BENCHMARK.md is produced by `python scripts/benchmark.py --write`.

The labels (which advisory truly affects which pinned version) are a DRAFT: written by the assistant and cross-checked
with a second, deliberately simple implementation of the OSV range rules (`oracle_affected`). They need the project
owner's manual verification (`verified_by_owner` stays false until then). See docs/BENCHMARK.md for what the results do
and do not show.
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from pathlib import Path

import yaml
from packaging.version import InvalidVersion, Version

from .data.feeds import load_kev
from .parsers import parse_files
from .pipeline import DataBundle, scan_files
from .scoring.config import load_config

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"
TOP_N = 3


# ------------------------------------------------------------------ the oracle: a second, simple reading of OSV ranges
def _semver_key(text: str) -> tuple:
    text = text.strip().lstrip("v").split("+")[0]
    core, _, pre = text.partition("-")
    nums = [int(p) if p.isdigit() else 0 for p in re.split(r"[.]", core)[:3]]
    nums += [0] * (3 - len(nums))
    if not pre:
        return (*nums, 1, ())
    ident = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (*nums, 0, ident)


def version_key(ecosystem: str, text: str):
    """A sortable key for a version, or None if the text is not a version (e.g. a git commit hash)."""
    if text.strip() == "0":                                   # OSV's "from the very beginning": below every other version
        return Version("0.dev0") if ecosystem == "PyPI" else (-1, -1, -1, -1, ())
    if ecosystem == "PyPI":
        try:
            return Version(text)
        except InvalidVersion:
            return None
    return _semver_key(text) if re.match(r"^v?\d+(\.\d+)*", text.strip()) else None


def oracle_affected(ecosystem: str, version: str, record: dict) -> bool:
    """Is `version` affected according to ONE advisory record? Walks the range events in version order."""
    target = version_key(ecosystem, version)
    if target is None:
        return False
    for aff in record.get("affected", []):
        if version in aff.get("versions", []):
            return True
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            events = []
            for ev in rng.get("events", []):
                kind = next((k for k in ("introduced", "fixed", "last_affected", "limit") if k in ev), None)
                key = version_key(ecosystem, ev[kind]) if kind else None
                if key is not None:                           # a git hash or other non-version cannot be compared: skipped
                    events.append((key, kind, ev[kind]))
            events.sort(key=lambda e: e[0])
            inside = False
            for key, kind, _ in events:
                if kind == "introduced" and target >= key:
                    inside = True
                elif kind in ("fixed", "limit") and target >= key:
                    inside = False
                elif kind == "last_affected" and target > key:
                    inside = False
            if inside:
                return True
    return False


# ------------------------------------------------------------------ grouping records into issues
def group_records(records: list[dict]) -> list[dict]:
    """Union records that share an id or alias. Returns [{canon, ids, records}]; canon is the lowest CVE id, else the lowest id."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for r in records:
        ids = [r["id"], *r.get("aliases", [])]
        for i in ids[1:]:
            parent[find(i)] = find(ids[0])
        find(ids[0])
    groups: dict[str, list[dict]] = {}
    for r in records:
        groups.setdefault(find(r["id"]), []).append(r)
    out = []
    for recs in groups.values():
        ids = sorted({i for r in recs for i in [r["id"], *r.get("aliases", [])]})
        cves = [i for i in ids if i.startswith("CVE-")]
        out.append({"canon": cves[0] if cves else ids[0], "ids": set(ids), "records": recs})
    return sorted(out, key=lambda g: g["canon"])


def oracle_issue_affected(ecosystem: str, version: str, group: dict) -> bool:
    live = [r for r in group["records"] if not r.get("withdrawn")]          # a withdrawn record is retracted, not evidence
    return any(oracle_affected(ecosystem, version, r) for r in live)


# ------------------------------------------------------------------ fixtures and labels
@dataclass
class Fixture:
    name: str
    description: str
    snapshot: Path
    inputs: list[Path]
    project_dir: Path | None
    reachable: dict[str, str] | None
    labels: dict
    is_report: bool


def load_fixtures(path: Path = BENCH / "fixtures.yaml") -> list[Fixture]:
    spec = yaml.safe_load(path.read_text("utf-8"))
    return [Fixture(
        name=f["name"], description=f["description"], snapshot=ROOT / f["snapshot"], inputs=[ROOT / p for p in f["inputs"]],
        project_dir=ROOT / f["project_dir"] if f.get("project_dir") else None, reachable=f.get("reachable"),
        labels=f["labels"], is_report=any(p.endswith(".json") and "package" not in Path(p).name for p in f["inputs"]),
    ) for f in spec["fixtures"]]


def labels_verified() -> bool:
    """True only when the owner has checked BOTH label files and set the flag."""
    files = [BENCH / "labels.yaml", ROOT / "tests" / "sample" / "labels.yaml"]
    return all(yaml.safe_load(f.read_text("utf-8")).get("verified_by_owner") is True for f in files)


def affected_from_labels(fx: Fixture, groups_by_pkg: dict[tuple[str, str], list[dict]], deps) -> tuple[set[tuple[str, str]], str]:
    """The labelled-affected set as {(package, canonical issue id)}, and where the labels came from."""
    lab = fx.labels
    if "hand" in lab:
        doc = yaml.safe_load((ROOT / lab["hand"]).read_text("utf-8"))
        pins = {(d.name, d.version) for d in deps}
        # every labelled advisory for the pins this fixture contains, from any section of the label file (a scan report's own
        # section only lists the claims it makes, but depscan also reports real findings the report did not mention)
        entries = [e for sec in doc["inputs"].values() for e in sec if (e["package"], e["version"]) in pins]
        out = set()
        for e in entries:
            if e.get("label") != "affected":
                continue
            dep = next(d for d in deps if d.name == e["package"])
            group = next((g for g in groups_by_pkg.get((dep.ecosystem, dep.name), []) if e["advisory"] in g["ids"]), None)
            out.add((e["package"], group["canon"] if group else e["advisory"]))
        return out, f"hand-written draft ({lab['hand']})"
    doc = yaml.safe_load((BENCH / "labels.yaml").read_text("utf-8"))["fixtures"][fx.name]
    return {(pkg, canon) for pkg, ids in doc["affected"].items() for canon in ids}, "draft derived by `oracle_affected` (benchmark/labels.yaml)"


def draft_labels(fixtures: list[Fixture]) -> dict:
    """What `oracle_affected` says is affected, per fixture. Written to benchmark/labels.yaml for the owner to review."""
    out: dict = {}
    for fx in fixtures:
        if "hand" in fx.labels:
            continue
        bundle = DataBundle(fx.snapshot)
        deps = parse_files([(p.name, p.read_bytes()) for p in fx.inputs]).dependencies
        affected: dict[str, list[str]] = {}
        for d in deps:
            version = d.version
            if version is None:
                continue
            idx = bundle.osv(d.ecosystem) if (fx.snapshot / "osv" / f"{d.ecosystem}.index.json").exists() else {}
            for g in group_records(idx.get(d.name, [])):
                if oracle_issue_affected(d.ecosystem, version, g):
                    affected.setdefault(d.name, []).append(g["canon"])
        out[fx.name] = {"affected": {k: sorted(v) for k, v in sorted(affected.items())}}
    return out


# ------------------------------------------------------------------ metrics
def rate(num: int, den: int) -> float | None:
    return round(num / den, 3) if den else None


def listing_metrics(reported: set, positives: set) -> dict:
    tp = len(reported & positives)
    return {"reported": len(reported), "true_positives": tp, "false_positives": len(reported) - tp,
            "precision": rate(tp, len(reported)), "recall": rate(tp, len(positives))}


def top_n_metrics(ranked: list, targets: set, n: int = TOP_N) -> dict:
    """How many of `targets` appear in the first n of `ranked`, and where the first one sits (1-based, None = not listed)."""
    hits = sum(1 for k in ranked[:n] if k in targets)
    possible = min(n, len(targets))
    first = next((i + 1 for i, k in enumerate(ranked) if k in targets), None)
    return {"hits": hits, "possible": possible, "share": rate(hits, possible), "first_rank": first}


def _canon_of(finding: dict, groups: list[dict]) -> str:
    ids = {finding["id"], *finding["aliases"]}
    group = next((g for g in groups if ids & g["ids"]), None)
    return group["canon"] if group else finding["id"]


def _reported(result: dict, groups_by_pkg: dict) -> tuple[list[tuple[str, str]], list[tuple[str, str]], dict]:
    """depscan's main list (matched and not uncertain) in its own order, the held-back findings, and key -> finding."""
    main, held, by_key = [], [], {}
    for f in result["findings"]:
        key = (f["package"], _canon_of(f, groups_by_pkg.get((f["ecosystem"], f["package"]), [])))
        if key in by_key:
            continue
        by_key[key] = f
        (main if f["claim_status"] == "matched" and f["match"]["confidence"] != "uncertain" else held).append(key)
    return main, held, by_key


def cvss_order(keys: list, by_key: dict) -> list:
    return sorted(keys, key=lambda k: (-(by_key[k]["cvss"] if by_key[k]["cvss"] is not None else -1.0), k))


def without_kev(cfg: dict) -> dict:
    out = copy.deepcopy(cfg)
    out["risk"]["weights"]["known_exploited"] = 0.0
    total = sum(out["risk"]["weights"].values())
    out["risk"]["weights"] = {k: v / total for k, v in out["risk"]["weights"].items()}
    return out


# ------------------------------------------------------------------ running
def run_fixture(fx: Fixture, bundles: dict[Path, DataBundle], cfg: dict) -> dict:
    bundle = bundles.setdefault(fx.snapshot, DataBundle(fx.snapshot))
    files = [(p.name, p.read_bytes()) for p in fx.inputs]
    deps = parse_files(files).dependencies
    groups_by_pkg: dict[tuple[str, str], list[dict]] = {}
    for d in deps:
        if (d.ecosystem, d.name) in groups_by_pkg:
            continue
        has_index = (fx.snapshot / "osv" / f"{d.ecosystem}.index.json").exists()
        groups_by_pkg[(d.ecosystem, d.name)] = group_records(bundle.osv(d.ecosystem).get(d.name, [])) if has_index else []
    positives, label_source = affected_from_labels(fx, groups_by_pkg, deps)
    kev = load_kev(fx.snapshot)

    def is_kev(key) -> bool:
        groups = next((g for (eco, name), gs in groups_by_pkg.items() if name == key[0] for g in gs if g["canon"] == key[1]), None)
        return bool(groups and any(i in kev for i in groups["ids"]))

    exploited = {k for k in positives if is_kev(k)}

    # naive: every advisory that mentions the package name (or, for a scan report, every claim)
    naive: set = set()
    for d in deps:
        if fx.is_report:
            for c in d.claims:
                g = next((g for g in groups_by_pkg[(d.ecosystem, d.name)] if c.cve in g["ids"]), None)
                naive.add((d.name, g["canon"] if g else c.cve))
        else:
            naive |= {(d.name, g["canon"]) for g in groups_by_pkg[(d.ecosystem, d.name)]}

    result = scan_files(files, bundle, cfg, project_dir=None)
    main, held, by_key = _reported(result, groups_by_pkg)
    no_kev_result = scan_files(files, bundle, without_kev(cfg), project_dir=None)
    no_kev_main, _, _ = _reported(no_kev_result, groups_by_pkg)
    cvss_main = cvss_order(main, by_key)

    out = {
        "name": fx.name, "description": fx.description, "dependencies": len(deps), "label_source": label_source,
        "labelled_affected": len(positives), "known_exploited_affected": len(exploited),
        "naive": listing_metrics(naive, positives),
        "depscan": {**listing_metrics(set(main), positives), "held": len(held), "held_truly_affected": len(set(held) & positives)},
        "disagreements": {
            "labelled_affected_but_not_reported": [{"package": k[0], "id": k[1], "status": "held back" if k in held else "not found"}
                                                    for k in sorted(positives - set(main))],
            "reported_but_not_labelled_affected": [{"package": k[0], "id": k[1]} for k in sorted(set(main) - positives)],
        },
        "ranking": {
            "cvss_only": top_n_metrics(cvss_main, exploited),
            "depscan": top_n_metrics(main, exploited),
            "depscan_without_kev_weight": top_n_metrics(no_kev_main, exploited),
        },
        "reachability": None,
    }
    if fx.project_dir and fx.reachable:
        with_project = scan_files(files, bundle, cfg, project_dir=fx.project_dir)
        with_main, _, with_by_key = _reported(with_project, groups_by_pkg)
        web = {k for k in positives if fx.reachable.get(k[0]) == "web"}
        levels = {f["package"]: (f["exposure"] or {}).get("level") for f in with_project["findings"] if f["exposure"]}
        out["reachability"] = {
            "web_reachable_affected": len(web),
            "exposure_matches_design": all(levels.get(p) == lvl for p, lvl in fx.reachable.items() if p in levels),
            "cvss_only": top_n_metrics(cvss_main, web),
            "depscan_no_project": top_n_metrics(main, web),
            "depscan_with_project": top_n_metrics(with_main, web),
        }
        out["reachability"]["top3_with_project"] = [{"package": k[0], "id": k[1], "exposure": levels.get(k[0])} for k in with_main[:TOP_N]]
    return out


def hand_vs_oracle(fixtures: list[Fixture], bundles: dict[Path, DataBundle]) -> dict:
    """For the hand-labelled fixtures: does the simple oracle agree with the hand labels?"""
    agree = only_hand = only_oracle = 0
    detail = []
    for fx in fixtures:
        if "hand" not in fx.labels:
            continue
        bundle = bundles.setdefault(fx.snapshot, DataBundle(fx.snapshot))
        deps = parse_files([(p.name, p.read_bytes()) for p in fx.inputs]).dependencies
        groups = {(d.ecosystem, d.name): group_records(bundle.osv(d.ecosystem).get(d.name, [])) for d in deps}
        hand, _ = affected_from_labels(fx, groups, deps)
        oracle = {(d.name, g["canon"]) for d in deps if d.version for g in groups[(d.ecosystem, d.name)]
                  if oracle_issue_affected(d.ecosystem, d.version, g)}
        if fx.is_report:                      # a report names only some packages' claims: compare on the packages it covers
            names = {d.name for d in deps}
            oracle = {k for k in oracle if k[0] in names}
        agree += len(hand & oracle)
        only_hand += len(hand - oracle)
        only_oracle += len(oracle - hand)
        detail.append({"fixture": fx.name, "agree": len(hand & oracle), "only_hand": sorted(hand - oracle), "only_oracle": sorted(oracle - hand)})
    return {"agree": agree, "only_hand_labelled": only_hand, "only_oracle": only_oracle, "detail": detail}


def totals(rows: list[dict]) -> dict:
    def listing(key: str) -> dict:
        reported = sum(r[key]["reported"] for r in rows)
        tp = sum(r[key]["true_positives"] for r in rows)
        positives = sum(r["labelled_affected"] for r in rows)
        return {"reported": reported, "true_positives": tp, "false_positives": reported - tp, "labelled_affected": positives,
                "precision": rate(tp, reported), "recall": rate(tp, positives)}

    def top3(path: tuple[str, ...]) -> dict:
        used = []
        for r in rows:
            node = r
            for p in path:
                node = node[p] if node else None
            if node and node["possible"]:
                used.append(node)
        hits, possible = sum(n["hits"] for n in used), sum(n["possible"] for n in used)
        return {"hits": hits, "possible": possible, "share": rate(hits, possible), "fixtures_counted": len(used)}

    return {
        "naive": listing("naive"), "depscan": listing("depscan"),
        "held_back": sum(r["depscan"]["held"] for r in rows), "held_back_truly_affected": sum(r["depscan"]["held_truly_affected"] for r in rows),
        "ranking": {k: top3(("ranking", k)) for k in ("cvss_only", "depscan", "depscan_without_kev_weight")},
        "reachability": {k: top3(("reachability", k)) for k in ("cvss_only", "depscan_no_project", "depscan_with_project")},
    }


def run_all() -> dict:
    cfg = load_config()
    fixtures = load_fixtures()
    bundles: dict[Path, DataBundle] = {}
    rows = [run_fixture(fx, bundles, cfg) for fx in fixtures]
    snaps = {str(fx.snapshot.relative_to(ROOT)).replace("\\", "/"): bundles[fx.snapshot].snapshots for fx in fixtures}
    return {
        "labels_verified_by_owner": labels_verified(),
        "snapshots": snaps,
        "top_n": TOP_N,
        "fixtures": rows,
        "totals": totals(rows),
        "hand_labels_vs_oracle": hand_vs_oracle(fixtures, bundles),
    }


# ------------------------------------------------------------------ the tables for docs/BENCHMARK.md
def pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.0f}%"


def share(m: dict | None) -> str:
    if not m or not m["possible"]:
        return "n/a"
    first = f", first at #{m['first_rank']}" if m["first_rank"] else ", not listed"
    return f"{m['hits']}/{m['possible']}{first}"


def render_tables(res: dict) -> str:
    rows, tot = res["fixtures"], res["totals"]
    lines = ["**Table 1. What gets reported** (precision = real findings among those reported; recall = real findings found; "
             "FP = reported but not truly affected)", "",
             "| fixture | deps | truly affected | naive reports | naive FP | naive precision | depscan reports | depscan FP | depscan precision | depscan recall | held back (of which truly affected) |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        n, d = r["naive"], r["depscan"]
        lines.append(f"| {r['name']} | {r['dependencies']} | {r['labelled_affected']} | {n['reported']} | {n['false_positives']} | {pct(n['precision'])} "
                     f"| {d['reported']} | {d['false_positives']} | {pct(d['precision'])} | {pct(d['recall'])} | {d['held']} ({d['held_truly_affected']}) |")
    n, d = tot["naive"], tot["depscan"]
    lines.append(f"| **all fixtures** | | **{n['labelled_affected']}** | **{n['reported']}** | **{n['false_positives']}** | **{pct(n['precision'])}** "
                 f"| **{d['reported']}** | **{d['false_positives']}** | **{pct(d['precision'])}** | **{pct(d['recall'])}** "
                 f"| **{tot['held_back']} ({tot['held_back_truly_affected']})** |")
    lines += ["", f"**Table 2. Are the known-exploited findings near the top?** (exploited = truly affected and listed in CISA KEV; "
              f"cell = how many of them are in the top {res['top_n']} of the list, and the position of the first one)", "",
              "| fixture | exploited | CVSS-only | depscan | depscan without the KEV weight |", "|---|---|---|---|---|"]
    for r in rows:
        if not r["known_exploited_affected"]:
            continue
        k = r["ranking"]
        lines.append(f"| {r['name']} | {r['known_exploited_affected']} | {share(k['cvss_only'])} | {share(k['depscan'])} | {share(k['depscan_without_kev_weight'])} |")
    k = tot["ranking"]
    lines.append(f"| **all counted** | | **{share_total(k['cvss_only'])}** | **{share_total(k['depscan'])}** | **{share_total(k['depscan_without_kev_weight'])}** |")
    reach = [r for r in rows if r["reachability"]]
    if reach:
        lines += ["", f"**Table 3. Is what a web request can reach near the top?** (django-app fixture; reachable = truly affected and imported by "
                  f"code a URL route reaches, by the app's construction; cell = how many are in the top {res['top_n']})", "",
                  "| fixture | reachable | CVSS-only | depscan, no project folder | depscan, with the project folder |", "|---|---|---|---|---|"]
        for r in reach:
            x = r["reachability"]
            lines.append(f"| {r['name']} | {x['web_reachable_affected']} | {share(x['cvss_only'])} | {share(x['depscan_no_project'])} | {share(x['depscan_with_project'])} |")
            top = "; ".join(f"{t['package']} {t['id']} ({t['exposure'] or 'no exposure data'})" for t in x["top3_with_project"])
            lines += ["", f"depscan's top {res['top_n']} with the project folder ({r['name']}): {top}."]
    return "\n".join(lines) + "\n\n" + render_disagreements(res)


def render_disagreements(res: dict) -> str:
    lines = ["**Where depscan and the draft labels disagree** (every case; none is hidden)", ""]
    any_row = False
    for r in res["fixtures"]:
        d = r["disagreements"]
        for e in d["labelled_affected_but_not_reported"]:
            lines.append(f"- {r['name']}: `{e['package']}` {e['id']} is labelled affected but depscan {'held it back for checking' if e['status'] == 'held back' else 'did not report it'}.")
            any_row = True
        for e in d["reported_but_not_labelled_affected"]:
            lines.append(f"- {r['name']}: `{e['package']}` {e['id']} was reported by depscan but is not labelled affected.")
            any_row = True
    if not any_row:
        lines.append("- none")
    h = res["hand_labels_vs_oracle"]
    lines += ["", f"**Hand labels against the simple oracle** (the hand-written fixtures only): {h['agree']} advisories agree, "
              f"{h['only_hand_labelled']} are only in the hand labels, {h['only_oracle']} are only in the oracle's reading."]
    for d in h["detail"]:
        for k in d["only_hand"]:
            lines.append(f"- {d['fixture']}: {k[0]} {k[1]} is in the hand labels but not the oracle's reading.")
        for k in d["only_oracle"]:
            lines.append(f"- {d['fixture']}: {k[0]} {k[1]} is in the oracle's reading but not the hand labels.")
    return "\n".join(lines)


def share_total(t: dict) -> str:
    return f"{t['hits']}/{t['possible']} across {t['fixtures_counted']} fixtures ({pct(t['share'])})"
