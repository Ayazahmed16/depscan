"""Command line.

    python -m depscan scan requirements.txt [more files or a folder] [--out report.html|report.md|result.json]
    python -m depscan review result.json --list
    python -m depscan review result.json KEY accept_risk --reviewer "Ana" --note "why" --expires 2030-01-31
    python -m depscan audit [--verify]
    python -m depscan serve [--port 8000] [--offline]

`scan` reads files and never changes them. `review` records a person's decision about a finding; it never changes
dependency files either. Everything works offline from the cached snapshots in ./data.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .pipeline import DEFAULT_DATA_DIR, DEFAULT_REVIEW_DB, DataBundle, collect_files, scan_files
from .registry import Registry
from .report import REVIEW_LABEL, render_html, render_markdown
from .review import DECISIONS, ReviewError, ReviewStore
from .scoring.config import load_config


def _store_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("--review-db", type=Path, default=DEFAULT_REVIEW_DB, help="where reviewer decisions and the audit log are kept")
    p.add_argument("--project", default=None, help="decisions are kept per project (default: the project of the scan, else 'default')")


def cmd_scan(args) -> int:
    try:
        bundle = DataBundle(args.data_dir, Registry(args.data_dir, offline=args.offline), osv_api=True, offline=args.offline)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    store = ReviewStore(args.review_db) if args.review_db.exists() else None  # a scan alone never creates review state
    project_dir = args.project_dir or next((p for p in args.files if p.is_dir() and (p / "manage.py").exists()), None)
    result = scan_files(collect_files(args.files), bundle, review_store=store, project=args.project or "default", project_dir=project_dir)
    if args.out is None:
        print(render_markdown(result))
        return 0
    text = {".html": render_html, ".md": render_markdown, ".json": lambda r: json.dumps(r, indent=2)}.get(args.out.suffix)
    if text is None:
        print("error: --out must end in .html, .md or .json", file=sys.stderr)
        return 2
    args.out.write_text(text(result), "utf-8")
    print(f"wrote {args.out} ({len(result['findings'])} findings)")
    return 0


def cmd_review(args) -> int:
    result = json.loads(args.result.read_text("utf-8"))
    project = args.project or result.get("project", "default")
    findings = {f["key"]: f for f in result["findings"]}
    if args.list:
        for f in result["findings"]:
            print(f"{REVIEW_LABEL[f.get('review_status', 'pending')]:24} risk {f['risk']['score']:3.0f} trust {f['trust']['score']:3.0f}  {f['key']}")
        return 0
    if not args.key or not args.decision:
        print("error: give a KEY and a DECISION (or --list to see the keys)", file=sys.stderr)
        return 2
    if args.key not in findings:
        print(f"error: no finding with key {args.key!r} in {args.result.name} (use --list)", file=sys.stderr)
        return 2
    cfg = load_config()
    store = ReviewStore(args.review_db)
    try:
        if args.decision == "revoke":
            store.revoke(project, args.key, args.note or "", args.reviewer or "", cfg=cfg)
            print(f"revoked: {args.key} needs review again")
        else:
            rec = store.record(project, args.key, args.decision, args.note or "", args.reviewer or "", args.expires,
                               cfg=cfg, risk_score=findings[args.key]["risk"]["score"])
            until = f" until {rec['expires']}" if rec["expires"] else ""
            print(f"recorded: {REVIEW_LABEL[args.decision]} by {rec['reviewer']}{until}: {args.key}")
    except ReviewError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


def cmd_audit(args) -> int:
    if not args.review_db.exists():
        print("no review state yet: nothing has been decided")
        return 0
    store = ReviewStore(args.review_db)
    if args.verify:
        ok, bad, n = store.verify_audit()
        print(f"audit log intact: {n} entries" if ok else f"AUDIT LOG BROKEN at entry {bad} (checked {n} before it)")
        return 0 if ok else 1
    for e in store.audit(args.project, args.key, args.limit):
        until = f" until {e['expires']}" if e["expires"] else ""
        print(f"#{e['id']:<4} {e['at']}  {e['action']:15} {e['reviewer']:12} {e['key']}{until}\n      {e['note']}")
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    from .server import create_app
    app = create_app(args.data_dir, args.review_db, offline=args.offline)
    print(f"depscan console: http://{args.host}:{args.port}/app   (Ctrl+C to stop)")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="depscan")
    sub = ap.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="scan a dependency file or scan report (read-only)")
    scan.add_argument("files", type=Path, nargs="+", help="dependency files or folders; lock files beside a manifest are found automatically")
    scan.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    scan.add_argument("--offline", action="store_true", help="never use the network: version ranges use cached registry data or fall back to the lowest allowed version")
    scan.add_argument("--out", type=Path, help=".html, .md or .json; default prints Markdown")
    scan.add_argument("--project-dir", type=Path, help="a Django project folder: finds which vulnerable packages its URL routes can reach (a folder given above that holds manage.py is used automatically)")
    _store_arg(scan)

    review = sub.add_parser("review", help="record a person's decision about a finding (never changes dependency files)")
    review.add_argument("result", type=Path, help="a result.json written by `scan --out result.json`")
    review.add_argument("key", nargs="?", help="finding key, see --list")
    review.add_argument("decision", nargs="?", choices=[*DECISIONS, "revoke"])
    review.add_argument("--reviewer", help="who is deciding (typed in, not authenticated)")
    review.add_argument("--note", help="the reason (required)")
    review.add_argument("--expires", help="YYYY-MM-DD, required for accept_risk and false_positive")
    review.add_argument("--list", action="store_true", help="list the findings with their keys and review status")
    _store_arg(review)

    audit = sub.add_parser("audit", help="show the audit log, or check that it has not been tampered with")
    audit.add_argument("--key")
    audit.add_argument("--limit", type=int, default=50)
    audit.add_argument("--verify", action="store_true", help="recompute the hash chain; exit 1 if it is broken")
    _store_arg(audit)

    serve = sub.add_parser("serve", help="run the web console (reads uploads, never changes them)")
    serve.add_argument("--host", default="127.0.0.1", help="local only by default: there is no login")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    serve.add_argument("--offline", action="store_true", help="never use the network")
    _store_arg(serve)

    args = ap.parse_args(argv)
    return {"scan": cmd_scan, "review": cmd_review, "audit": cmd_audit, "serve": cmd_serve}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
