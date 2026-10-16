"""Command line: python -m depscan scan requirements.txt [--out report.html|report.md|result.json]

Reads the file, never changes it, and works offline from the cached snapshots in ./data.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .pipeline import DEFAULT_DATA_DIR, DataBundle, scan_bytes
from .report import render_html, render_markdown


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="depscan")
    sub = ap.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan", help="scan a dependency file or scan report (read-only)")
    scan.add_argument("file", type=Path)
    scan.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    scan.add_argument("--out", type=Path, help=".html, .md or .json; default prints Markdown")
    args = ap.parse_args(argv)

    try:
        bundle = DataBundle(args.data_dir)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    result = scan_bytes(args.file.name, args.file.read_bytes(), bundle)  # read_bytes: input is never written
    if args.out is None:
        print(render_markdown(result))
    else:
        text = {".html": render_html, ".md": render_markdown, ".json": lambda r: json.dumps(r, indent=2)}.get(args.out.suffix)
        if text is None:
            print("error: --out must end in .html, .md or .json", file=sys.stderr)
            return 2
        args.out.write_text(text(result), "utf-8")
        print(f"wrote {args.out} ({len(result['findings'])} findings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
