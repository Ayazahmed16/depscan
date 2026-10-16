# depscan

Evidence-based prioritisation of vulnerable dependencies, with uncertainty.

depscan reads a dependency file, lock file or scan report, lists the vulnerabilities that might affect the project with
the evidence for each, ranks them with documented, configurable factors, says how far to trust each finding, and
recommends a next step. **A person decides. depscan never changes your dependency files, installs anything, or runs your
code.**

> **No findings does not prove a project is secure.**

Built for the Cybersecurity 3 hackathon problem (dependency vulnerability prioritisation). Python 3, open source, no
machine learning, runs fully offline from cached snapshots.

## Quick start

```
python -m venv .venv
.venv\Scripts\activate                  # Windows   (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
python scripts/fetch_data.py            # one-off download into ./data (about 10 minutes, no API key)
python -m depscan scan mock/requirements.txt --offline
```

The web console:

```
cd frontend && npm install && npm run build && cd ..
python -m depscan serve --offline       # then open http://127.0.0.1:8000/  (console: /app)
```

Upload `mock/requirements.txt` (a ready-made input with old, vulnerable pins) or `mock/django_app.zip` (to see the
exposure graph). Local only: there is no login, so do not expose the server to a network.

## What it does

**Input:** `requirements.txt`, `package.json`, `package-lock.json`, `yarn.lock`, `poetry.lock`, `Pipfile.lock`, `go.mod`,
`go.sum`, an OWASP Dependency-Check JSON report, or a zip of a Django project. A lock file beside a manifest is found
automatically and beats a version range.

**Output, per finding:** the advisory and its evidence (affected ranges, dates, links), a match confidence, a **risk**
score (how bad if real) with every factor, a **trust** score (should we believe it) with every signal, the minimum fixed
version and whether it is a major bump, a recommended action (*fix now*, *verify first*, *monitor*, *no action*), how a
web request can reach the package (Django), a dated history, and the reviewer's decision. As a console, a Markdown/HTML
report, JSON, or editor squiggles.

| Requirement | Where |
|---|---|
| Parse manifests and scan reports | `depscan/parsers/` |
| Match against cached advisories, with confidence and evidence | `depscan/matcher/`, `depscan/data/` |
| Documented, configurable risk factors | `config/scoring.yaml`, [docs/SCORING.md](docs/SCORING.md) |
| Recommendations, minimum fix, major bump | `depscan/scoring/recommend.py` |
| Human review, audit log, expiring suppressions | `depscan/review/`, [docs/REVIEW.md](docs/REVIEW.md) |
| Trust layer | `depscan/scoring/trust.py` |
| Django exposure graph | `depscan/graph/`, [docs/EXPOSURE.md](docs/EXPOSURE.md) |
| Timeline and watchlist from real dates | `depscan/temporal.py` |
| Adjustable weights | `GET/PUT /api/config/weights`, the console |
| "No findings does not prove a project is secure." | footer of the console, every report, `/api/meta` |
| Tested on a small known sample | `tests/sample/`, `tests/test_known_sample.py` |
| Benchmark | [docs/BENCHMARK.md](docs/BENCHMARK.md) (labels need manual verification) |

## Three ways to use it

**Command line**

```
python -m depscan scan path/to/requirements.txt
python -m depscan scan path/to/project --out report.html        # a folder: known files are picked up
python -m depscan scan package.json package-lock.json go.mod    # several files
python -m depscan scan path/to/django_project                   # a folder with manage.py also gets the exposure analysis
python -m depscan scan requirements.txt --offline               # no network at all
python -m depscan review result.json --list                     # record a decision about a finding
python -m depscan audit --verify                                # check the audit log has not been altered
```

**Web console** (`python -m depscan serve`): upload files or a project zip; tabs for findings, exposure graph, timeline and
review log; a weights editor that re-scores the scan. The API is in [docs/CONTRACT.md](docs/CONTRACT.md).

**VS Code** (`vscode-extension/`): a read-only client over the command line, with Problems-panel squiggles on the
declaring line, a findings tree, a details page and review actions. See [vscode-extension/README.md](vscode-extension/README.md).

## How it ranks, in one paragraph

Risk is a weighted sum of severity (CVSS), known exploited (CISA KEV), exploit likelihood (EPSS), how the package is used
(direct or transitive, runtime or dev), fix availability and exposure. Trust starts at 40 and adds or subtracts points for
independent sources, agreement between them, withdrawn or disputed status, freshness, whether a fixed release exists,
and how sure the match is. High risk with low trust reads *verify first*, not *fix now*. Every number and the reasoning
behind it is in [docs/SCORING.md](docs/SCORING.md); the weights are reasoned defaults, not fitted values.

## Safety guarantees

- Files you give it are only read. Nothing is written to your project, and no package is installed.
- Project code is parsed with `ast`, never imported or executed. An uploaded zip is unpacked to a temporary folder with
  zip-slip, size and file-count limits, and only `.py` files and manifests are extracted.
- Network use is limited to `scripts/fetch_data.py` and two optional, cached lookups (package registries for version
  ranges, and OSV.dev for an ecosystem with no local index). Downloads are hash-checked and written atomically.
- A decision never changes a score, and a suppression must expire. The audit log is append-only (enforced by database
  triggers) and hash-chained.

## Testing

`pytest` runs 400+ tests offline (`ruff check .` for lint, `coverage run -m pytest` for coverage). They include the known
sample with written-down expected rankings, an API contract test against the frontend's `types.ts`, upload-safety tests,
and mutation checks on the scoring, review, exposure, server and benchmark logic. `python scripts/benchmark.py --check`
confirms the benchmark results are current.

The benchmark (9 frozen fixtures) compares depscan with name-only matching and CVSS-only ranking: see
[docs/BENCHMARK.md](docs/BENCHMARK.md) for the table, how the numbers are defined, and the limits. **Its labels are drafts
that need manual verification by the project owner, and it does not guarantee real-world performance.**

## Layout

```
depscan/            the library: parsers, matcher, scoring, graph, review, temporal, server, CLI
config/scoring.yaml every weight and threshold
scripts/            fetch_data.py (the only feed downloader), benchmark and snapshot scripts
frontend/           React console and landing page (built into frontend/dist, served by the backend)
vscode-extension/   the editor client
tests/              pytest, with a frozen known sample in tests/sample
benchmark/          benchmark fixtures, frozen data, labels and results
docs/               PLAN, SCORING, REVIEW, EXPOSURE, CONTRACT, BENCHMARK, ARCHITECTURE, DEMO
mock/               ready-made inputs for trying the tool
```

Docs: [ARCHITECTURE](docs/ARCHITECTURE.md) (two pages) · [DEMO](docs/DEMO.md) (the under-2-minute script) ·
[PLAN](docs/PLAN.md) (data sources and design) · [SCORING](docs/SCORING.md) · [REVIEW](docs/REVIEW.md) ·
[EXPOSURE](docs/EXPOSURE.md) · [CONTRACT](docs/CONTRACT.md) · [BENCHMARK](docs/BENCHMARK.md)

## Assumptions and limits, stated plainly

What is true today:

- **Ecosystems: PyPI, npm and Go.** Their advisories come from the OSV bulk snapshot, which works fully offline. Any other
  ecosystem OSV knows can be looked up through the OSV.dev API (cached), but depscan must also know how to **order that
  ecosystem's versions**. Ecosystems that order like semver need one row in `depscan/ecosystems.py` plus one manifest
  parser; Maven, NuGet, Debian and similar need their own version comparator first, and are not supported.
- **Exact versions are `confirmed`:** a lock file, a `==` pin, an exact `package.json` version, or `go.mod`. Ranges are
  resolved against the real registry (skipping pre-releases and yanked releases) and tested at the newest and the lowest
  allowed version: `likely` or `possible`. With no registry access, only the lowest is tested: `probable`.
- **Confidence order:** `confirmed > likely > possible > probable`, and `uncertain` below those.
- Direct vs dev-only comes from the manifest. A lock file alone cannot always say, and the report says when it is guessing.
- "Fix available" comes from OSV `fixed` events. depscan never guesses a version.
- Scores are transparent weighted sums with no machine learning; the weights and trust points are reasoned, not tuned.

Limits:

- **Registry lookups need the network.** Without a cache or connection, ranges fall back to `probable`, and an OSV.dev
  outage for an API-only ecosystem is reported as "not checked", never as clean.
- **`likely` is not proof,** and the newest satisfying release is not necessarily what you have installed.
- **`go.sum` can include versions no longer built:** supply `go.mod` as well. The Go standard library and toolchain are not
  scanned, and `replace` directives are only flagged.
- **yarn.lock and Pipfile.lock do not say which packages are direct:** give the manifest too.
- **The Dependency-Check JSON layout is unverified** against a real report (`depscan/parsers/depcheck.py`). yarn, poetry and
  Pipfile parsing were tested on small synthetic inputs, not real lock files.
- The trust score is a **heuristic about the advisory data**, not about whether the vulnerable code is reachable.
- The exposure graph is **Python/Django only and import-level only** ([docs/EXPOSURE.md](docs/EXPOSURE.md)); transitive
  links need a `poetry.lock`. It has been run on a small hand-written app, not on real Django projects.
- History uses only dates the sources provide: advisory published/modified, the KEV date added, and the cached EPSS
  files. Nothing is simulated.
- Reviewer names are typed in, not authenticated, and the audit chain is tamper-*evident*, not tamper-proof.
- The web server keeps one scan in memory and is single-user.
- **Benchmark:** small, hand-picked, labels unverified, two selections made so a metric is defined, and part of the result
  is circular (KEV is an input to the score). Read the limits in [docs/BENCHMARK.md](docs/BENCHMARK.md) before quoting a number.

## Still needs the project owner

- Verify the benchmark labels (`tests/sample/labels.yaml`, `benchmark/labels.yaml`) and set `verified_by_owner: true`.
- Check the parser against a real OWASP Dependency-Check report.
- Try the exposure analysis on a real Django project.
