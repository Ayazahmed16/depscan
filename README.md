# depscan

Evidence-based prioritisation of vulnerable dependencies, with uncertainty.
It reads a dependency file or scan report, lists the vulnerabilities that match with the evidence for
each, ranks them with documented factors, and recommends next steps. **A person decides: depscan never
changes your dependency files or installs anything.**

> **No findings does not prove a project is secure.**

This README is a first version (setup, usage, assumptions). The full README, architecture doc and demo
script come in phase 11.

## Setup

```
python -m venv .venv
.venv\Scripts\activate            # Windows   (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
python scripts/fetch_data.py      # one-off download of OSV, KEV, EPSS, NVD snapshots into ./data
```

NVD is slow without a free API key (set `NVD_API_KEY`); the other sources take a few minutes.

## Use

```
python -m depscan scan path/to/requirements.txt
python -m depscan scan path/to/project --out report.html     # a folder: known files are picked up
python -m depscan scan package.json package-lock.json go.mod # several files
python -m depscan scan requirements.txt --offline            # no network at all
```

A lock file beside the manifest (`package-lock.json`, `yarn.lock`, `Pipfile.lock`, `poetry.lock`) is found
automatically. Supported inputs: `requirements.txt`, `package.json`, `package-lock.json`, `yarn.lock`,
`poetry.lock`, `Pipfile.lock`, `go.mod`, `go.sum`, and OWASP Dependency-Check JSON.

Known test sample: `tests/sample/` (real, frozen advisory records) with expected results in `tests/test_known_sample.py`
and labels in `tests/sample/labels.yaml` (**unverified, needs the owner's check**).

Scoring: [docs/SCORING.md](docs/SCORING.md), weights in [config/scoring.yaml](config/scoring.yaml).
Plan and data sources: [docs/PLAN.md](docs/PLAN.md). Tests: `pytest`.

## Assumptions I made

What is true today:

- **Ecosystems: PyPI, npm and Go.** Their advisories come from the OSV bulk snapshot, which works fully offline.
  Any other ecosystem OSV knows can be looked up through the OSV.dev API (cached), but depscan must also
  know how to **order that ecosystem's versions**. Ecosystems that order like semver (Cargo, Hex, Pub, ...) need only
  one row in `depscan/ecosystems.py` plus one manifest parser. Maven, NuGet, Debian and similar need their own
  version comparator first. They are not supported.
- **Exact versions are `confirmed`:** a lock file, a `==` pin, an exact `package.json` version, or `go.mod`.
- **Ranges are resolved against the real registry** (PyPI JSON API, npm registry), skipping pre-releases and
  yanked releases, and tested at both the newest satisfying and the lowest allowed version: `likely` (both
  affected) or `possible` (one). If the registry cannot be reached the old behaviour applies: lowest version
  only, `probable`.
- **Confidence order:** `confirmed > likely > possible > probable`, and `uncertain` below those.
- Direct vs dev-only comes from the manifest (`devDependencies`, `requirements-dev*.txt`). A lock file alone
  cannot always say, and the report says when it is guessing.
- "Fix available" comes from OSV `fixed` events. We never guess a version.
- Scores are transparent weighted sums, with no machine learning. The weights are reasoned defaults, not tuned.

Remaining limits, honestly:

- **Registry lookups need the network.** Without a cache or connection ranges fall back to `probable`, and an
  OSV.dev outage for an API-only ecosystem is reported as "not checked", never as clean. The network is used only
  for these lookups and by `scripts/fetch_data.py`; everything else runs from the cached snapshots.
- **`likely` is not proof.** Both ends of a range being affected does not guarantee every version in between is.
  A lock file or scan report is the only way to `confirmed`.
- **The newest satisfying release is not necessarily what you have installed.** It is what a fresh install would
  get today; an older install may differ.
- **`go.sum` can include versions no longer built.** Supply `go.mod` as well; it takes precedence.
- **Go: the standard library and toolchain version are not scanned**, and `replace` directives are only flagged.
- **yarn.lock and Pipfile.lock do not say which packages are direct.** Give depscan the manifest too for that.
- **The Dependency-Check JSON layout is unverified** against a real report (see `depscan/parsers/depcheck.py`).
- The trust score, reviewer actions, exposure graph (Python/Django, import level only), timeline and the web
  API are planned phases, not built yet. The frontend in `frontend/` is built against the planned API and
  has not been connected to a backend.
- Benchmark numbers do not exist yet. When they do, they come from a real run on a small labelled set and
  will not guarantee real-world performance.
