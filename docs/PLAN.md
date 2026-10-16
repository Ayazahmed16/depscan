# Phase 0: Plan

Project: **depscan**, evidence-based prioritisation of vulnerable dependencies, with uncertainty.
Problem statement: Cybersecurity 3 (dependency vulnerability prioritisation). It must list findings with
evidence, rank them with documented factors, recommend actions, require human review, and never change
production dependencies.

## 1. Data sources (checked 2026-10-17 against the live endpoints)

| Source | What we take | Download location | Format (observed) |
|---|---|---|---|
| **OSV** | Affected ranges, fixed versions, aliases, published/modified, withdrawn | `https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip` (we use `PyPI` and `npm`). HTTP 200 for both; PyPI ~36 MB. | Zip of one JSON per advisory (OSV schema 1.x). `affected[].ranges[].events` holds `introduced` / `fixed`. `aliases` links GHSA to CVE. |
| **NVD** | CVSS base scores, vulnStatus (e.g. Rejected, Disputed tag), published / lastModified | **Official yearly feeds** (fast path): `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-<year>.json.gz` for 2002 to now, each with a `.meta` file holding the sha256 of the uncompressed JSON. Fallback: CVE API 2.0 `https://services.nvd.nist.gov/rest/json/cves/2.0` (rate limited). 409,137 CVEs today. | JSON in the same record format as the API. `cve` has `metrics` (cvssMetricV40 / V31 / V30 / V2), `vulnStatus`, `cveTags` (objects holding a `tags` list), `configurations`, `lastModified`. |
| **CISA KEV** | Known-exploited flag and `dateAdded` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (1,748 entries, catalogVersion 2026.10.16) | JSON: `vulnerabilities[]` with `cveID`, `dateAdded`, `dueDate`, `knownRansomwareCampaignUse`, `cwes`. |
| **EPSS** | Exploit probability and percentile | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (old `epss.cyentia.com` URL redirects here). Historical days: `.../epss_scores-YYYY-MM-DD.csv.gz` (HTTP 200 for 2025-01-01). | gz CSV. First line is a `#model_version:...,score_date:...` comment, then `cve,epss,percentile`. |

Notes that change the design:
- **NVD is large, so we do not crawl its API.** The API allows about 5 requests per 30 seconds without a key; a full crawl was heading for hours (measured: about 98k of 409k records after roughly 1.5 hours). The official yearly feeds download the same data with no rate limit in about 6 minutes (measured, 25 files). `fetch_data.py` verifies each file against its `.meta` sha256, streams it with `ijson`, keeps only CVEs that are aliases of OSV records we hold, and re-downloads a year only when its `.meta` changes. NVD files a CVE under the year it was *published*, so every feed from 2002 to now is read. The API crawl remains as `--nvd-method api`.
- **EPSS is now hosted by Empirical Security**, not FIRST's own host. FIRST remains the standard's owner; we cite both.
- NVD records also carry `cisaExploitAdd`, but the CISA KEV feed (`dateAdded`) is the source of truth for KEV.
- OSV `all.zip` per ecosystem includes withdrawn advisories (they carry a `withdrawn` timestamp). We keep them, because withdrawn status is a trust signal.
- All downloads go in `data/` (git-ignored) with a `manifest.json` recording each snapshot's fetch time, source URL, byte size and SHA-256. The UI footer shows these dates.

## 2. Repo layout

```
depscan/
  depscan/               Python package (the core)
    data/                snapshot loaders (OSV, NVD, KEV, EPSS)
    parsers/             requirements.txt, package.json, Dependency-Check JSON
    matcher/             version ranges (PEP 440, semver) and match evidence
    scoring/             risk, trust, recommendations
    graph/               Django import-level exposure graph (ast)
    review/              reviewer decisions + audit log (local SQLite or JSONL)
    history/             dated snapshots, watchlist
    api/                 FastAPI app, serves frontend/dist
  scripts/fetch_data.py  the only code that uses the network
  config/scoring.yaml    all weights and thresholds
  docs/                  PLAN.md, SCORING.md, ARCHITECTURE.md, DEMO.md
  tests/                 pytest, plus tests/fixtures/
  data/                  cached snapshots (git-ignored)
  frontend/              React app (done)
```

Tooling: Python 3.14 (installed), `packaging`, `PyYAML`, `fastapi`, `uvicorn`, `python-multipart`, `networkx`, `pytest`. Node for the frontend only.

## 3. Assumptions

1. Ecosystems: **PyPI, npm and Go** for matching (see `depscan/ecosystems.py`); the exposure graph is **Python/Django only**.
2. Version matching uses OSV ranges (`ECOSYSTEM` for PyPI via PEP 440, `SEMVER` for npm and Go). `GIT` ranges are not used for matching but their fix commits count as "a fix exists" evidence.
3. An exact version (a `==` pin, a lock file, or go.mod) gives a **confirmed** match. A range (`>=1.2`) is resolved against the package registry and tested at its lowest and newest satisfying version: **likely** or **possible**. If the registry is unreachable it falls back to the lowest version only: **probable**. See SCORING.md section 2.
4. Transitive dependencies are only known from a scan report or a lock file. A bare `requirements.txt` yields direct dependencies only, and the report says so.
5. "Fix availability" comes from OSV `fixed` events. If none exists the fix is shown as unknown, and trust drops. We never guess a version.
6. Runtime vs dev: `requirements-dev*.txt` and `devDependencies` are dev; everything else is runtime.
7. The frontend's API contract (`frontend/src/lib/types.ts`) is the target for the backend's JSON.
8. No ML. Scores are weighted sums with weights in `config/scoring.yaml`.
9. Sample and benchmark labels are marked unverified until the project owner confirms them.

## 4. Risks and mitigations

| Risk | Mitigation |
|---|---|
| NVD download is slow or blocked | Official yearly feeds (about 6 min, checksum-verified, incremental refresh); API crawl is only a fallback. |
| Large OSV zips make loading slow | Build a compact on-disk index (JSON by package name) on first load. |
| npm semver edge cases (prereleases, `x` ranges) | Small tested semver module; unknown syntax is reported as "uncertain", never silently matched. |
| Disagreement between sources | Treated as data: shown as a trust signal, not hidden. |
| Time | Cut order: temporal view (phase 8), then simplify the graph (phase 7). Phases 1 to 6 and the console come first. |
| Snapshot goes stale | Footer shows each snapshot date; trust includes advisory freshness. |

## 5. Definition of done per phase

Tests pass, a commit is made, and a short summary lists what works, what is rough, and the assumptions made.
