# Architecture (two pages)

depscan answers one question: **of the vulnerabilities that might affect this project, which should a person look at
first, and how far should they trust each finding?** It recommends. It never changes a dependency file, installs a
package, or runs the project's code.

## 1. The shape

```
 dependency file / lock file / scan report / project zip
                         |
                  parsers/ (read-only)           requirements.txt, package.json, lock files, go.mod, Dependency-Check JSON
                         |
   registry.py (optional, cached) resolves ranges   <-- the only runtime network use, besides osv_api.py
                         |
 data/ snapshots ---> matcher/ ---> findings with evidence + match confidence
 (OSV, NVD, KEV, EPSS)    |
                          +--> scoring/risk.py     0-100, weighted factors (config/scoring.yaml)
                          +--> scoring/trust.py    0-100, 13 explainable signals
                          +--> scoring/recommend   next step from risk AND trust
                          +--> graph/              Django import-level exposure (ast, Python only)
                          +--> temporal.py         dated history + watchlist (real dates only)
                          +--> review/store.py     human decisions + hash-chained audit log (SQLite)
                          |
                    pipeline.py: one function, scan_files(), returns one JSON-able result
                          |
       +------------------+------------------+
   __main__.py          server.py          vscode-extension/
   CLI + reports     FastAPI + React        thin client over the CLI
```

One core library, three thin clients. Everything a client shows comes from the same result object, so the CLI report,
the web console and the editor squiggles cannot disagree.

## 2. Data and the offline rule

`scripts/fetch_data.py` is the only code that downloads feeds. It stores **OSV** advisories (per ecosystem), **NVD**
CVSS scores, the **CISA KEV** list and **EPSS** scores (the newest file plus dated history) under `data/`, each checked
against the publisher's hash and written atomically so a bad download never replaces a good snapshot. A scan reads
only those files, so the demo works with the network off. The snapshot dates are shown in the UI footer, and a scan warns
when the data is older than `data.stale_days`.

The two exceptions are optional and cached: registry lookups (to turn `>=1.2,<2` into real versions) and the OSV.dev
API for an ecosystem with no local index. Failure there is reported as "not checked", never as clean.

## 3. Matching and match confidence

OSV range events are evaluated with PEP 440 or semver, per source record. Records are grouped by alias so a GHSA, a
PYSEC and a CVE record are one finding, and each record's verdict is kept. A pinned or locked version is `confirmed`;
a range is tested at its newest and lowest allowed versions (`likely` / `possible`) or only the lowest (`probable`).
`uncertain` is used for a withdrawn record or a scan-report claim our data cannot confirm. Sources that disagree
lower the **trust** score, not the match confidence, so one disagreement is not counted twice.

## 4. Two scores, deliberately separate

- **Risk (0-100)** = how bad if real: a weighted sum of severity (CVSS), known exploited (KEV), exploit likelihood
  (EPSS), criticality (direct vs transitive, runtime vs dev), fix availability and exposure. Weights live in
  `config/scoring.yaml` and can be changed at run time through the API; an uncomputable factor is dropped and the rest
  renormalised. Every factor is returned with its weight and contribution. Formulas: `docs/SCORING.md`.
- **Trust (0-100)** = should we believe the finding: independent sources, whether their ranges agree, withdrawn or
  disputed status, freshness, whether a patched release really exists, match confidence. Every signal is shown with
  its points.
- **Action** comes from both: high risk with high trust is *fix now*; high risk with low trust is *verify first*.

No machine learning. The weights and trust points are reasoned defaults, not fitted values (stated everywhere they appear).

## 5. Exposure, history, review

- **Exposure** (`graph/`): for a Django project, `ast` reads imports and URL routes (never executing code) and builds a
  NetworkX graph from entry points (routes, middleware, startup, commands, tests) to modules to packages. A package gets
  the strongest level that reaches it. Import-level only, Python/Django only; unknown is `None`, not "safe".
- **History** (`temporal.py`): per-finding points from the advisory's published/modified dates, the KEV date added and
  every cached EPSS file, each point re-scored with only what was known then. Nothing is interpolated or simulated. The
  watchlist flags findings below the critical tier whose EPSS rose sharply or that entered KEV recently.
- **Review** (`review/`): *fix now*, *accept risk* and *false positive* need a name and a reason; the two suppressions
  must expire (30 days for critical-tier findings, else 180). Decisions never change a score; they are shown beside the
  finding, sort it lower, and stay visible. Every action is appended to an audit log that SQLite triggers make
  append-only, chained by SHA-256 so an edit is detectable (`audit --verify`).

## 6. Clients and API

`server.py` exposes the contract in `docs/CONTRACT.md` (the frontend's `types.ts` is the source of truth; a test checks
real output against it). Uploads are only read: a zip is unpacked into a temporary folder with zip-slip, size and count
limits, only `.py` files and manifests are extracted, and nothing is executed. The server is local-only with no login.
The React console (`frontend/`) has findings, exposure, timeline and review-log views plus a weights editor. The VS Code
extension runs the CLI and shows Problems-panel squiggles, a findings tree and review actions.

## 7. Why it is built this way

| Decision | Reason |
|---|---|
| A separate trust score | A scanner's top finding is often wrong or disputed; one number hides that. |
| Held-back findings, never dropped | Uncertain matches and scanner claims we cannot confirm stay visible, flagged. |
| KEV above CVSS in the weights | A vulnerability known to be exploited matters more than a higher theoretical score. |
| Reviewer decisions do not re-score | Hiding or rescoring on opinion would make the ranking unauditable. |
| SQLite + triggers for the audit log | Dependency-free, cross-platform, append-only enforced below the application. |
| Static analysis only | The tool must be safe to point at untrusted code. |

## 8. Limits (the short list; each doc has the long one)

Exposure is import-level and Django-only. The trust and exposure points are reasoned, not fitted. Reviewer names are not
authenticated and the audit chain is tamper-evident, not tamper-proof. History has only the dates the sources give.
Dependency-Check JSON parsing was built from an assumed layout and is unverified. The benchmark is small, its labels
are drafts that need the owner's verification, and it does not predict real-world performance (`docs/BENCHMARK.md`).

**No findings does not prove a project is secure.**
