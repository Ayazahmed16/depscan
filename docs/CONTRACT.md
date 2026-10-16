# API contract

The frontend is the source of truth: `frontend/src/lib/types.ts` (shapes) and `frontend/src/lib/api.ts` (calls).
`tests/test_api_contract.py` parses `types.ts` and checks real scan output against it; `tests/test_server.py` exercises
every endpoint. Rules: fields are only ever added, never renamed or retyped; missing data is `null` or `[]`, never a 500;
errors are a plain-text message with a 4xx/5xx status (the console shows the text).

| Method and path | Body | Returns |
|---|---|---|
| `GET /api/health` | | `{status, version, snapshots:{osv,nvd,kev,epss}}` (snapshot dates, `null` if missing) |
| `GET /api/meta` | | `{version, disclaimer, snapshots, limitations:{data,matching,trust,exposure,temporal,review}, stale_days}` |
| `POST /api/scan` | multipart `files` (1-20): dependency files, a scan report, or a `.zip` of a project | the scan result (below); also remembered as the current scan |
| `GET /api/findings` | | the current scan result, or `null` |
| `GET /api/graph` | | the exposure graph (`nodes`, `links`, `limitation`, `stats`) or `null` |
| `GET /api/watchlist` | | `[{key, package, id, risk, reason}]` |
| `GET /api/audit` | | audit entries, newest first |
| `POST /api/review` | `{key, decision, note, reviewer, expires}` | the stored record; 400 with the reason if a rule is broken |
| `POST /api/review/revoke` | `{key, note, reviewer}` | `{ok:true}` |
| `POST /api/reset` | | `{ok:true}` (forgets the scan; reviewer decisions are kept) |
| `GET /api/config/weights` | | `{weights, defaults, customised}` |
| `PUT /api/config/weights` | `{weights:{severity,known_exploited,exploit_likelihood,criticality,fix_availability,exposure}}` | same, plus `rescored` |
| `DELETE /api/config/weights` | | back to the defaults, same shape |

**Scan result:** `{source, scanned_at, kind, dependencies_read, warnings, snapshots, findings[], project, graph, dependency_graph, review_summary, package_actions}`.
`dependency_graph` is `{nodes[], links[], stats, limitation}`; nodes are `{id, label, name, version, scope, kind, depth, findings, max_risk}`.

**Finding:** `key, id, aliases, package, version, ecosystem, direct, scope, summary, cvss, epss, kev, fixed_version, major_bump,
match{confidence, evidence[]}, risk{score, factors[]}, trust{score, signals[], level}, action, claim_status, recommendation,
exposure, advisories[], history[], watch, review, review_status`.
`dependency_path` is `{known, direct, path[], path_labels[], direct_parents[], note}`: the route from a direct dependency to this package (see `docs/DEPENDENCIES.md`).
`advisories[]` is the evidence: `{id, aliases, summary, published, modified, withdrawn, affected_ranges[], affected_versions_listed, links[{label,url}]}`.
`history[]` is `{date, risk, epss, event, simulated}`, real dates only (`simulated` is always `false`).

**Differences from the original handoff brief's default API** (the frontend wins where they disagree): one current scan
instead of scan ids (`/api/findings`, not `/api/scans/{id}/findings`); flat `version`/`fixed_version`/`major_bump` instead of
`installed_version`/`fix{}`; `review` + `review_status`; `exposure{level, path, path_labels, imported_by}`; the snapshot
dates are in `/api/health` and `/api/meta`; the timeline and `watch` ride on each finding, with `/api/watchlist` as a list view.
