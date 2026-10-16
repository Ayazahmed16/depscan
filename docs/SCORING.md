# Scoring

All weights and thresholds live in [`config/scoring.yaml`](../config/scoring.yaml). Nothing about the
ranking is hidden in code. Change a number, rerun, and the ranking changes.

depscan uses **evidence-based prioritisation with uncertainty**. There is no machine learning. Every
score is a weighted sum of named factors, and the UI and report show each factor with its value,
weight and contribution.

This document covers the **risk score** (phase 3). The trust score is added in phase 5.

## 1. Risk score (0 to 100)

> How bad is this finding **if the advisory is real**?

```
risk = 100 × Σ ( weight_i × factor_i )        weights sum to 1, each factor is in [0, 1]
```

| Factor | Default weight | factor value (0 to 1) |
|---|---|---|
| `severity` | 0.30 | CVSS base score ÷ 10 |
| `known_exploited` | 0.20 | 1 if the CVE is in the CISA KEV catalog, else 0 |
| `exploit_likelihood` | 0.20 | EPSS probability ÷ `epss_cap` (0.5), capped at 1 |
| `criticality` | 0.15 | (direct 1.0, transitive 0.6) × (runtime 1.0, dev-only 0.3) |
| `fix_availability` | 0.05 | fix in same major 1.0, fix needs a major bump 0.6, no fix 0.0 |
| `exposure` | 0.10 | 1 if reachable from an app entry point, 0 if not (phase 7) |

**Severity source order** (first one available wins, and the source is shown):

1. NVD CVSS base score (v3.1, then v3.0, then v4.0, then v2).
2. The OSV advisory's CVSS v3 vector, converted to a score with the FIRST CVSS v3.x formula
   (`depscan/scoring/cvss.py`, tested against published example scores).
3. The CVSS score reported in the uploaded scan report.
4. The advisory's severity label (GitHub): LOW 0.25, MODERATE 0.50, HIGH 0.75, CRITICAL 0.95.
5. Nothing known: a neutral 0.50 is used, and the finding says "severity unknown".

**Dropped factors.** If a factor cannot be computed (exposure, when no Django project was analysed),
it is dropped and the other weights are renormalised to sum to 1. The finding carries a note saying so,
so a score without exposure is never silently compared as if it had it.

### Why these choices

- **Severity** is the standard, widely understood measure of impact. It is not enough alone, because most
  high-severity vulnerabilities are never exploited.
- **KEV** is direct evidence that attackers are using the vulnerability now. It carries the same weight as
  EPSS on its own, because KEV is a fact and EPSS is a prediction.
- **EPSS** estimates the chance of exploitation in the next 30 days. Its values are heavily skewed toward
  zero, so anything at or above `epss_cap` counts as fully likely, and small differences near zero stay small.
- **Criticality** captures "does this code run in production": a direct runtime dependency matters more than
  a transitive dev tool.
- **Fix availability** is an *actionability* factor with a small weight. A fix you can apply today makes a
  finding worth scheduling now. With no fix, the response is a mitigation or monitoring, not a patch.
  A fix that needs a major version bump is real but costs more, so it counts less. Someone who thinks
  "no fix means more risk" can raise this weight or flip the values in the config.
- **Exposure** raises findings whose package can be reached from a web route and lowers build-only or
  dev-only use.

### Tiers and next steps

Tiers are the same cut-offs drawn on the gauge: **critical ≥ 60**, **high ≥ 30**, else low.

Provisional next step (phase 3, from risk alone):

| Condition | Next step |
|---|---|
| match confidence is `uncertain` | `verify_first` |
| risk ≥ 60 | `fix_now` |
| risk ≥ 30 | `monitor` |
| otherwise | `no_action` |

Phase 5 refines this with trust: **high risk with low trust reads `verify_first`, not `fix_now`.**

## 2. Match confidence (separate from risk and trust)

Confidence says how sure we are that the **dependency version is affected**.

| Confidence | Meaning |
|---|---|
| `exact` | The file or report pins an exact version, and an advisory range or explicit version list includes it. |
| `probable` | The file only declares a range such as `>=1.2` or `^4.17.0`. We test its **lowest allowed version**. The installed version may differ. |
| `uncertain` | Every record that affirms the match was withdrawn, the version could not be compared, or a scan report claims a vulnerability that the advisory data does not confirm (or contradicts). |

Records from different sources are merged by alias (GHSA, CVE, PYSEC). If one source says a version is
affected and another says it is not, the match stays as strong as its best evidence. The disagreement is
written into the evidence and counted by the **trust** score in phase 5. It is not counted twice.

A withdrawn record next to live records is noted but does not weaken the match.

## 3. Recommendations

Recommendations are text. depscan never edits a manifest or installs anything.

- **Minimum fixed version:** the lowest `fixed` version in the matched advisory that is above the tested
  version. If the major version changes, the recommendation says it is a major bump and to check the
  changelog.
- **Package upgrade target:** one version per package, the highest of its findings' minimum fixes. It clears
  every finding that has a listed fix. For old packages this can be a large jump, so the per-finding
  minimums are shown too.
- **No fix listed:** the recommendation says so and suggests mitigation, an alternative, or monitoring. We never
  guess a version.

## 4. What these scores are not

- Not a measurement of real-world exploitation of your application.
- Not tuned or validated on a large dataset. The default weights are reasoned, documented starting points.
  The benchmark (phase 10) reports how this ranking performed on a small labelled set, and says so.
- Not a replacement for review. A person accepts, rejects or acts on every finding.

**No findings does not prove a project is secure.**
