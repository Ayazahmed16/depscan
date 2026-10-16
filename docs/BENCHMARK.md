# Benchmark

**Status: provisional. The labels: needs manual verification by the project owner** (`verified_by_owner: false` in
`benchmark/labels.yaml` and `tests/sample/labels.yaml`). Every number below is produced by
`python scripts/benchmark.py --write` from frozen data; none was typed in by hand.

## What it answers

1. **What gets reported.** Against a scanner that reports every advisory whose package *name* matches, how many of the
   reported findings are real, and how many real findings are found?
2. **What comes first.** Against ranking by CVSS score alone, do the known-exploited findings (listed in CISA KEV)
   land in the top 3?
3. **What a web request can reach.** On the Django fixture, is code a URL route reaches near the top?

It does **not** answer how depscan performs on your project, or whether its scores predict real attacks.

## The three approaches compared

| name | what it does |
|---|---|
| **naive** | reports every advisory that mentions a package's name, whatever the version. For a scan report, every claim in it. It has no ranking, so it appears in Table 1 only. |
| **CVSS-only** | the same findings depscan reports, ranked by CVSS score alone (no EPSS, KEV, fix, criticality or exposure). It isolates what the ranking adds. |
| **depscan** | version-aware matching, the risk/trust ranking, and findings that need checking (uncertain match, unconfirmed or contradicted scanner claim) **held back** from the main list. Held-back findings are counted in Table 1 so the cost of that caution is visible. |

`depscan without the KEV weight` in Table 2 re-runs depscan with the `known_exploited` weight set to 0 (others
renormalised); see "Limits" for why.

## Fixtures (9)

Frozen data: `tests/sample/snapshot` (the first three) and `benchmark/snapshot`, extracted from the real feeds by
`scripts/make_benchmark_snapshot.py`. No NVD data is in either (severity comes from OSV CVSS vectors).

| fixture | what it is |
|---|---|
| known-sample | 6 packages: one KEV-listed, one withdrawn record, one name-only false positive, one clean package |
| known-sample-report | a Dependency-Check-style report with true, false-positive and unconfirmed claims |
| django-app | the hand-written Django app; which packages a URL route reaches is known by construction |
| py-web-old | a Python web stack pinned around 2018-2020 |
| py-kev-mix | a platform stack that deliberately includes every PyPI application dependency in the cache with a KEV-listed advisory |
| npm-old | 12 old exact npm pins |
| go-old | 6 old Go requirements |
| clean-current | pins at the highest fixed version any advisory names: a scanner should report almost nothing |
| boundary | pins equal to an advisory's fixed version: that advisory must not be reported |

Selection: popular packages at old versions, chosen before looking at depscan's output. **Two selections were made to
make a metric defined:** `py-kev-mix` and the `mongo-express`/`electron`/`x/net` pins exist because Table 2 needs
fixtures that contain known-exploited findings (without them most fixtures would have none).

## Labels (the part that needs you)

A label says which advisories truly affect a pinned version. There are two sources, both drafts:

- `tests/sample/labels.yaml` (known-sample, known-sample-report): written by the assistant by reading advisory ranges.
- `benchmark/labels.yaml` (the rest): written by `python scripts/benchmark.py --draft-labels` from `oracle_affected`, a
  second, deliberately simple implementation of the OSV range rules in `depscan/bench.py`.

Both read the same frozen advisory text, so a misreading of an advisory could be shared. The oracle is a cross-check on
depscan's version logic, **not independent ground truth**. Everything not listed as affected counts as not affected.

To verify: for each package/advisory in the label files, open `https://osv.dev/vulnerability/<id>`, check the affected
range against the pinned version, edit the file where you disagree, set `verified_by_owner: true`, and re-run
`python scripts/benchmark.py --write`. Until both files say `true`, the doc and `results.json` say provisional.

## Metrics, exactly

- **Reported** (depscan): findings that depscan's own data matched and whose match is not `uncertain`, in its own order.
  **Held back**: uncertain matches and scan-report claims that are unconfirmed or contradicted.
- **Truly affected**: labelled affected. **Precision** = truly affected among reported. **Recall** = truly affected that
  were reported. **FP** = reported and not labelled affected.
- Findings are grouped by alias (the CVE and its GHSA/PYSEC/GO ids are one issue).
- **Exploited**: truly affected and listed in CISA KEV in the frozen snapshot. **Top-3 share** = exploited findings
  in the first 3 of the list, divided by the smaller of 3 and the number of exploited findings. Fixtures with none are
  left out, and the totals say how many fixtures counted.
- **Reachable** (Table 3): truly affected and in a package that a URL route reaches by the app's construction.

## Results

<!-- BENCHMARK:START (generated by scripts/benchmark.py --write: do not edit by hand) -->

**Table 1. What gets reported** (precision = real findings among those reported; recall = real findings found; FP = reported but not truly affected)

| fixture | deps | truly affected | naive reports | naive FP | naive precision | depscan reports | depscan FP | depscan precision | depscan recall | held back (of which truly affected) |
|---|---|---|---|---|---|---|---|---|---|---|
| known-sample | 6 | 14 | 42 | 28 | 33% | 14 | 0 | 100% | 100% | 1 (0) |
| known-sample-report | 4 | 5 | 4 | 3 | 25% | 5 | 0 | 100% | 100% | 3 (0) |
| django-app | 7 | 14 | 42 | 28 | 33% | 14 | 0 | 100% | 100% | 1 (0) |
| py-web-old | 10 | 134 | 331 | 197 | 40% | 134 | 0 | 100% | 100% | 7 (0) |
| py-kev-mix | 10 | 240 | 435 | 195 | 55% | 237 | 0 | 100% | 99% | 4 (0) |
| npm-old | 12 | 123 | 215 | 92 | 57% | 123 | 0 | 100% | 100% | 4 (0) |
| go-old | 6 | 31 | 49 | 18 | 63% | 31 | 0 | 100% | 100% | 0 (0) |
| clean-current | 11 | 1 | 343 | 342 | 0% | 1 | 0 | 100% | 100% | 0 (0) |
| boundary | 8 | 68 | 323 | 255 | 21% | 68 | 0 | 100% | 100% | 1 (0) |
| **all fixtures** | | **630** | **1784** | **1158** | **35%** | **627** | **0** | **100%** | **100%** | **21 (0)** |

**Table 2. Are the known-exploited findings near the top?** (exploited = truly affected and listed in CISA KEV; cell = how many of them are in the top 3 of the list, and the position of the first one)

| fixture | exploited | CVSS-only | depscan | depscan without the KEV weight |
|---|---|---|---|---|
| known-sample | 1 | 0/1, first at #5 | 1/1, first at #1 | 1/1, first at #1 |
| django-app | 1 | 0/1, first at #5 | 1/1, first at #1 | 1/1, first at #1 |
| py-web-old | 1 | 0/1, first at #20 | 1/1, first at #1 | 1/1, first at #1 |
| py-kev-mix | 8 | 1/3, first at #3 | 3/3, first at #1 | 3/3, first at #1 |
| npm-old | 3 | 1/3, first at #1 | 3/3, first at #1 | 2/3, first at #1 |
| go-old | 1 | 0/1, first at #11 | 1/1, first at #1 | 1/1, first at #1 |
| boundary | 1 | 0/1, first at #10 | 1/1, first at #1 | 1/1, first at #1 |
| **all counted** | | **2/11 across 7 fixtures (18%)** | **11/11 across 7 fixtures (100%)** | **10/11 across 7 fixtures (91%)** |

**Table 3. Is what a web request can reach near the top?** (django-app fixture; reachable = truly affected and imported by code a URL route reaches, by the app's construction; cell = how many are in the top 3)

| fixture | reachable | CVSS-only | depscan, no project folder | depscan, with the project folder |
|---|---|---|---|---|
| django-app | 6 | 2/3, first at #2 | 1/3, first at #3 | 1/3, first at #3 |

depscan's top 3 with the project folder (django-app): pyspark CVE-2022-33891 (command); pyspark CVE-2023-32007 (command); pyyaml CVE-2020-14343 (web).

**Where depscan and the draft labels disagree** (every case; none is hidden)

- py-kev-mix: `apache-airflow` CVE-2024-32077 is labelled affected but depscan did not report it.
- py-kev-mix: `apache-airflow` CVE-2024-45498 is labelled affected but depscan did not report it.
- py-kev-mix: `apache-airflow` CVE-2025-54831 is labelled affected but depscan did not report it.

**Hand labels against the simple oracle** (the hand-written fixtures only): 19 advisories agree, 0 are only in the hand labels, 0 are only in the oracle's reading.

<!-- BENCHMARK:END -->

## How to read them, and the limits

- **Precision and recall measure version matching, not real-world danger.** The labels come from the same advisory
  text depscan reads. A high score means depscan applies the OSV range rules correctly (including the boundary,
  withdrawn-record and name-only cases), not that the findings are exploitable in your application.
- **The naive scanner is a strawman on purpose.** Real scanners check versions. It shows what matching by name costs,
  not how depscan compares with a good commercial or open-source scanner. That comparison has not been run.
- **Table 2 is partly circular.** KEV is an input to depscan's score (weight 0.20), so putting KEV-listed findings
  first is what it is built to do. The "without the KEV weight" column removes that direct input; EPSS still correlates
  with KEV, so it is not fully independent either. The fair reading is "depscan surfaces known-exploited findings as
  designed, and CVSS alone does not", not "depscan predicts exploitation".
- **Table 3 is a result against depscan.** With the project folder, depscan puts the two command-only `pyspark`
  findings (one KEV-listed, one with a 76% EPSS) ahead of the web-reachable ones, so its top 3 holds fewer reachable
  findings than CVSS-only. That follows from the weights: exposure is 0.10 and KEV plus EPSS are 0.40, by design.
  Exposure helps order findings that are otherwise close; it does not outvote a known-exploited one. One fixture, so
  it shows the behaviour, not a rate.
- **Disagreements are listed above, not hidden.** The three `apache-airflow` cases (CVE-2024-32077, CVE-2024-45498, CVE-2025-54831) each have a PYSEC record that
  says "introduced 0" up to the release before the fix, while the GHSA record for the same CVE says "introduced 2.9.0",
  "2.10.0" and "3.0.3" respectively (checked in the frozen data for all three). The oracle counts a finding
  as affected when any live record says so; depscan weighs the sources and did not report it. The GHSA record
  matches the vendor's published range, so the label is probably the over-claim. It is left as the rule produced it
  until the owner verifies.
- **Small and hand-picked.** 9 fixtures, 7 with an exploited finding (16 exploited findings in total, 11 top-3 slots to fill),
  all from one frozen date and mostly old pins. Confidence intervals would be wide; none are shown because no sampling was done.
- **Held-back findings cost nothing here** (none of the 21 is labelled affected), but that is a property of these labels
  and fixtures. A held-back finding can be a real one, which is why the main list never hides it from the console.
- Results are reproducible (`python scripts/benchmark.py --check`) but are **not a guarantee of real-world
  performance**.

## Reproduce

```
python scripts/benchmark.py                  # print the tables
python scripts/benchmark.py --write          # also refresh benchmark/results.json and the tables above
python scripts/benchmark.py --check          # exit 1 if either is out of date
python scripts/make_benchmark_snapshot.py    # re-freeze the data from ./data (then re-check the labels)
```
