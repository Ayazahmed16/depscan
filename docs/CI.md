# Using depscan in CI

depscan can make a build fail when a scan finds something that needs attention. It only sets an exit status. It never
changes a dependency file, and it is your CI system, not depscan, that blocks a merge or a deploy.

```
python -m depscan scan . --offline --fail-on fix_now
```

## Exit status

| status | meaning |
|---|---|
| 0 | the scan ran and no finding trips the gate (or `--fail-on` was not given) |
| 1 | the scan ran and at least one finding needs attention at the chosen level |
| 2 | the scan itself failed: missing data, unreadable file, bad `--out` |

Keep 1 and 2 apart in a script. A status of 2 is not "no findings", and a pass is not proof of safety.

## Levels

`--fail-on` takes the recommended action a finding must reach, or worse:

| level | fails when a finding is |
|---|---|
| `fix_now` | fix now |
| `verify_first` | fix now or verify first |
| `monitor` | fix now, verify first or monitor |
| `any` | anything at all |

Most teams start with `fix_now`: it triggers on high risk that is also believable (for example a KEV-listed vulnerability
in a pinned package), which is a short, actionable list.

## What does not count

- A finding a person marked **accept risk** or **false positive**, while that decision has not expired. The audit log keeps
  the decision, and an expired suppression counts again. Point the scan at the review database with `--review-db`.
  Without one, nothing is suppressed.
- A scan-report claim the advisory data contradicts (a likely false positive).

A **fix now** decision does not exempt a finding, because the work is still outstanding.

## What this repository runs

`.github/workflows/ci.yml` has three jobs. **python** runs the linter, the tests and `benchmark.py --check`. **frontend**
builds the console and runs the extension tests. **gate** is the live demonstration, on the benchmark fixtures that stand in
for test repositories:

- `benchmark/fixtures/py-web-old` must fail the gate with status exactly 1 (so a scan error does not pass as a failure);
- `benchmark/fixtures/clean-current` must pass.

The report is written to the job summary and uploaded as an artifact. All of it runs offline from the frozen snapshots in
the repository.

## Using it on your own repository

`docs/ci/depscan-github-workflow.yml` is a ready-made workflow. It checks out depscan next to your code, caches the
advisory snapshots (about 400 MB, roughly 10 minutes to download on a cache miss, refreshed weekly), scans the repository
root, publishes the report, and fails the build on exit status 1 or 2. It also runs weekly, because new vulnerabilities
appear when your code has not changed.

## Limits

- **The workflows have not been run on GitHub by the author.** The commands were run locally and the YAML parses, but the
  first real run may need small fixes.
- The gate reads the files in the folder you give it (a manifest and the lock files beside it), not every folder of a
  monorepo. Run one scan per project folder.
- Data is only as fresh as the cached snapshots. A scan warns when they are older than the configured limit.
- A passing gate means no finding at that level in the data and files given. **No findings does not prove a project is secure.**
