# depscan

depscan takes a dependency file or a scan report and tells you which known vulnerabilities in it deserve attention
first, and how much to trust each one. It lists findings with their evidence, ranks them using factors you can read and
change, and recommends a next step. A person makes the decision. depscan never edits your dependency files, installs
packages, or runs your code.

> No findings does not prove a project is secure.

It was built for the Cybersecurity 3 hackathon problem on dependency vulnerability prioritisation. It is written in
Python, uses no machine learning, and runs offline from cached copies of the public vulnerability feeds.

## Input and output

It reads `requirements.txt`, `package.json`, `package-lock.json`, `yarn.lock`, `poetry.lock`, `Pipfile.lock`, `go.mod`,
`go.sum` and OWASP Dependency-Check JSON. A zip of a Django project adds an exposure analysis.

For each finding it reports the advisory and the reason it matched, a risk score and a trust score with every factor
shown, the lowest fixed version and whether reaching it needs a major upgrade, a recommended action (fix now, verify
first, monitor, no action), the history of the finding, and any decision a reviewer has recorded. Results come as a web
console, a Markdown or HTML report, JSON, or squiggles in VS Code.

In CI, `scan --fail-on fix_now` exits with status 1 when a finding needs attention, so a build can fail on it. Accepted
risks that have not expired do not count. See `docs/CI.md`.

## How it decides

**Risk** is a weighted sum of severity (CVSS), whether the vulnerability is known to be exploited (CISA KEV), exploit
probability (EPSS), how the package is used, whether a fix exists, and whether a web request can reach it. The weights
are in `config/scoring.yaml` and can be changed in the console.

**Trust** is a separate score for whether the finding itself is believable: how many independent databases list it,
whether their version ranges agree, whether it was withdrawn or disputed, how fresh it is, and whether the fixed release
exists. A high-risk finding with low trust is marked verify first, not fix now.

**Exposure** applies to Django projects. depscan reads the code with `ast`, follows URL routes, middleware, startup code
and commands to the packages they import, and gives each vulnerable package the strongest way it can be reached. This is
import-level analysis: it shows that code importing a package is reachable, not that the vulnerable function is called.

**Review** lets a person mark a finding fix now, accept risk or false positive, with a name and a reason. Accepting risk
or calling a finding a false positive requires an expiry date. Decisions are appended to an audit log protected by
database triggers and a hash chain. A decision moves a finding down the list but never changes its score or hides it.

**History** is built only from dates the sources give: when an advisory was published and modified, when it entered KEV,
and the cached EPSS snapshots. Nothing is interpolated. A watchlist flags findings that are not yet critical but whose
exploit probability is rising or that were recently added to KEV.

The formulas and the reasoning behind each number are in `docs/SCORING.md`.

## Components

| Path | Purpose |
|---|---|
| `depscan/` | the library: parsers, matcher, scoring, exposure graph, review log, history, server, command line |
| `frontend/` | the web console and landing page |
| `vscode-extension/` | a read-only VS Code client that runs the command line |
| `scripts/` | feed downloader (the only code that fetches the feeds), benchmark and snapshot scripts |
| `tests/` | the test suite and a frozen known sample |
| `benchmark/` | benchmark fixtures, frozen data, draft labels and results |
| `mock/` | ready-made inputs for trying the tool |
| `.github/workflows/` | continuous integration, including a demonstration of the CI gate |

## Evidence

The test suite covers a known sample with written-down expected rankings, the API contract against the frontend types,
upload safety, and the scoring, review, exposure, server and benchmark logic.

The benchmark compares depscan with matching by package name alone and with ranking by CVSS alone on nine frozen
fixtures. The results are in `docs/BENCHMARK.md`. The labels they rely on are drafts that need the project owner's manual
verification, part of the ranking result is circular because KEV is an input to the score, and the set is small. The
numbers describe these fixtures and do not predict performance on real projects.

## Limits

- Exposure analysis covers Python and Django only, at import level.
- The trust and exposure points and the risk weights are reasoned defaults, not fitted to data.
- The Dependency-Check parser follows an assumed report layout that has not been checked against a real report.
- The exposure analysis has been run on a small hand-written app, not on real projects.
- Version ranges are resolved through package registries when the network is available. Without it, matches on ranges are
  marked less certain.
- Reviewer names are typed in, not authenticated. The audit log shows tampering but does not prevent it.
- The web server is local and single-user, with no login.

## Documentation

[Architecture](docs/ARCHITECTURE.md) | [Scoring](docs/SCORING.md) | [Exposure](docs/EXPOSURE.md) | [Review](docs/REVIEW.md) |
[API contract](docs/CONTRACT.md) | [CI](docs/CI.md) | [Benchmark](docs/BENCHMARK.md) | [Demo script](docs/DEMO.md) | [Plan](docs/PLAN.md) |
[VS Code extension](vscode-extension/README.md)
