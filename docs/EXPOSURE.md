# Exposure graph (Python / Django only)

**Question it answers:** for a vulnerable package your project depends on, can a web request, the application
starting up, or an operator's command lead to code that imports it?

**What it is not:** a call graph. It reads `import` statements, not function calls. Read the limits below before
trusting a "not reached" or relying on a "reachable".

## How it works

1. **Read the code, never run it.** Every `.py` file under the project folder is parsed with Python's `ast` module.
   Nothing is imported or executed (a test plants a module that would write a file and `raise SystemExit`; it is never
   triggered). `.venv`, `node_modules`, `site-packages` and similar folders are skipped. Files that do not parse are
   skipped and listed in the report.
2. **Find the entry points.** Strongest first:

   | Level | Entry points | Risk factor |
   |---|---|---|
   | `web` | URL routes (`path`, `re_path`, `url`, `include()` chains, DRF `router.register`), the root urlconf, and everything named in `MIDDLEWARE`, `AUTHENTICATION_BACKENDS` and `SESSION_ENGINE` (they run on web requests) | 1.0 |
   | `startup` | settings, `INSTALLED_APPS` (and the `models`, `admin`, `apps`, `signals` modules Django auto-loads for each app), `wsgi`/`asgi`, `manage.py` | 0.6 |
   | `command` | `management/commands/*`, `tasks.py` | 0.3 |
   | `test` | `tests/`, `test_*.py`, `conftest.py` | 0 |

3. **Build a directed graph:** entry point → module → module → ... → third-party package → the packages it depends on.
   Import names are matched to declared dependencies (`yaml` → `pyyaml`) with a table of common differences, then by name,
   then through the distributions installed on this machine. Import names that cannot be matched are listed.
4. **Give each package the strongest level that reaches it**, with the shortest path as evidence. A package that is
   imported but not reached is `none`, and the modules that import it are named so you can check by eye.
5. **Feed the risk score.** The `exposure` factor (weight 0.10) earns the level's share (`risk.exposure_levels` in
   `config/scoring.yaml`). The net effect is that a vulnerability a route can reach ranks above one only a command
   or dead code touches. Exposure never changes the trust score.

On the tiny sample app (`tests/sample/django_app`), compared with the same scan without the app: the findings in
`pyyaml` and `requests` (web-reached) rise, the `pyspark` ones (command only) and `flask` (imported only by dead code)
fall, and the one KEV-listed finding stays first, because a known-exploited vulnerability should not be pushed down
by an import-level guess.

## Using it

```
python -m depscan scan path/to/django_project            # a folder with manage.py is analysed automatically
python -m depscan scan requirements.txt --project-dir path/to/django_project
```

The result has a `graph` (nodes, links, limitation, stats) and each finding an `exposure` object. The console's exposure
view draws the paths and highlights the selected finding's path; reports print each finding's path and the limitation.

## Limits, stated plainly

- **Import-level, not call-level.** An imported package may never be called. A package can also be reached by code
  this analysis cannot see.
- **Python / Django only.** Findings for other ecosystems get no exposure, and a warning says so. A project with no
  Django entry points at all gets no exposure (unknown), never "not exposed".
- **What it can miss:** `getattr` and other reflection, string values in settings other than the ones read above,
  signal receivers, templates and template tags, plugin systems and entry points, Celery routing, code generated at run
  time, `importlib` with a computed name (a string literal is followed), a URL pattern built at run time, a
  view that is a lambda. A route it cannot read is skipped, not guessed.
- **Conditional imports count as reachable** (inside functions, `if`, `try`). Imports under `if TYPE_CHECKING:` do not.
- **Import name to package matching is heuristic.** A table, a name match, and this machine's installed packages. An
  unmatched import is reported, but its package will look unused.
- **Transitive dependencies** are linked only when a `poetry.lock` is supplied. Without it, a transitive finding's
  exposure is unknown (the factor is dropped), not "not reached".
- **`none` is weaker than it sounds:** "imported but unreachable" can be dead code, or code reached in a way listed above.
  "No import found" can be a tool, a plugin, or something only another package needs.
- **Scores with and without a project folder are not comparable** (different weights).
- The `startup` and `command` credits (0.6 and 0.3) are reasoned defaults, like every weight here, not fitted values.
