# Dependency graph

**Question it answers:** why is this vulnerable package in my project, and whose release do I have to change to get rid of it?

A vulnerable *transitive* package cannot be fixed by editing your manifest. You update or replace the direct
dependency that needs it, or use your package manager's override. The advisory data does not say which one. The lock
file does, and depscan reads it.

This is separate from the exposure graph ([EXPOSURE.md](EXPOSURE.md)), which asks whether a web request can reach a
package's code. Both can be shown for the same finding.

## Where the links come from

| File | Links | How |
|---|---|---|
| `package-lock.json` (v2 and v3) | yes | each package's `dependencies`, `optionalDependencies` and non-optional `peerDependencies`, resolved the way npm resolves them: the package's own nested `node_modules` first, then each parent's, then the root's. A vulnerable copy under one parent is not confused with a safe copy at the root. |
| `yarn.lock` (v1 and berry) | yes | each entry's `dependencies`, with the range matched to the version yarn locked for that range. Workspace and patched entries are skipped. |
| `poetry.lock` | yes | each package's `dependencies`; Poetry locks one version per name. |
| `Pipfile.lock`, `requirements.txt`, `go.mod`, `go.sum` | no | they do not record what depends on what. The packages appear with no links, and the result says so. |

## What you get

- **Per finding, `dependency_path`:** the route from a direct dependency (shortest, runtime routes preferred), every direct
  dependency that needs the package, and a plain sentence. For a direct dependency it says so. When the files give no
  links it says what is missing. It never invents a route.
- **Per scan, `dependency_graph`:** nodes and links for the direct dependencies, every vulnerable package and the routes
  between them (a lock file can hold thousands of packages, so the rest are counted, not drawn), with counts and the limitation.
- **In the console:** a *dependencies* view that highlights the selected finding's route, and a *Dependency path* panel in the
  finding detail. Reports and the editor's details page carry a "Dependency path" line for transitive findings.

## How it was checked

Not only against hand-written examples. On a real lock file with 251 packages, 21 of them nested copies (generated with
npm, `tests/fixtures/real-npm/`), the parser's links equal the 550 that `npm ls --all --json` reports. On a real `yarn.lock`
from `yarn install` over the same project, they equal the 553 found by reading the installed `node_modules` folder and
resolving each `package.json` the way Node does. `poetry.lock` and the berry `yarn.lock` format were tested on small
hand-written files only.

Running it on a real project found a bug elsewhere: combining `package.json` with its lock file marked every copy of a
package as direct when its name was in the manifest, including nested transitive copies. That inflated their risk score
(direct counts more than transitive). Fixed, with a regression test.

## Limits

- The path is the shortest one. A package can be needed by several others; all the direct dependencies are listed, but only one route is drawn.
- It does not check whether a newer release of the parent still needs the vulnerable version, so it cannot promise that updating the parent removes the finding.
- For `yarn.lock` with two versions of one name, `package.json` alone cannot say which copy is the direct one; both can be marked direct.
- Only the links the lock file records. Dependencies loaded at run time, optional features and plugins are not seen.
- No graph for Go, or for Python without a `poetry.lock`.

**No findings does not prove a project is secure.**
