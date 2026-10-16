# depscan for VS Code

A thin, **read-only** client for depscan (the parent folder of this extension). It scans the dependency files in your workspace, ranks the
vulnerabilities by risk and trust, and shows them where you work. It never edits or installs anything in your project.

**No findings does not prove a project is secure.**

## What you get

- **Problems panel:** a squiggle on the line that declares each vulnerable package (`requirements.txt`, `package.json`,
  `go.mod`, lock files). Red = fix now, yellow = verify first, blue = monitor, hint = no action, a likely false positive,
  or a finding a person has accepted. Click the advisory id to open it on OSV.
- **depscan side bar:** findings grouped by recommended action, plus a watchlist of findings that may become urgent.
  Click one for the full page: why it matched, every risk factor and trust signal, advisories with links, the Django
  exposure path, and its real dated history.
- **Review decisions** (right-click or the checklist icon): fix now, accept risk, false positive, or revoke, with your
  name, a reason (10+ characters) and, for suppressions, an expiry date. Recorded in depscan's tamper-evident audit log
  (`depscan: Show audit log`). A decision never changes a score; it is shown beside the finding and sorts it lower.
- **Status bar:** `depscan: 67 findings, 6 fix now`. Click to scan again.
- **Open the web console** for the graph view and the full timeline.

## Setup

The extension calls the depscan command line, so it needs the depscan project and its cached data
(`python scripts/fetch_data.py`, see the main README of the depscan project).

1. In this folder: `npm install`, then `npm run package`. This writes `depscan-vscode-0.1.0.vsix`.
2. In VS Code: Extensions view, `...` menu, **Install from VSIX...**. (Or: `code --install-extension depscan-vscode-0.1.0.vsix`.)
3. Open a folder with a `requirements.txt` or `package.json` and run **depscan: Scan workspace**.

If this folder sits inside the depscan repo (as it does here), the repo, its `.venv` and `data/` are found automatically.
Otherwise set `depscan.repoPath` (and `depscan.pythonPath` if needed). Settings: `depscan.offline` (default on),
`depscan.dataDir`, `depscan.reviewer`, `depscan.scanOnSave`, `depscan.consoleUrl`.

## Limits

- It scans the folder of each dependency file. A Django project's **exposure graph** needs `manage.py` in that same folder;
  for a project elsewhere, use the web console and upload a zip.
- Everything depscan does not know stays unknown: see the main README of the depscan project for the data and scoring limits.
- Reviewer names are typed in, not authenticated.
- Tested: the pure logic (`npm test`) and the exact CLI calls it makes, on real data. Not tested automatically: the VS Code wiring in `src/extension.ts`
  (tree, Problems panel, commands); try it in an Extension Development Host before relying on it.

## Development

`npm test` compiles and runs the unit tests. Press F5 in VS Code (with this folder open) to launch an Extension
Development Host. The logic lives in `src/core.ts` (no VS Code imports); `src/extension.ts` is the VS Code wiring.
