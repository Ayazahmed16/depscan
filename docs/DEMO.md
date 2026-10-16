# Demo script (under 2 minutes)

Everything runs **offline** from the cached snapshots. Rehearse once with a stopwatch: the spoken lines below are about
240 words, which is roughly 95 seconds at a normal pace, leaving some slack for clicks.

## Before you go on (5 minutes, the day before and again 10 minutes before)

```powershell
cd C:\Users\moham\depscan
.\.venv\Scripts\python.exe scripts\fetch_data.py            # only if data\ is missing or old (about 10 min)
cd frontend; npm install; npm run build; cd ..               # only if frontend\dist is missing or the frontend changed
.\.venv\Scripts\python.exe -m depscan serve --offline        # leave this running; Wi-Fi off is fine
```

- Open http://127.0.0.1:8000/ in a browser and zoom the page so the back row can read it.
- Have these ready in a file picker: `tests\sample\requirements.txt` and `mock\django_app.zip`.
- Optional: delete the `state\` folder first if you want an empty review log (it holds only local decisions).
- Click **Reset** in the console so no old scan is showing.
- Check the footer shows four snapshot dates and "engine: online".

## The script

| time | do | say |
|---|---|---|
| 0:00 | Landing page, then click into the console | "Teams get hundreds of vulnerability alerts and no way to know which to read first, or which are even true. depscan ranks them, shows its evidence, and tells you how far to trust each one. It only recommends. It never touches your dependencies." |
| 0:15 | Drop `tests\sample\requirements.txt` | "Six pinned packages. Fifteen findings. The first is PySpark CVE-2022-33891, risk 96, and it is on CISA's known-exploited list, so it beats a pile of higher-scoring but unexploited ones." |
| 0:30 | Click the top finding; scroll its risk factors and trust signals | "Nothing is a black box. Every factor, its weight and its contribution is listed, and so is every reason to trust, or not trust, the advisory." |
| 0:45 | Point at the withdrawn pyyaml entry (verify first); mention Jinja2 | "This PyYAML advisory was withdrawn by its publisher, so depscan says verify first, not fix now. And Jinja2 has 21 advisories, all fixed in this version: a name-matching scanner flags every one. depscan flags none." |
| 1:00 | Reset, drop `mock\django_app.zip`, open the **Exposure** tab | "For a Django project it reads the code, never runs it, and traces URL routes to vulnerable packages. PyYAML is reachable from a web request, PySpark only from a management command, Flask not at all. This is import-level, and the limit is stated right here." |
| 1:25 | Findings tab: choose a finding, **accept risk**, type a reason, set an expiry | "A person decides. Accepting a risk needs a name, a reason and an expiry. The finding stays visible, and it is written to a tamper-evident audit log." |
| 1:40 | Review log tab, then Timeline tab | "Every decision is logged. The timeline uses only real dates from the sources, and the watchlist flags a finding whose exploit probability is rising." |
| 1:50 | Footer | "No findings does not prove a project is secure." |

If you have 10 more seconds, mention the benchmark honestly (see below). Do not skip the last line: it is required.

## Lines you can safely say

- "Offline from cached data." (True: show Wi-Fi off.)
- "It never modifies your project." (True: uploads are only read, a zip's code is never run.)
- "Every score shows its working." (True.)
- Benchmark, in one breath, with the caveat: "On nine frozen test projects, matching by package name alone reported 1,784
  findings of which about a third were real; depscan reported 627 with none false against our draft labels, which are
  still being verified. Against CVSS-only ranking, it put the known-exploited findings in the top three in 11 of 11
  cases, but KEV is one of its inputs, so that is by design." (Numbers from `docs/BENCHMARK.md` at the time of writing:
  check them first with `python scripts/benchmark.py --check`.)

## Lines to avoid

- "Accurate" or "100%" with no context: the labels are our drafts and the matcher and labels read the same advisory text.
- "It finds all vulnerabilities" or "your project is safe": see the required notice.
- "The exposure graph proves it is exploitable": it is import-level and only says a route can reach code that imports the package.
- "Machine learning" or "AI": there is none. Scores are transparent weighted sums.
- "Real-time": data is a snapshot; its date is in the footer.

## If something goes wrong

| problem | do |
|---|---|
| Page says the backend is unreachable | The server window closed. Rerun the `serve` command and reload. |
| Upload shows an error | Read it aloud, it is plain English (for example "nothing to scan"). Re-drop the right file. |
| Port 8000 busy | `... serve --offline --port 8123`, then open `http://127.0.0.1:8123/app`. |
| Exposure tab empty | You scanned a manifest, not the zip. Reset and drop `mock\django_app.zip`. |
| Anything else | Run the same scan in the terminal: `python -m depscan scan tests\sample\requirements.txt --offline`. Same engine, same results. |

## Editor version (optional, 20 seconds)

Install `vscode-extension\depscan-vscode-0.1.0.vsix`, open the `mock` folder, run **depscan: Scan workspace**. Red
squiggles appear on `requirements.txt`, and the depscan side bar lists findings by recommended action.
