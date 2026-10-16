"""Render a scan result as Markdown or a single self-contained HTML file."""
from __future__ import annotations

import html

NOTICE = "No findings does not prove a project is secure."

ACTION = {"fix_now": "FIX NOW", "verify_first": "VERIFY FIRST", "monitor": "MONITOR", "no_action": "NO ACTION"}

LIMITS = [
    "Matches are only as good as the cached advisory snapshots, dated below.",
    "An exact version (a lock file or == pin) gives a confirmed match. A version range (for example >=1.2) is resolved "
    "against the package registry when it can be (likely or possible); if the registry cannot be used it is tested at its "
    "lowest allowed version only (probable).",
    "Without a lock file or scan report, transitive dependencies are not known.",
    "Risk and trust scores are transparent heuristics (see docs/SCORING.md), not measurements of real-world exploitation.",
    "Reviewer names are typed in, not authenticated.",
    "depscan only recommends. A person decides, and nothing is changed in your project.",
]

# What each review status reads as. "expired" means a suppression's end date passed: it needs review again.
REVIEW_LABEL = {"pending": "needs review", "expired": "EXPIRED, needs review", "fix_now": "fix confirmed",
                "accept_risk": "risk accepted", "false_positive": "false positive"}


def review_line(x: dict) -> str:
    """One plain sentence about a finding's review state."""
    r, status = x.get("review"), x.get("review_status", "pending")
    if not r:
        return "Review: needs review (no decision recorded)."
    until = f" until {r['expires']}" if r.get("expires") else ""
    lapsed = " That decision has EXPIRED, so this finding needs review again." if status == "expired" else ""
    return f"Review: {REVIEW_LABEL[r['decision']]} by {r['reviewer']} on {r['at'][:10]}{until}: \"{r['note']}\".{lapsed}"


def review_summary_line(result: dict) -> str:
    s = result.get("review_summary")
    if not s:
        return ""
    return (f"Review: {s['needs_review']} need review ({s['pending']} not yet reviewed, {s['expired']} expired) · "
            f"{s['fix_now']} confirmed to fix · {s['accept_risk']} risk accepted · {s['false_positive']} false positive. "
            f"Suppressed findings stay listed.")


def render_markdown(result: dict) -> str:
    f = result["findings"]
    snap = ", ".join(f"{k} {v or 'missing'}" for k, v in result["snapshots"].items())
    out = [
        f"# depscan report: {result['source']}",
        "",
        f"> **{NOTICE}**",
        "",
        f"Scanned {result['scanned_at']} · {result['dependencies_read']} dependencies read · {len(f)} findings · data snapshots: {snap}",
        "",
    ]
    if review_summary_line(result):
        out += [review_summary_line(result), ""]
    if result["warnings"]:
        out += ["## Could not read or caveats", ""] + [f"- {w}" for w in result["warnings"]] + [""]
    if not f:
        out += ["No findings matched the cached advisory data.", "", f"**{NOTICE}**", ""]
    else:
        out += ["## Recommended upgrades (suggestions only)", ""]
        for a in result["package_actions"]:
            if a["target_version"]:
                out.append(f"- **{a['package']}** {a['version']} → {a['target_version']} clears {a['clears']} of {a['total']} findings")
            else:
                out.append(f"- **{a['package']}** {a['version']}: no fixed version listed for {a['total']} finding(s)")
        out += ["", "## Findings, highest risk first", "",
                "| # | Advisory | Package | Risk | Trust | Next step | Match | Review |", "|---|---|---|---|---|---|---|---|"]
        for i, x in enumerate(f, 1):
            out.append(f"| {i} | {x['id']} | {x['package']} {x['version']} | {x['risk']['score']:.0f} | {x['trust']['score']:.0f} | "
                       f"{ACTION[x['action']]} | {x['match']['confidence']} | {REVIEW_LABEL[x.get('review_status', 'pending')]} |")
        out.append("")
        for i, x in enumerate(f, 1):
            out += [f"### {i}. {x['id']} · {x['package']} {x['version']}", "", x["summary"], "",
                    f"**Risk {x['risk']['score']:.0f}/100** · **Trust {x['trust']['score']:.0f}/100 ({x['trust']['level']})** · {ACTION[x['action']]} · match: {x['match']['confidence']}", "",
                    "Evidence:"] + [f"- {e}" for e in x["match"]["evidence"]]
            out += ["", "Risk factors:", "", "| factor | value | weight | adds |", "|---|---|---|---|"]
            out += [f"| {r['name']} | {r['value']} | {r['weight']:.2f} | {r['contribution']:.1f} |" for r in x["risk"]["factors"]]
            for n in x["risk"]["notes"]:
                out.append(f"\n_Note: {n}_")
            out += ["", f"Trust signals (start at {x['trust']['base']}, add the points, clamp to 0-100):", "",
                    "| signal | value | points | why |", "|---|---|---|---|"]
            out += [f"| {s['name']} | {s['value']} | {s['effect']:+.0f} | {s['note']} |" for s in x["trust"]["signals"]]
            out += ["", f"**Recommendation:** {x['recommendation']}", "", f"**{review_line(x)}**", ""]
        decided = [x for x in f if x.get("review")]
        if decided:
            out += ["## Reviewer decisions", "", "| finding | decision | reviewer | decided | expires | reason |", "|---|---|---|---|---|---|"]
            out += [f"| {x['id']} · {x['package']} {x['version']} | {REVIEW_LABEL[x['review_status']] if x['review_status'] == 'expired' else REVIEW_LABEL[x['review']['decision']]} "
                    f"| {x['review']['reviewer']} | {x['review']['at'][:10]} | {x['review']['expires'] or '-'} | {x['review']['note']} |" for x in decided]
            out.append("")
    out += ["## Limitations", ""] + [f"- {limit}" for limit in LIMITS] + ["", f"**{NOTICE}**", ""]
    return "\n".join(out)


def render_html(result: dict) -> str:
    """Markdown-free HTML so the report opens anywhere with no dependencies."""
    e = html.escape
    f = result["findings"]
    snap = ", ".join(f"{e(k)} {e(v or 'missing')}" for k, v in result["snapshots"].items())
    rows = "".join(
        f"<tr><td>{i}</td><td>{e(x['id'])}</td><td>{e(x['package'])} {e(str(x['version']))}</td>"
        f"<td class='n'>{x['risk']['score']:.0f}</td><td class='n'>{x['trust']['score']:.0f}</td><td>{ACTION[x['action']]}</td><td>{e(x['match']['confidence'])}</td>"
        f"<td>{e(REVIEW_LABEL[x.get('review_status', 'pending')])}</td></tr>"
        for i, x in enumerate(f, 1))
    decided = [x for x in f if x.get("review")]
    decisions = ("<h2>Reviewer decisions</h2><table><tr><th>finding</th><th>decision</th><th>reviewer</th><th>decided</th><th>expires</th><th>reason</th></tr>"
                 + "".join(
                     f"<tr><td>{e(x['id'])} · {e(x['package'])} {e(str(x['version']))}</td>"
                     f"<td>{e(REVIEW_LABEL['expired'] if x['review_status'] == 'expired' else REVIEW_LABEL[x['review']['decision']])}</td>"
                     f"<td>{e(x['review']['reviewer'])}</td><td>{e(x['review']['at'][:10])}</td><td>{e(x['review']['expires'] or '-')}</td>"
                     f"<td>{e(x['review']['note'])}</td></tr>" for x in decided)
                 + "</table>") if decided else ""
    cards = ""
    for i, x in enumerate(f, 1):
        factors = "".join(
            f"<tr><td>{e(r['name'])}</td><td>{e(str(r['value']))}</td><td class='n'>{r['weight']:.2f}</td><td class='n'>{r['contribution']:.1f}</td></tr>"
            for r in x["risk"]["factors"])
        notes = "".join(f"<p class='note'>Note: {e(n)}</p>" for n in x["risk"]["notes"])
        trust_rows = "".join(
            f"<tr><td>{e(s['name'])}</td><td>{e(str(s['value']))}</td><td class='n'>{s['effect']:+.0f}</td><td>{e(s['note'])}</td></tr>"
            for s in x["trust"]["signals"])
        cards += (
            f"<section><h3>{i}. {e(x['id'])} · {e(x['package'])} {e(str(x['version']))}</h3><p>{e(x['summary'])}</p>"
            f"<p><b>Risk {x['risk']['score']:.0f}/100</b> · <b>Trust {x['trust']['score']:.0f}/100 ({e(x['trust']['level'])})</b> · {ACTION[x['action']]} · match: {e(x['match']['confidence'])}</p>"
            f"<p>Evidence:</p><ul>{''.join(f'<li>{e(v)}</li>' for v in x['match']['evidence'])}</ul>"
            f"<table><tr><th>factor</th><th>value</th><th>weight</th><th>adds</th></tr>{factors}</table>{notes}"
            f"<p>Trust signals (start at {x['trust']['base']}, add the points, clamp to 0-100):</p>"
            f"<table><tr><th>signal</th><th>value</th><th>points</th><th>why</th></tr>{trust_rows}</table>"
            f"<p><b>Recommendation:</b> {e(x['recommendation'])}</p><p><b>{e(review_line(x))}</b></p></section>")
    actions = "".join(
        f"<li><b>{e(a['package'])}</b> {e(str(a['version']))} → {e(a['target_version'])} clears {a['clears']} of {a['total']} findings</li>"
        if a["target_version"] else
        f"<li><b>{e(a['package'])}</b> {e(str(a['version']))}: no fixed version listed for {a['total']} finding(s)</li>"
        for a in result["package_actions"])
    warnings = "".join(f"<li>{e(w)}</li>" for w in result["warnings"])
    body_find = (f"<h2>Recommended upgrades (suggestions only)</h2><ul>{actions}</ul>"
                 f"<h2>Findings, highest risk first</h2><table><tr><th>#</th><th>Advisory</th><th>Package</th><th>Risk</th><th>Trust</th><th>Next step</th><th>Match</th><th>Review</th></tr>{rows}</table>{cards}{decisions}"
                 if f else f"<p>No findings matched the cached advisory data.</p><p><b>{NOTICE}</b></p>")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>depscan report</title><style>
body{{font:15px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#09090b}}
table{{border-collapse:collapse;width:100%;margin:.5rem 0}}td,th{{border:1px solid #d4d4d8;padding:.3rem .5rem;text-align:left}}
.n{{text-align:right;font-variant-numeric:tabular-nums}}section{{border-top:2px solid #09090b;margin-top:1.5rem}}
.notice{{border:2px solid #09090b;padding:.6rem 1rem;font-weight:700}}.note,.meta{{color:#52525b;font-size:.9em}}
</style></head><body><h1>depscan report: {e(result['source'])}</h1>
<p class="notice">{NOTICE}</p>
<p class="meta">Scanned {e(result['scanned_at'])} · {result['dependencies_read']} dependencies read · {len(f)} findings · data snapshots: {snap}</p>
{f'<p class="meta">{e(review_summary_line(result))}</p>' if review_summary_line(result) else ''}
{f'<h2>Could not read or caveats</h2><ul>{warnings}</ul>' if warnings else ''}{body_find}
<h2>Limitations</h2><ul>{''.join(f'<li>{e(limit)}</li>' for limit in LIMITS)}</ul><p class="notice">{NOTICE}</p></body></html>"""
