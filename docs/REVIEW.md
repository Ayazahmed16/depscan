# Human review

depscan only **recommends**. It never edits your dependency files and never installs or upgrades anything.
A person looks at each finding and records a decision. This document describes exactly what that does, so the
"human in the loop" is something you can inspect, not just a claim.

## The three decisions

| Decision | Meaning | Must expire? |
|---|---|---|
| `fix_now` | A person confirmed this will be fixed. | No |
| `accept_risk` | A known risk is accepted for now. | **Yes** |
| `false_positive` | The finding does not really apply here. | **Yes** |

`accept_risk` and `false_positive` are called **suppressions**. Revoking a decision (`revoke`) puts the finding
back to "needs review"; the history is kept.

## The rules (`review:` in `config/scoring.yaml`)

- A **reviewer name** and a **reason** of at least 10 characters are required.
- A suppression needs an **expiry date**, in the future, and no more than **180 days** away. For a finding whose
  risk is in the critical tier (risk ≥ 60) the limit is **30 days**. This stops a forgotten decision from hiding a
  finding forever.
- `fix_now` does not take an expiry date.
- Anything that breaks a rule is refused with a message naming the rule, and nothing is stored or logged.

## What a decision changes, and what it never does

- A suppressed finding **stays visible**. It is listed with its reviewer, reason and expiry, in the console and in
  the Markdown/HTML reports ("Reviewer decisions" section). Nothing is hidden.
- It **never changes** the risk score, the trust score, the computed next step or the recommendation. Those stay
  as the data and rules produced them, so a decision can always be compared with what depscan thought.
- When the expiry date has passed, the finding's status becomes **expired** and it counts as **needing review**
  again. The date itself is the last valid day. The system writes one `expired` entry to the audit log when it
  first notices.
- Statuses: `pending` (nobody decided), `fix_now`, `accept_risk`, `false_positive`, `expired`.
  "Needs review" = `pending` + `expired`.

## Finding identity

A decision attaches to a finding's **key**: `ecosystem|package|version|advisory`, for example
`PyPI|requests|2.31.0|CVE-2024-35195`. So a decision on `requests 2.31.0` does not carry over to `2.32.4`, and
decisions are also kept per **project** (`--project`, default `default`) so two projects do not share them.

## Where it is stored

A local SQLite file, by default `state/review.sqlite` (git-ignored; change it with `--review-db`). A scan alone never
creates it.

- `decisions`: the current decision per finding.
- `audit_log`: **every** event (a decision, a revoke, an expiry), with time (UTC), who, why and the expiry.

The audit log is **append-only**: database triggers refuse `UPDATE` and `DELETE`. Each row also stores a SHA-256
hash that covers the previous row's hash, so editing or removing history breaks the chain.

```
python -m depscan audit              # show the log, newest first
python -m depscan audit --verify     # recompute the chain: exit code 1 and the first bad entry if it is broken
```

## Using it

```
python -m depscan scan requirements.txt --out result.json
python -m depscan review result.json --list
python -m depscan review result.json "PyPI|requests|2.31.0|CVE-2024-35195" accept_risk \
       --reviewer "Ana Ruiz" --note "only used behind our proxy, patch in the Q4 refresh" --expires 2030-01-31
python -m depscan scan requirements.txt            # the report now shows the decision
python -m depscan review result.json KEY revoke --reviewer "Ana Ruiz" --note "the patch shipped"
```

The web console (phase 9) uses the same store through the API.

## Limits, stated plainly

- **Reviewer names are typed in, not authenticated.** The log records who *claimed* to decide.
- **The hash chain is tamper-evident, not tamper-proof.** It detects accidental damage and casual edits (including
  deletion and reordering). Someone with write access to the file who understands the scheme can recompute every hash.
  For a stronger guarantee, copy the latest hash somewhere you trust (a ticket, a signed commit) and compare later.
- `fix_now` is a record that someone decided; depscan does not check later that the fix happened. If the finding
  disappears from a later scan, the decision simply stops matching anything.
- The 10-character minimum stops "ok", not a bad reason.
- Decisions are stored on one machine. Sharing them between people needs the file to be shared, or a server.
