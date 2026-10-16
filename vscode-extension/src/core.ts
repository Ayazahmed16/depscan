// Pure logic for the extension: no VS Code imports, so it is unit-tested with `node --test`.

export const DISCLAIMER = 'No findings does not prove a project is secure.'

export type Action = 'fix_now' | 'verify_first' | 'monitor' | 'no_action'

export interface Finding {
  key: string
  id: string
  package: string
  version: string
  ecosystem: string
  summary: string
  kev: boolean
  fixed_version: string | null
  action: Action
  claim_status?: 'matched' | 'unconfirmed' | 'contradicted'
  recommendation: string
  review_status: string
  review: { decision: string; reviewer: string; note: string; expires: string | null } | null
  watch: string | null
  cvss: number | null
  epss: number | null
  match: { confidence: string; evidence: string[] }
  risk: { score: number; factors: { name: string; value: string; weight: number; contribution: number }[] }
  trust: { score: number; signals: { name: string; value: string; effect: number; note: string }[] }
  exposure: { level: string; path_labels: string[]; imported_by: string[]; note: string } | null
  advisories?: { id: string; summary: string; published: string | null; modified: string | null; withdrawn: string | null; affected_ranges: string[]; links: { label: string; url: string }[] }[]
  history: { date: string; risk: number; epss: number | null; event: string | null; simulated: boolean }[]
}

export interface ScanResult {
  source: string
  scanned_at: string
  findings: Finding[]
  warnings?: string[]
  graph?: { limitation: string } | null
}

export const ACTION_LABEL: Record<Action, string> = {
  fix_now: 'fix now',
  verify_first: 'verify first',
  monitor: 'monitor',
  no_action: 'no action',
}

export const ACTION_ORDER: Action[] = ['fix_now', 'verify_first', 'monitor', 'no_action']

/** requests, Requests, requests_ -> requests (PyPI names ignore case and - _ .) */
export function normalizeName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-')
}

function baseName(path: string): string {
  return path.split(/[\\/]/).pop() ?? path
}

/**
 * The 0-based line where `pkg` is declared in a dependency file, or null.
 * Used only to put a squiggle in the right place: the file is never edited.
 */
export function findLine(text: string, file: string, pkg: string): number | null {
  const lines = text.split(/\r?\n/)
  const name = baseName(file).toLowerCase()
  const want = normalizeName(pkg)
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (name.endsWith('.txt') || name === 'pipfile') {
      const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(?:[=<>!~;@#]|$)/.exec(line)
      if (m && normalizeName(m[1]) === want) return i
    } else if (name === 'go.mod' || name === 'go.sum') {
      if (line.split(/\s+/).includes(pkg)) return i
    } else {
      // package.json, package-lock.json, Pipfile.lock, poetry.lock, yarn.lock, reports: a quoted or bare name
      const quoted = new RegExp(`"${escapeRegex(pkg)}"\\s*:`, 'i')
      const lock = new RegExp(`^\\s*(name\\s*=\\s*)?"?${escapeRegex(pkg)}@?[",:\\s]`, 'i')
      if (quoted.test(line) || (name.endsWith('.lock') && lock.test(line))) return i
    }
  }
  return null
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/** Manifests first: a squiggle on `requests==2.19.0` is more useful than one in a 40 000 line lock file. */
const FILE_PRIORITY = ['requirements.txt', 'package.json', 'go.mod', 'pipfile', 'pipfile.lock', 'poetry.lock', 'package-lock.json', 'yarn.lock', 'go.sum']

export function sortByPriority(files: string[]): string[] {
  const rank = (f: string) => {
    const i = FILE_PRIORITY.indexOf(baseName(f).toLowerCase())
    return i === -1 ? FILE_PRIORITY.length : i
  }
  return [...files].sort((a, b) => rank(a) - rank(b))
}

export type DiagSeverity = 'error' | 'warning' | 'info' | 'hint'

export function severityFor(f: Finding): DiagSeverity {
  if (f.claim_status === 'contradicted') return 'hint'            // a scan report claims it, our data says not affected
  if (f.review_status === 'accept_risk' || f.review_status === 'false_positive') return 'hint'
  return { fix_now: 'error', verify_first: 'warning', monitor: 'info', no_action: 'hint' }[f.action] as DiagSeverity
}

export function diagnosticMessage(f: Finding): string {
  const flags = [
    f.kev ? 'KEV-listed' : '',
    f.claim_status === 'unconfirmed' ? 'unconfirmed scan-report claim' : '',
    f.claim_status === 'contradicted' ? 'likely false positive' : '',
    f.review_status !== 'pending' ? `review: ${f.review_status.replace('_', ' ')}` : '',
  ].filter(Boolean)
  const head = `${f.package} ${f.version}: ${f.id}${flags.length ? ` (${flags.join(', ')})` : ''}`
  return `${head}\nrisk ${f.risk.score.toFixed(0)} / trust ${f.trust.score.toFixed(0)}: ${ACTION_LABEL[f.action]}. ${f.recommendation}`
}

export interface Group { action: Action | 'watch'; label: string; findings: Finding[] }

/** Findings grouped by recommended action, then the watchlist. Order within a group is the engine's own order. */
export function groupFindings(findings: Finding[]): Group[] {
  const groups: Group[] = ACTION_ORDER.map((a) => ({
    action: a,
    label: ACTION_LABEL[a],
    findings: findings.filter((f) => f.action === a),
  }))
  groups.push({ action: 'watch', label: 'watchlist (may become urgent)', findings: findings.filter((f) => f.watch) })
  return groups.filter((g) => g.findings.length > 0)
}

export function summaryLine(findings: Finding[]): string {
  if (findings.length === 0) return 'depscan: no findings'
  const fix = findings.filter((f) => f.action === 'fix_now').length
  return `depscan: ${findings.length} finding${findings.length === 1 ? '' : 's'}, ${fix} fix now`
}

export function expiryDefault(f: Finding, today: Date): string {
  const days = f.risk.score >= 60 ? 30 : 90        // critical-tier suppressions are capped at 30 days by the engine
  const d = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() + days))
  return d.toISOString().slice(0, 10)
}

/** Everything the engine knows about a finding, as Markdown for the preview pane. */
export function detailsMarkdown(f: Finding): string {
  const out: string[] = []
  out.push(`# ${f.package} ${f.version}: ${f.id}`, '')
  out.push(`**Next step:** ${ACTION_LABEL[f.action]}. ${f.recommendation}`, '')
  out.push(`${f.summary}`, '')
  out.push(`| risk | trust | CVSS | EPSS | KEV | match |`, `|---|---|---|---|---|---|`)
  out.push(`| ${f.risk.score.toFixed(1)} | ${f.trust.score.toFixed(0)} | ${f.cvss ?? 'n/a'} | ${f.epss != null ? (f.epss * 100).toFixed(1) + '%' : 'n/a'} | ${f.kev ? 'yes' : 'no'} | ${f.match.confidence} |`, '')
  if (f.claim_status && f.claim_status !== 'matched') {
    out.push(f.claim_status === 'unconfirmed'
      ? '> Only a scan report claims this; the advisory data does not confirm it.'
      : '> A scan report claims this, but the advisory data says this version is **not** affected (likely false positive).', '')
  }
  out.push('## Why it matched', '', ...f.match.evidence.map((e) => `- ${e}`), '')
  out.push('## Risk factors', '', '| factor | value | weight | adds |', '|---|---|---|---|')
  for (const x of f.risk.factors) out.push(`| ${x.name} | ${x.value} | ${x.weight.toFixed(2)} | ${x.contribution.toFixed(1)} |`)
  out.push('', '## Trust signals', '', '| signal | value | effect |', '|---|---|---|')
  for (const x of f.trust.signals) out.push(`| ${x.name} | ${x.value} | ${x.effect > 0 ? '+' : ''}${x.effect.toFixed(0)} |`)
  if (f.advisories?.length) {
    out.push('', '## Advisories')
    for (const a of f.advisories) {
      out.push('', `**${a.id}**${a.withdrawn ? ' (WITHDRAWN)' : ''}: ${a.summary}`)
      out.push(`published ${a.published?.slice(0, 10) ?? 'unknown'}, modified ${a.modified?.slice(0, 10) ?? 'unknown'}; affected: ${a.affected_ranges.join(' | ') || 'see record'}`)
      out.push(a.links.map((l) => `[${l.label}](${l.url})`).join(' · '))
    }
  }
  if (f.exposure) {
    out.push('', '## Exposure (import-level only)', '', f.exposure.note)
    if (f.exposure.path_labels.length) out.push('', f.exposure.path_labels.join(' → '))
    out.push('', '_Import-level analysis does not follow function calls, so an imported package may never be used._')
  }
  if (f.history.length) {
    out.push('', '## History (real dates only)', '', '| date | risk | EPSS | event |', '|---|---|---|---|')
    for (const p of f.history) out.push(`| ${p.date} | ${p.risk.toFixed(1)} | ${p.epss != null ? (p.epss * 100).toFixed(1) + '%' : ''} | ${p.event ?? ''}${p.simulated ? ' (simulated)' : ''} |`)
  }
  if (f.watch) out.push('', `**Watchlist:** ${f.watch}`)
  if (f.review) out.push('', `**Review:** ${f.review.decision.replace('_', ' ')} by ${f.review.reviewer}${f.review.expires ? ` until ${f.review.expires}` : ''}: ${f.review.note}`)
  out.push('', '---', `${DISCLAIMER} depscan only recommends; it never changes your dependency files.`, '')
  return out.join('\n')
}

/** Tell a useful failure from noise: the CLI prints `error: ...` on stderr for problems it understands. */
export function cliError(stderr: string, code: number | null): string {
  if (/No module named/.test(stderr)) return 'Python cannot import depscan: set depscan.repoPath and depscan.pythonPath'
  const lines = stderr.split(/\r?\n/)
  const line = [...lines].reverse().find((l) => /^error:/i.test(l.trim()))
  if (line) return line.replace(/^error:\s*/i, '').trim()
  return `depscan exited with code ${code}${stderr.trim() ? `: ${lines.filter((l) => l.trim()).pop()}` : ''}`
}
