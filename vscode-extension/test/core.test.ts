import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  type Finding, DISCLAIMER, cliError, detailsMarkdown, diagnosticMessage, expiryDefault, findLine, groupFindings, normalizeName,
  severityFor, sortByPriority, summaryLine,
} from '../src/core'

function finding(over: Partial<Finding> = {}): Finding {
  return {
    key: 'PyPI|requests|2.19.0|CVE-2018-18074', id: 'CVE-2018-18074', package: 'requests', version: '2.19.0', ecosystem: 'PyPI',
    summary: 'Credentials sent on redirect', kev: false, fixed_version: '2.20.0', action: 'verify_first', claim_status: 'matched',
    recommendation: 'Upgrade to 2.20.0.', review_status: 'pending', review: null, watch: null, cvss: 9.8, epss: 0.012,
    match: { confidence: 'confirmed', evidence: ['requests 2.19.0 is in the affected range'] },
    risk: { score: 55.2, factors: [{ name: 'severity', value: '9.8', weight: 0.3, contribution: 29.4 }] },
    trust: { score: 71, signals: [{ name: 'sources', value: '2', effect: 10, note: 'two sources agree' }] },
    exposure: null, advisories: [], history: [], ...over,
  }
}

test('names are compared the way PyPI compares them', () => {
  assert.equal(normalizeName('Flask_SQLAlchemy'), 'flask-sqlalchemy')
  assert.equal(normalizeName('zope.interface'), 'zope-interface')
})

test('findLine finds a requirements.txt line, ignoring case, extras, comments and similar names', () => {
  const text = ['# deps', 'requests-oauthlib==1.0', 'Requests[security]==2.19.0  # old', 'flask>=1.0'].join('\n')
  assert.equal(findLine(text, 'C:\\proj\\requirements.txt', 'requests'), 2)
  assert.equal(findLine(text, 'requirements.txt', 'flask'), 3)
  assert.equal(findLine(text, 'requirements.txt', 'django'), null)
  assert.equal(findLine('requests', 'requirements.txt', 'requests'), 0) // bare name, no version
})

test('findLine finds package.json, go.mod and lock file entries', () => {
  const pkg = '{\n  "dependencies": {\n    "lodash": "4.17.0",\n    "@scope/pkg": "1.0.0"\n  }\n}'
  assert.equal(findLine(pkg, 'package.json', 'lodash'), 2)
  assert.equal(findLine(pkg, '/x/package.json', '@scope/pkg'), 3)
  assert.equal(findLine(pkg, 'package.json', 'lodash-es'), null)
  const mod = 'module x\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.0\n)\n'
  assert.equal(findLine(mod, 'go.mod', 'github.com/gin-gonic/gin'), 3)
  assert.equal(findLine('[[package]]\nname = "pyyaml"\nversion = "5.1.2"', 'poetry.lock', 'pyyaml'), 1)
})

test('manifests are preferred over lock files for placing a squiggle', () => {
  assert.deepEqual(sortByPriority(['package-lock.json', 'package.json', 'yarn.lock', 'x.txt']), ['package.json', 'package-lock.json', 'yarn.lock', 'x.txt'])
})

test('severity follows the recommended action, and softens for false positives and decided findings', () => {
  assert.equal(severityFor(finding({ action: 'fix_now' })), 'error')
  assert.equal(severityFor(finding({ action: 'verify_first' })), 'warning')
  assert.equal(severityFor(finding({ action: 'monitor' })), 'info')
  assert.equal(severityFor(finding({ action: 'no_action' })), 'hint')
  assert.equal(severityFor(finding({ action: 'fix_now', claim_status: 'contradicted' })), 'hint')
  assert.equal(severityFor(finding({ action: 'fix_now', review_status: 'accept_risk' })), 'hint')
  assert.equal(severityFor(finding({ action: 'fix_now', review_status: 'fix_now' })), 'error') // still pending work
})

test('the diagnostic message names the package, advisory, scores, action and flags', () => {
  const m = diagnosticMessage(finding({ kev: true, action: 'fix_now' }))
  assert.match(m, /requests 2\.19\.0: CVE-2018-18074 \(KEV-listed\)/)
  assert.match(m, /risk 55 \/ trust 71: fix now\. Upgrade to 2\.20\.0\./)
  assert.match(diagnosticMessage(finding({ claim_status: 'contradicted' })), /likely false positive/)
  assert.match(diagnosticMessage(finding({ review_status: 'accept_risk' })), /review: accept risk/)
})

test('findings are grouped by action in a fixed order, with the watchlist last and empty groups dropped', () => {
  const groups = groupFindings([
    finding({ id: 'a', action: 'monitor' }), finding({ id: 'b', action: 'fix_now' }), finding({ id: 'c', action: 'monitor', watch: 'EPSS rose' }),
  ])
  assert.deepEqual(groups.map((g) => [g.action, g.findings.map((f) => f.id)]), [['fix_now', ['b']], ['monitor', ['a', 'c']], ['watch', ['c']]])
  assert.deepEqual(groupFindings([]), [])
})

test('the status line counts findings and fix-now items', () => {
  assert.equal(summaryLine([]), 'depscan: no findings')
  assert.equal(summaryLine([finding({ action: 'fix_now' })]), 'depscan: 1 finding, 1 fix now')
  assert.equal(summaryLine([finding(), finding({ action: 'fix_now' })]), 'depscan: 2 findings, 1 fix now')
})

test('the default expiry respects the engine caps (30 days for critical-tier risk, 90 otherwise)', () => {
  const today = new Date(Date.UTC(2026, 9, 17))
  assert.equal(expiryDefault(finding({ risk: { score: 60, factors: [] } }), today), '2026-11-16')
  assert.equal(expiryDefault(finding({ risk: { score: 59.9, factors: [] } }), today), '2027-01-15')
})

test('the details page carries the evidence, both score tables, the limits and the disclaimer', () => {
  const md = detailsMarkdown(finding({
    exposure: { level: 'web', path_labels: ['route /login', 'accounts.views', 'requests'], imported_by: [], note: 'reached from a route' },
    advisories: [{ id: 'GHSA-x', summary: 's', published: '2018-10-01T00:00:00Z', modified: null, withdrawn: null, affected_ranges: ['introduced 0, fixed 2.20.0'], links: [{ label: 'OSV', url: 'https://osv.dev/vulnerability/GHSA-x' }] }],
    history: [{ date: '2025-10-17', risk: 50, epss: 0.01, event: 'advisory published', simulated: false }],
  }))
  for (const part of ['requests 2.19.0 is in the affected range', '| severity | 9.8 |', '| sources | 2 | +10 |', 'introduced 0, fixed 2.20.0',
    '[OSV](https://osv.dev/vulnerability/GHSA-x)', 'route /login → accounts.views → requests', 'does not follow function calls', '2025-10-17', DISCLAIMER]) {
    assert.ok(md.includes(part), `missing: ${part}`)
  }
  assert.ok(!md.includes('(simulated)'))
  assert.ok(detailsMarkdown(finding({ history: [{ date: 'd', risk: 1, epss: null, event: null, simulated: true }] })).includes('(simulated)'))
  assert.match(detailsMarkdown(finding({ claim_status: 'contradicted' })), /likely false positive/)
})

test('CLI failures become a short readable message', () => {
  assert.equal(cliError('Traceback...\nerror: no local advisory index for PyPI: run fetch_data', 2), 'no local advisory index for PyPI: run fetch_data')
  assert.match(cliError('ModuleNotFoundError: No module named depscan', 1), /depscan\.repoPath/)
  assert.match(cliError('', 3), /exited with code 3/)
})

test('a transitive finding shows the route from a direct dependency, a direct one does not', () => {
  const via = detailsMarkdown(finding({
    dependency_path: { known: true, direct: false, path_labels: ['express@4.16.0', 'qs@6.5.1'], direct_parents: ['express'], note: 'A transitive dependency, needed through express.' },
  }))
  assert.ok(via.includes('## Dependency path') && via.includes('express@4.16.0 → qs@6.5.1') && via.includes('needed through express'))
  const direct = detailsMarkdown(finding({ dependency_path: { known: true, direct: true, path_labels: ['requests@2.19.0'], direct_parents: [], note: 'A direct dependency.' } }))
  assert.ok(!direct.includes('## Dependency path'))
  assert.ok(!detailsMarkdown(finding()).includes('## Dependency path'))                       // older results carry no path
})
