import type { AuditEntry, ExposureGraph, Health, ScanResult } from '../lib/types'

// LAYOUT FIXTURE: placeholder values for checking the UI before the backend exists.
// Everything here is made up on purpose (FIXTURE-xxxx IDs, "example-*" packages).
// It is only reachable in `npm run dev` with ?fixture=1 and shows a banner.
// It is never bundled into a production build (see ConsoleApp, import.meta.env.DEV).

export const fixtureHealth: Health = {
  status: 'ok',
  version: 'fixture',
  snapshots: { osv: null, nvd: null, kev: null, epss: null },
}

export const fixtureScan: ScanResult = {
  source: 'layout-fixture',
  scanned_at: 'fixture',
  findings: [
    {
      id: 'FIXTURE-0001', aliases: ['FIXTURE-A'], package: 'example-web', version: '1.0.0', ecosystem: 'PyPI',
      direct: true, scope: 'runtime', summary: 'Placeholder advisory used only to check the layout.',
      cvss: 9.1, epss: 0.42, kev: true, fixed_version: '1.2.0', major_bump: false,
      match: { confidence: 'exact', evidence: ['placeholder: version 1.0.0 is inside range >=0.5,<1.2.0 (source A)', 'placeholder: source B lists the same range'] },
      risk: { score: 82, factors: [{ name: 'cvss', value: '9.1', weight: 0.3, contribution: 27 }, { name: 'kev', value: 'listed', weight: 0.3, contribution: 30 }] },
      trust: { score: 88, signals: [{ name: 'independent sources', value: '2', effect: 25, note: 'two sources list this advisory' }, { name: 'fix exists', value: 'yes', effect: 15, note: 'patched release found' }] },
      action: 'fix_now', recommendation: 'Placeholder: upgrade example-web to 1.2.0 or later (minor bump).',
      exposure: { exposed: true, path: ['urls.py', 'views.home', 'example-web'] },
      history: [
        { date: '2025-01-01', risk: 30, epss: 0.02, event: 'advisory published', simulated: false },
        { date: '2025-06-01', risk: 55, epss: 0.2, event: 'EPSS rose', simulated: true },
        { date: '2025-09-01', risk: 82, epss: 0.42, event: 'added to KEV', simulated: true },
      ],
      watch: null, review: null,
    },
    {
      id: 'FIXTURE-0002', aliases: [], package: 'example-parser', version: '2.3.1', ecosystem: 'PyPI',
      direct: false, scope: 'dev', summary: 'Second placeholder advisory with low trust.',
      cvss: 7.5, epss: 0.01, kev: false, fixed_version: null, major_bump: null,
      match: { confidence: 'uncertain', evidence: ['placeholder: only one source, ranges unspecified'] },
      risk: { score: 41, factors: [{ name: 'cvss', value: '7.5', weight: 0.3, contribution: 22 }] },
      trust: { score: 22, signals: [{ name: 'independent sources', value: '1', effect: 5, note: 'single source' }, { name: 'fix exists', value: 'no', effect: -10, note: 'no patched release found' }] },
      action: 'verify_first', recommendation: 'Placeholder: confirm the advisory before acting.',
      exposure: { exposed: false, path: [] },
      history: [{ date: '2025-03-01', risk: 41, epss: 0.01, event: 'advisory published', simulated: false }],
      watch: 'placeholder: EPSS trending up', review: null,
    },
  ],
}

export const fixtureGraph: ExposureGraph = {
  nodes: [
    { id: 'urls.py', label: 'urls.py', kind: 'entry' },
    { id: 'views.home', label: 'views.home', kind: 'module' },
    { id: 'example-web', label: 'example-web', kind: 'vulnerable' },
    { id: 'example-parser', label: 'example-parser', kind: 'package' },
  ],
  links: [
    { source: 'urls.py', target: 'views.home' },
    { source: 'views.home', target: 'example-web' },
  ],
  limitation: 'Placeholder text. The real limitation (import-level analysis, Python/Django only) comes from the backend.',
}

export const fixtureAudit: AuditEntry[] = []
