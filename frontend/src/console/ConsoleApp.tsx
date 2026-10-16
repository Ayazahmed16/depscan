import { useCallback, useEffect, useState } from 'react'
import { Footer, type Engine } from '../components/layout/Footer'
import { Header, type Mode } from '../components/layout/Header'
import { api } from '../lib/api'
import type { AuditEntry, ExposureGraph, Health, ReviewInput, ScanResult } from '../lib/types'
import { ExposureView } from './ExposureView'
import { FindingsView } from './FindingsView'
import { ReviewLogView } from './ReviewLogView'
import { TimelineView } from './TimelineView'

// Layout fixture is dev-only. `import.meta.env.DEV` is false in a production build,
// so the fixture module is dropped from the bundle.
// ?fixture=1 loads placeholder data; ?fixture=real loads a REAL scan of the frozen known sample (see tests/sample).
const fixtureMode = import.meta.env.DEV ? new URLSearchParams(window.location.search).get('fixture') : null
const useFixture = fixtureMode !== null

function EmptyState({ children }: { children: string }) {
  return <div className="flex flex-1 items-center justify-center text-center font-mono text-[13px] text-on-surface-variant">{children}</div>
}

export default function ConsoleApp() {
  const [mode, setMode] = useState<Mode>('findings')
  const [engine, setEngine] = useState<Engine>('connecting')
  const [health, setHealth] = useState<Health | null>(null)
  const [scan, setScan] = useState<ScanResult | null>(null)
  const [graph, setGraph] = useState<ExposureGraph | null>(null)
  const [audit, setAudit] = useState<AuditEntry[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadAll = useCallback(async () => {
    const [s, g, a] = await Promise.all([api.findings(), api.graph().catch(() => null), api.audit().catch(() => [])])
    setScan(s)
    setGraph(g)
    setAudit(a)
  }, [])

  useEffect(() => {
    if (useFixture) {
      import('../dev/layoutFixture').then(async (f) => {
        setHealth(f.fixtureHealth)
        setEngine('online')
        setScan(fixtureMode === 'real' ? ((await import('../dev/sampleScan.json')).default as unknown as ScanResult) : f.fixtureScan)
        setGraph(f.fixtureGraph)
        setAudit(f.fixtureAudit)
      })
      return
    }
    api.health()
      .then((h) => { setHealth(h); setEngine('online'); return loadAll() })
      .catch(() => setEngine('failed'))
  }, [loadAll])

  async function onUpload(file: File) {
    setBusy(true)
    setError(null)
    try {
      await api.scan(file)
      await loadAll()
      setSelectedId(null)
      setMode('findings')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'scan failed')
    } finally {
      setBusy(false)
    }
  }

  async function onReset() {
    await api.reset().catch(() => undefined)
    setScan(null)
    setGraph(null)
    setSelectedId(null)
    setError(null)
  }

  async function onReview(input: ReviewInput) {
    await api.review(input)
    await loadAll() // re-read so the table, detail panel and audit log all show the stored record
  }

  async function onRevoke(input: { key: string; note: string; reviewer: string }) {
    await api.revoke(input)
    await loadAll()
  }

  const findings = scan?.findings ?? []
  // Every view shares one selection. Until the user picks, it is the highest-risk finding,
  // which is also what the findings table shows as selected.
  const topFinding = [...findings].sort((a, b) => b.risk.score - a.risk.score)[0]
  const activeId = selectedId ?? (topFinding ? topFinding.key : null)
  const meta = scan
    ? [
        { label: 'source', value: scan.source },
        { label: 'findings', value: String(findings.length) },
        // pending or expired: a lapsed suppression needs a person again
        { label: 'needs review', value: String(findings.filter((f) => f.review_status === 'pending' || f.review_status === 'expired').length) },
      ]
    : []

  return (
    <div className="console flex min-h-screen flex-col bg-surface-container-lowest font-sans text-on-surface">
      <Header
        mode={mode}
        onModeChange={setMode}
        meta={meta}
        busy={busy}
        error={error}
        onUpload={onUpload}
        onReset={onReset}
        hasScan={!!scan}
      />
      {useFixture && (
        <p className="border-b border-signal-warning bg-surface-container px-5 py-1.5 text-center font-mono text-[11px] uppercase tracking-wide text-signal-warning">
          {fixtureMode === 'real' ? 'dev view: a real scan of the frozen known sample, not your project' : 'layout fixture: placeholder data, not a real scan'}
        </p>
      )}
      <main className="flex flex-1 flex-col overflow-y-auto">
        <section className="flex flex-1 flex-col gap-3 p-3">
          {engine === 'failed' ? (
            <EmptyState>The backend is unreachable. Start it with the run script, then reload this page.</EmptyState>
          ) : !scan ? (
            <EmptyState>Drop a requirements.txt, package.json or scan report in the bar above to begin. Files are only read, never changed.</EmptyState>
          ) : mode === 'findings' ? (
            <FindingsView findings={findings} selectedId={activeId} onSelect={setSelectedId} onReview={onReview} onRevoke={onRevoke} />
          ) : mode === 'exposure' ? (
            <ExposureView graph={graph} findings={findings} selectedId={activeId} />
          ) : mode === 'timeline' ? (
            <TimelineView findings={findings} selectedId={activeId} onSelect={setSelectedId} />
          ) : (
            <ReviewLogView entries={audit} />
          )}
        </section>
      </main>
      <Footer engine={engine} health={health} />
    </div>
  )
}
