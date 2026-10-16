import { useMemo, useState } from 'react'
import { Badge, Tag } from '../components/primitives/Badge'
import { DataReadout } from '../components/primitives/DataReadout'
import { Gauge } from '../components/primitives/Gauge'
import { Panel } from '../components/primitives/Panel'
import { IconRisk, IconTrust, IconWarning } from '../lib/icons'
import {
  ACTION_LABEL, ACTION_SIGNAL, riskSignal, SIGNAL_TEXT_CLASS, trustSignal,
} from '../lib/severity'
import { REQUIRED_NOTICE, type Finding, type ReviewDecision } from '../lib/types'

const DECISIONS: { id: ReviewDecision; label: string }[] = [
  { id: 'fix_now', label: 'fix now' },
  { id: 'accept_risk', label: 'accept risk' },
  { id: 'false_positive', label: 'false positive' },
]

export function FindingsView({ findings, selectedId, onSelect, onReview }: {
  findings: Finding[]
  selectedId: string | null
  onSelect: (id: string) => void
  onReview: (input: { finding_id: string; decision: ReviewDecision; note: string; reviewer: string; expires: string | null }) => Promise<void>
}) {
  // Highest risk first. The backend already orders them; this keeps the table stable if it ever does not.
  const sorted = useMemo(() => [...findings].sort((a, b) => b.risk.score - a.risk.score), [findings])
  const selected = sorted.find((f) => f.id + f.package === selectedId) ?? sorted[0] ?? null

  if (findings.length === 0) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-2 text-center font-mono text-[13px] text-on-surface-variant">
        <p>The scan completed with no matched findings.</p>
        <p className="text-on-surface">{REQUIRED_NOTICE}</p>
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
      <Panel
        title="Findings"
        icon={<IconWarning size={13} className="text-primary" />}
        aside={<DataReadout className="text-[10px]" dim>{findings.length} matched, ranked by risk</DataReadout>}
        className="lg:col-span-7"
        bodyClassName="overflow-x-auto"
      >
        <table className="w-full min-w-[34rem] border-collapse text-left font-mono text-[11px]">
          <thead>
            <tr className="border-b border-outline-variant/60 text-[9px] uppercase tracking-wide text-on-surface-variant">
              <th className="px-3 py-2 font-medium">Advisory</th>
              <th className="px-2 py-2 font-medium">Package</th>
              <th className="px-2 py-2 text-right font-medium">Risk</th>
              <th className="px-2 py-2 text-right font-medium">Trust</th>
              <th className="px-3 py-2 font-medium">Next step</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((f) => {
              const key = f.id + f.package
              const active = selected && key === selected.id + selected.package
              return (
                <tr
                  key={key}
                  onClick={() => onSelect(key)}
                  onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(key) } }}
                  tabIndex={0}
                  aria-selected={active ? true : undefined}
                  className={`cursor-pointer border-b border-outline-variant/40 transition-colors focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-primary hover:bg-surface-container ${active ? 'bg-surface-container' : ''}`}
                >
                  <td className="px-3 py-2 text-on-surface">
                    <span className="flex items-center gap-2">
                      <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${active ? 'bg-primary' : 'border border-on-surface-variant'}`} />
                      {f.id}
                    </span>
                  </td>
                  <td className="px-2 py-2 text-on-surface-variant">
                    {f.package}<span className="text-outline">@</span>{f.version}
                  </td>
                  <td className={`px-2 py-2 text-right tabular-nums ${SIGNAL_TEXT_CLASS[riskSignal(f.risk.score)]}`}>{Math.round(f.risk.score)}</td>
                  <td className={`px-2 py-2 text-right tabular-nums ${SIGNAL_TEXT_CLASS[trustSignal(f.trust.score)]}`}>{Math.round(f.trust.score)}</td>
                  <td className="px-3 py-2">
                    <span className="flex flex-wrap items-center gap-1.5">
                      <Badge signal={ACTION_SIGNAL[f.action]}>{ACTION_LABEL[f.action]}</Badge>
                      {f.review && <Tag>{f.review.decision.replace('_', ' ')}</Tag>}
                    </span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        <p className="border-t border-outline-variant/60 px-3 py-2 font-mono text-[9px] leading-relaxed text-on-surface-variant opacity-80">
          {REQUIRED_NOTICE} Scores are heuristics built from the signals shown on the right, not a measurement of real-world exploitability.
        </p>
      </Panel>

      <div className="flex flex-col gap-3 lg:col-span-5">
        {selected && <Detail key={selected.id + selected.package} finding={selected} onReview={onReview} />}
      </div>
    </div>
  )
}

function Detail({ finding: f, onReview }: {
  finding: Finding
  onReview: (input: { finding_id: string; decision: ReviewDecision; note: string; reviewer: string; expires: string | null }) => Promise<void>
}) {
  return (
    <>
      <Panel
        title={f.id}
        aside={<Badge signal={ACTION_SIGNAL[f.action]}>{ACTION_LABEL[f.action]}</Badge>}
        bodyClassName="flex flex-col gap-3 p-3"
      >
        <p className="font-sans text-[13px] leading-relaxed text-on-surface">{f.summary}</p>
        <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10px]">
          <Tag>{f.package}@{f.version}</Tag>
          <Tag>{f.ecosystem}</Tag>
          <Tag>{f.direct ? 'direct' : 'transitive'}</Tag>
          <Tag>{f.scope}</Tag>
          {f.aliases.map((a) => <Tag key={a}>{a}</Tag>)}
        </div>
        {/* Risk and trust side by side: this pair is what separates "fix now" from "verify first". */}
        <div className="grid grid-cols-2 gap-3 border-t border-outline-variant/60 pt-3">
          <div className="flex flex-col items-center gap-1">
            <span className="flex items-center gap-1 font-mono text-[9px] uppercase tracking-wide text-on-surface-variant"><IconRisk size={11} />risk</span>
            <Gauge value={f.risk.score} signal={riskSignal(f.risk.score)} label="Risk score" />
            <DataReadout className={`text-[22px] font-bold ${SIGNAL_TEXT_CLASS[riskSignal(f.risk.score)]}`}>{Math.round(f.risk.score)}</DataReadout>
          </div>
          <div className="flex flex-col items-center gap-1">
            <span className="flex items-center gap-1 font-mono text-[9px] uppercase tracking-wide text-on-surface-variant"><IconTrust size={11} />trust</span>
            <Gauge value={f.trust.score} signal={trustSignal(f.trust.score)} label="Trust score" invert />
            <DataReadout className={`text-[22px] font-bold ${SIGNAL_TEXT_CLASS[trustSignal(f.trust.score)]}`}>{Math.round(f.trust.score)}</DataReadout>
          </div>
        </div>
        <div className="flex w-full items-stretch divide-x divide-outline-variant border border-outline-variant">
          <Cell label="cvss" value={f.cvss === null ? 'n/a' : f.cvss.toFixed(1)} />
          <Cell label="epss" value={f.epss === null ? 'n/a' : `${(f.epss * 100).toFixed(1)}%`} />
          <Cell label="kev" value={f.kev ? 'listed' : 'no'} danger={f.kev} />
          <Cell label="fix" value={f.fixed_version ?? 'none'} />
        </div>
      </Panel>

      <Panel title="Recommendation" bodyClassName="flex flex-col gap-2 p-3">
        <p className="font-sans text-[13px] leading-relaxed text-on-surface">{f.recommendation}</p>
        {f.major_bump && (
          <p className="font-mono text-[10px] text-signal-warning">The suggested fix is a major-version bump. Check for breaking changes first.</p>
        )}
        <p className="font-mono text-[9px] leading-relaxed text-on-surface-variant opacity-80">
          Recommendation only. depscan never changes your dependency files; a person applies any fix.
        </p>
      </Panel>

      <Panel title="Why it matched" aside={<Badge signal={f.match.confidence === 'exact' ? 'info' : f.match.confidence === 'probable' ? 'warning' : 'critical'}>{f.match.confidence}</Badge>} bodyClassName="p-3">
        <ul className="flex flex-col gap-1 border border-outline-variant bg-surface-container-lowest p-2.5 font-mono text-[10px] leading-relaxed text-on-surface">
          {f.match.evidence.map((e, i) => <li key={i}>{e}</li>)}
        </ul>
      </Panel>

      <Panel title="Risk factors" bodyClassName="p-0">
        <FactorTable
          head={['factor', 'value', 'weight', 'adds']}
          rows={f.risk.factors.map((x) => [x.name, x.value, x.weight.toFixed(2), x.contribution.toFixed(1)])}
        />
      </Panel>

      <Panel title="Trust signals" bodyClassName="p-0">
        <FactorTable
          head={['signal', 'value', 'effect']}
          rows={f.trust.signals.map((x) => [x.name, x.value, (x.effect > 0 ? '+' : '') + x.effect.toFixed(0)])}
          notes={f.trust.signals.map((x) => x.note)}
        />
        <p className="border-t border-outline-variant/60 px-3 py-2 font-mono text-[9px] leading-relaxed text-on-surface-variant opacity-80">
          Trust is a heuristic about the advisory data. It says nothing about whether the vulnerability can be exploited in your app.
        </p>
      </Panel>

      <ReviewPanel finding={f} onReview={onReview} />
    </>
  )
}

function Cell({ label, value, danger = false }: { label: string; value: string; danger?: boolean }) {
  return (
    <div className="flex min-w-0 flex-1 flex-col items-center gap-0.5 px-1 py-2">
      <span className="font-mono text-[9px] uppercase tracking-wide text-on-surface-variant">{label}</span>
      <DataReadout className={`max-w-full truncate text-[13px] font-bold ${danger ? 'text-signal-critical' : ''}`}>{value}</DataReadout>
    </div>
  )
}

function FactorTable({ head, rows, notes }: { head: string[]; rows: string[][]; notes?: string[] }) {
  return (
    <table className="w-full border-collapse text-left font-mono text-[10px]">
      <thead>
        <tr className="border-b border-outline-variant/60 text-[9px] uppercase tracking-wide text-on-surface-variant">
          {head.map((h, i) => <th key={h} className={`px-3 py-1.5 font-medium ${i > 1 ? 'text-right' : ''}`}>{h}</th>)}
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="border-b border-outline-variant/40 align-top">
            {r.map((c, j) => <td key={j} className={`px-3 py-1.5 ${j === 0 ? 'text-on-surface' : 'text-on-surface-variant'} ${j > 1 ? 'text-right tabular-nums' : ''}`}>
              {c}
              {j === 0 && notes?.[i] && <span className="mt-0.5 block text-[9px] leading-snug opacity-80">{notes[i]}</span>}
            </td>)}
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function ReviewPanel({ finding: f, onReview }: {
  finding: Finding
  onReview: (input: { finding_id: string; decision: ReviewDecision; note: string; reviewer: string; expires: string | null }) => Promise<void>
}) {
  const [decision, setDecision] = useState<ReviewDecision>('fix_now')
  const [note, setNote] = useState('')
  const [reviewer, setReviewer] = useState('')
  const [expires, setExpires] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Suppressions must expire, so a forgotten "accept risk" cannot hide a finding forever.
  const needsExpiry = decision !== 'fix_now'
  const valid = note.trim().length > 0 && reviewer.trim().length > 0 && (!needsExpiry || expires !== '')

  async function submit() {
    setSaving(true)
    setError(null)
    try {
      await onReview({ finding_id: f.id, decision, note: note.trim(), reviewer: reviewer.trim(), expires: needsExpiry ? expires : null })
      setNote('')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'could not save')
    } finally {
      setSaving(false)
    }
  }

  const field = 'w-full border border-outline-variant bg-surface-container-lowest px-2 py-1.5 font-mono text-[11px] text-on-surface placeholder:text-outline focus:border-primary focus:outline-none'

  return (
    <Panel title="Human review" aside={f.review ? <Tag>{f.review.decision.replace('_', ' ')}</Tag> : <Tag>pending</Tag>} bodyClassName="flex flex-col gap-2.5 p-3">
      {f.review && (
        <p className="border border-outline-variant bg-surface-container-lowest p-2 font-mono text-[10px] leading-relaxed text-on-surface-variant">
          Last decision by <span className="text-on-surface">{f.review.reviewer}</span> on <span className="text-on-surface">{f.review.at}</span>
          {f.review.expires && <> (expires <span className="text-on-surface">{f.review.expires}</span>)</>}: {f.review.note}
        </p>
      )}
      <div className="flex flex-wrap gap-1" role="radiogroup" aria-label="Decision">
        {DECISIONS.map((d) => (
          <button
            key={d.id}
            type="button"
            role="radio"
            aria-checked={decision === d.id}
            onClick={() => setDecision(d.id)}
            className={`select-none border px-3 py-1.5 font-mono text-[11px] uppercase tracking-wide transition-colors ${
              decision === d.id ? 'border-primary bg-surface-container text-on-surface' : 'border-outline-variant text-on-surface-variant hover:text-on-surface'
            }`}
          >
            {d.label}
          </button>
        ))}
      </div>
      <input className={field} placeholder="reviewer name" value={reviewer} onChange={(e) => setReviewer(e.target.value)} aria-label="Reviewer name" />
      <textarea className={field} rows={2} placeholder="reason (required)" value={note} onChange={(e) => setNote(e.target.value)} aria-label="Reviewer note" />
      {needsExpiry && (
        <label className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-wide text-on-surface-variant">
          expires
          <input type="date" className={`${field} w-auto`} value={expires} onChange={(e) => setExpires(e.target.value)} />
        </label>
      )}
      {error && <p className="font-mono text-[10px] text-signal-critical">{error}</p>}
      <button
        type="button"
        disabled={!valid || saving}
        onClick={submit}
        className="select-none self-start border border-primary bg-primary px-3 py-1.5 font-mono text-[11px] uppercase tracking-wide text-on-primary transition-colors enabled:hover:bg-transparent enabled:hover:text-primary disabled:opacity-40"
      >
        {saving ? 'saving_' : 'record decision'}
      </button>
    </Panel>
  )
}
