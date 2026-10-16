import { useEffect, useState } from 'react'
import { Panel } from '../components/primitives/Panel'
import { api } from '../lib/api'
import type { WeightsView } from '../lib/types'

// Edit the risk weights (docs/SCORING.md). Saving re-scores the current scan on the backend.
// The weights must add up to 1; the backend checks that too and normalises tiny rounding differences.
export function WeightsPanel({ onChanged }: { onChanged: () => Promise<void> }) {
  const [view, setView] = useState<WeightsView | null>(null)
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [message, setMessage] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  function show(v: WeightsView) {
    setView(v)
    setDraft(Object.fromEntries(Object.entries(v.weights).map(([k, w]) => [k, String(w)])))
  }

  useEffect(() => {
    api.weights().then(show).catch(() => setMessage('weights unavailable'))
  }, [])

  if (!view) return <p className="p-3 font-mono text-[11px] text-on-surface-variant">{message ?? 'loading weights_'}</p>

  const total = Object.values(draft).reduce((sum, v) => sum + (Number(v) || 0), 0)
  const valid = Object.values(draft).every((v) => v.trim() !== '' && Number(v) >= 0) && Math.abs(total - 1) <= 0.01

  async function save(action: () => Promise<WeightsView>) {
    setBusy(true)
    setMessage(null)
    try {
      const v = await action()
      show(v)
      await onChanged()
      setMessage(v.rescored ? 'saved; the current scan was re-scored' : 'saved; applies to the next scan')
    } catch (e) {
      setMessage(e instanceof Error ? e.message : 'could not save')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Panel title="Risk weights" aside={<span className="font-mono text-[10px] text-on-surface-variant">{view.customised ? 'customised' : 'defaults'}</span>} bodyClassName="flex flex-col gap-3 p-3">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        {Object.keys(view.weights).map((name) => (
          <label key={name} className="flex flex-col gap-1 font-mono text-[10px] uppercase tracking-wide text-on-surface-variant">
            {name.replace(/_/g, ' ')}
            <input
              type="number"
              min={0}
              max={1}
              step={0.05}
              value={draft[name] ?? ''}
              onChange={(e) => setDraft({ ...draft, [name]: e.target.value })}
              className="border border-outline-variant bg-surface-container-lowest px-2 py-1 text-[12px] text-on-surface"
            />
            <span className="normal-case opacity-70">default {view.defaults[name]}</span>
          </label>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-3 font-mono text-[11px] text-on-surface-variant">
        <span className={valid ? '' : 'text-signal-critical'}>total {total.toFixed(2)} (must be 1.00)</span>
        <button
          type="button"
          disabled={!valid || busy}
          onClick={() => save(() => api.setWeights(Object.fromEntries(Object.entries(draft).map(([k, v]) => [k, Number(v)]))))}
          className="border border-outline-variant bg-surface-container px-2.5 py-1.5 uppercase tracking-wider text-on-surface enabled:hover:text-primary disabled:opacity-40"
        >
          save and re-score
        </button>
        <button
          type="button"
          disabled={!view.customised || busy}
          onClick={() => save(() => api.resetWeights())}
          className="border border-outline-variant bg-surface-container px-2.5 py-1.5 uppercase tracking-wider enabled:hover:text-signal-critical disabled:opacity-40"
        >
          back to defaults
        </button>
        {message && <span className="text-on-surface">{message}</span>}
      </div>
      <p className="font-mono text-[9px] leading-relaxed text-on-surface-variant opacity-80">
        Weights change the ranking, not the evidence. A factor that cannot be computed (for example exposure with no project folder) is dropped and the rest renormalised.
      </p>
    </Panel>
  )
}
