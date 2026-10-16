import { useRef, useState } from 'react'
import { IconReset, IconUpload } from '../../lib/icons'

export type Mode = 'findings' | 'exposure' | 'timeline' | 'review'

const MODES: { id: Mode; label: string }[] = [
  { id: 'findings', label: 'findings' },
  { id: 'exposure', label: 'exposure' },
  { id: 'timeline', label: 'timeline' },
  { id: 'review', label: 'review log' },
]

export function Header({ mode, onModeChange, meta, busy, error, onUpload, onReset, hasScan }: {
  mode: Mode
  onModeChange: (m: Mode) => void
  meta: { label: string; value: string }[]
  busy: boolean
  error: string | null
  onUpload: (file: File) => void
  onReset: () => void
  hasScan: boolean
}) {
  const input = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)

  return (
    <header className="sticky top-0 z-50 flex w-full flex-col border-b border-outline-variant bg-surface-container-lowest">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-outline-variant/60 px-5 py-2.5">
        <a href="/" className="flex items-center gap-2 font-sans text-sm font-semibold tracking-tight text-on-surface">
          <span className="h-2 w-2 rounded-full bg-primary" />
          depscan // dependency triage
        </a>
        <div className="flex items-center gap-3">
          {/* The drop zone doubles as the file picker. The file is only read, never modified. */}
          <button
            type="button"
            disabled={busy}
            onClick={() => input.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault()
              setDragging(false)
              const f = e.dataTransfer.files[0]
              if (f) onUpload(f)
            }}
            className={`flex h-8 min-w-64 cursor-pointer items-center gap-2 border px-2.5 font-mono text-[10px] uppercase tracking-wider transition-colors ${
              dragging ? 'border-primary bg-primary/10 text-on-surface' : 'border-outline-variant bg-surface-container text-on-surface-variant hover:text-on-surface'
            }`}
          >
            <IconUpload size={13} />
            {busy ? (
              <span className="animate-pulse text-signal-info">reading file_</span>
            ) : error ? (
              <span className="max-w-56 truncate text-signal-critical">{error}</span>
            ) : (
              'drop requirements.txt / package.json / report'
            )}
          </button>
          <input
            ref={input}
            type="file"
            accept=".txt,.json"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) onUpload(f)
              e.target.value = ''
            }}
          />
          <button
            type="button"
            onClick={onReset}
            disabled={!hasScan}
            className="flex select-none items-center gap-1.5 border border-outline-variant bg-surface-container px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider text-on-surface-variant transition-colors enabled:hover:text-signal-critical disabled:opacity-40"
          >
            <IconReset size={11} />
            reset
          </button>
        </div>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2 px-5 py-2">
        <nav className="flex flex-wrap items-center gap-1" aria-label="Views">
          {MODES.map((m) => (
            <button
              key={m.id}
              type="button"
              onClick={() => onModeChange(m.id)}
              aria-current={mode === m.id ? 'page' : undefined}
              className={`flex select-none items-center gap-1.5 border px-3 py-1.5 font-mono text-[11px] uppercase tracking-wider transition-colors ${
                mode === m.id ? 'border-outline-variant bg-surface-container text-on-surface' : 'border-transparent text-on-surface-variant hover:text-on-surface'
              }`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${mode === m.id ? 'bg-primary' : 'border border-on-surface-variant'}`} />
              {m.label}
            </button>
          ))}
        </nav>
        <div className="flex flex-wrap items-center gap-x-3 font-mono text-[11px] text-on-surface-variant">
          {meta.map((m, i) => (
            <span key={m.label} className="flex items-center gap-3">
              {i > 0 && <span className="text-outline-variant">/</span>}
              <span>{m.label} <span className="text-on-surface">{m.value}</span></span>
            </span>
          ))}
        </div>
      </div>
    </header>
  )
}
