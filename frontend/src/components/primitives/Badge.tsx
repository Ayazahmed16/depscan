import type { ReactNode } from 'react'
import { SIGNAL_BORDER_CLASS, SIGNAL_TEXT_CLASS, type Signal } from '../../lib/severity'

// Outlined (never filled) status tag. Colour maps to a real signal only.
export function Badge({ signal, children }: { signal: Signal; children: ReactNode }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 border px-1.5 py-0.5 font-mono text-[10px] font-medium uppercase tracking-wide ${SIGNAL_BORDER_CLASS[signal]} ${SIGNAL_TEXT_CLASS[signal]}`}
    >
      {children}
    </span>
  )
}

// Neutral variant for tags that carry no severity (e.g. "direct", "dev").
export function Tag({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex items-center border border-outline-variant px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-on-surface-variant">
      {children}
    </span>
  )
}
