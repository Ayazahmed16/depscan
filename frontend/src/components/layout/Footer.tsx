import type { Health } from '../../lib/types'
import { REQUIRED_NOTICE } from '../../lib/types'

export type Engine = 'connecting' | 'online' | 'failed'

export function Footer({ engine, health }: { engine: Engine; health: Health | null }) {
  return (
    <footer className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 border-t border-outline-variant bg-surface-container-lowest px-5 py-2 font-mono text-[11px] text-on-surface-variant">
      <div className="flex flex-wrap items-center gap-3">
        {engine === 'online' && (
          <span className="flex items-center gap-1.5 font-medium text-signal-info">
            <span className="h-1.5 w-1.5 rounded-full bg-signal-info" />engine: online
          </span>
        )}
        {engine === 'failed' && (
          <span className="flex items-center gap-1.5 font-medium text-signal-critical">
            <span className="h-1.5 w-1.5 rounded-full bg-signal-critical" />backend unreachable
          </span>
        )}
        {engine === 'connecting' && (
          <span className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-outline" />connecting
          </span>
        )}
        {health && (['osv', 'nvd', 'kev', 'epss'] as const).map((k) => (
          <span key={k} className="flex items-center gap-3">
            <span className="text-outline-variant">/</span>
            <span>{k} <span className={health.snapshots[k] ? 'text-on-surface' : 'text-signal-warning'}>{health.snapshots[k] ?? 'missing'}</span></span>
          </span>
        ))}
      </div>
      <p className="text-on-surface">{REQUIRED_NOTICE}</p>
    </footer>
  )
}
