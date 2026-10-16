import { Tag } from '../components/primitives/Badge'
import { DataReadout } from '../components/primitives/DataReadout'
import { Panel } from '../components/primitives/Panel'
import { IconAudit } from '../lib/icons'
import type { AuditEntry } from '../lib/types'

export function ReviewLogView({ entries }: { entries: AuditEntry[] }) {
  if (entries.length === 0) {
    return (
      <div className="flex flex-1 items-center justify-center text-center font-mono text-[13px] text-on-surface-variant">
        No reviewer decisions recorded yet. Decisions you make in the Findings view appear here.
      </div>
    )
  }
  return (
    <Panel
      title="Audit log"
      icon={<IconAudit size={13} className="text-primary" />}
      aside={<DataReadout dim className="text-[10px]">{entries.length} entries, newest first</DataReadout>}
      bodyClassName="overflow-x-auto"
    >
      <table className="w-full min-w-[40rem] border-collapse text-left font-mono text-[11px]">
        <thead>
          <tr className="border-b border-outline-variant/60 text-[9px] uppercase tracking-wide text-on-surface-variant">
            {['when', 'finding', 'decision', 'reviewer', 'expires', 'note'].map((h) => <th key={h} className="px-3 py-2 font-medium">{h}</th>)}
          </tr>
        </thead>
        <tbody>
          {entries.map((e, i) => (
            <tr key={i} className="border-b border-outline-variant/40 align-top">
              <td className="px-3 py-2"><DataReadout dim>{e.at}</DataReadout></td>
              <td className="px-3 py-2 text-on-surface">{e.finding_id}</td>
              <td className="px-3 py-2"><Tag>{e.decision.replace('_', ' ')}</Tag></td>
              <td className="px-3 py-2 text-on-surface-variant">{e.reviewer}</td>
              <td className="px-3 py-2"><DataReadout dim>{e.expires ?? '-'}</DataReadout></td>
              <td className="px-3 py-2 font-sans text-[12px] text-on-surface">{e.note}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  )
}
