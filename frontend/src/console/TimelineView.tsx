import {
  Area, CartesianGrid, ComposedChart, Line, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { Badge, Tag } from '../components/primitives/Badge'
import { DataReadout } from '../components/primitives/DataReadout'
import { Panel } from '../components/primitives/Panel'
import { IconTimeline, IconWatch } from '../lib/icons'
import type { Finding } from '../lib/types'

const AXIS_TICK = { fill: '#71717a', fontFamily: 'JetBrains Mono', fontSize: 10 }
const AXIS_LINE = { stroke: '#d4d4d8' }
const TOOLTIP_STYLE = { background: '#ffffff', border: '1px solid #d4d4d8', fontFamily: 'JetBrains Mono', fontSize: 11 }
const DATA = '#0e7490' // token: --color-data

export function TimelineView({ findings, selectedId, onSelect }: {
  findings: Finding[]
  selectedId: string | null
  onSelect: (id: string) => void
}) {
  const selected = findings.find((f) => f.key === selectedId) ?? findings[0] ?? null
  const watch = findings.filter((f) => f.watch)

  if (!selected) {
    return (
      <div className="flex flex-1 items-center justify-center text-center font-mono text-[13px] text-on-surface-variant">
        No findings to show history for. Scan a dependency file first.
      </div>
    )
  }

  const points = [...selected.history].sort((a, b) => a.date.localeCompare(b.date))
  const anySimulated = points.some((p) => p.simulated)
  const events = points.filter((p) => p.event)

  return (
    <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
      <div className="flex flex-col gap-3 lg:col-span-8">
        <Panel
          title={`Priority over time: ${selected.id}`}
          icon={<IconTimeline size={13} className="text-primary" />}
          aside={anySimulated ? <Badge signal="warning">contains simulated points</Badge> : <Tag>real dated data</Tag>}
          bodyClassName="h-64 shrink-0 p-2"
        >
          {points.length < 2 ? (
            <div className="flex h-full items-center justify-center text-center font-mono text-[12px] text-on-surface-variant">
              Fewer than two dated points exist for this finding, so no trend can be drawn.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={points} margin={{ top: 8, right: 12, bottom: 0, left: -12 }}>
                <defs>
                  <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={DATA} stopOpacity={0.2} />
                    <stop offset="100%" stopColor={DATA} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#d4d4d8" strokeDasharray="1 6" vertical={false} />
                <XAxis dataKey="date" tick={AXIS_TICK} axisLine={AXIS_LINE} tickLine={false} />
                <YAxis domain={[0, 100]} tick={AXIS_TICK} axisLine={AXIS_LINE} tickLine={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Area type="stepAfter" dataKey="risk" name="risk score" stroke={DATA} strokeWidth={2} fill="url(#riskFill)" animationDuration={600} />
                <Line
                  type="stepAfter"
                  dataKey="risk"
                  stroke="none"
                  dot={(p) => {
                    const { cx, cy, payload, index } = p as { cx: number; cy: number; payload: { simulated: boolean }; index: number }
                    return (
                      <circle
                        key={index}
                        cx={cx}
                        cy={cy}
                        r={3.5}
                        fill={payload.simulated ? '#ffffff' : DATA}
                        stroke={DATA}
                        strokeWidth={1.5}
                        strokeDasharray={payload.simulated ? '2 2' : undefined}
                      />
                    )
                  }}
                  isAnimationActive={false}
                />
              </ComposedChart>
            </ResponsiveContainer>
          )}
        </Panel>

        <Panel title="Events" bodyClassName="p-0">
          {events.length === 0 ? (
            <p className="p-3 font-mono text-[11px] text-on-surface-variant">No dated events recorded for this finding.</p>
          ) : (
            <ul className="divide-y divide-outline-variant/40 font-mono text-[11px]">
              {events.map((p) => (
                <li key={p.date + p.event} className="flex items-center justify-between gap-3 px-3 py-2">
                  <span className="flex items-center gap-3">
                    <DataReadout dim>{p.date}</DataReadout>
                    <span className="text-on-surface">{p.event}</span>
                  </span>
                  {p.simulated ? <Badge signal="warning">[simulated]</Badge> : <span className="text-[9px] uppercase tracking-wide text-on-surface-variant">[observed]</span>}
                </li>
              ))}
            </ul>
          )}
          <p className="border-t border-outline-variant/60 px-3 py-2 font-mono text-[9px] leading-relaxed text-on-surface-variant opacity-80">
            Solid points come from real dates in the data (advisory published or modified, KEV date added, EPSS files). Hollow dashed points are simulated and never evidence of real history.
          </p>
        </Panel>
      </div>

      <div className="flex flex-col gap-3 lg:col-span-4">
        <Panel title="Findings" bodyClassName="max-h-60 overflow-y-auto p-0">
          <ul className="divide-y divide-outline-variant/40 font-mono text-[11px]">
            {findings.map((f) => {
              const key = f.key
              const active = key === selected.key
              return (
                <li key={key}>
                  <button
                    type="button"
                    onClick={() => onSelect(key)}
                    className={`flex w-full items-center justify-between gap-2 px-3 py-2 text-left transition-colors hover:bg-surface-container ${active ? 'bg-surface-container text-on-surface' : 'text-on-surface-variant'}`}
                  >
                    <span className="truncate">{f.id}</span>
                    <span className="shrink-0 text-[10px]">{f.package}</span>
                  </button>
                </li>
              )
            })}
          </ul>
        </Panel>
        <Panel title="Watchlist" icon={<IconWatch size={13} className="text-primary" />} aside={<DataReadout dim className="text-[10px]">{watch.length}</DataReadout>} bodyClassName="p-0">
          {watch.length === 0 ? (
            <p className="p-3 font-mono text-[11px] text-on-surface-variant">Nothing flagged as likely to become urgent.</p>
          ) : (
            <ul className="divide-y divide-outline-variant/40">
              {watch.map((f) => (
                <li key={f.key} className="flex flex-col gap-0.5 px-3 py-2">
                  <span className="font-mono text-[11px] text-on-surface">{f.id} <span className="text-on-surface-variant">{f.package}</span></span>
                  <span className="font-mono text-[10px] leading-snug text-on-surface-variant">{f.watch}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  )
}
