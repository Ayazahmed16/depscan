import { SIGNAL_HEX, type Signal } from '../../lib/severity'

// Semicircular dial for a bounded 0-100 value. Zones are drawn left to right:
// risk goes info -> critical, trust goes critical -> info (`invert`).
const CX = 100
const CY = 96
const R = 78

function polar(pct: number, radius = R) {
  const a = Math.PI * (1 - pct / 100)
  return { x: CX + radius * Math.cos(a), y: CY - radius * Math.sin(a) }
}
function arc(from: number, to: number) {
  const s = polar(from)
  const e = polar(to)
  return `M ${s.x.toFixed(2)} ${s.y.toFixed(2)} A ${R} ${R} 0 0 1 ${e.x.toFixed(2)} ${e.y.toFixed(2)}`
}

export function Gauge({ value, signal, label, invert = false }: {
  value: number
  signal: Signal
  label: string
  invert?: boolean
}) {
  const v = Math.max(0, Math.min(100, value))
  const zones: Signal[] = invert ? ['critical', 'warning', 'info'] : ['info', 'warning', 'critical']
  const bounds = [0, 30, 60, 100]
  const rotation = -90 + (v / 100) * 180 // needle points straight up at 50

  return (
    <svg viewBox="-14 -8 228 114" className="w-full max-w-60" role="img" aria-label={`${label}: ${Math.round(v)} out of 100`}>
      {zones.map((z, i) => (
        <path key={i} d={arc(bounds[i], bounds[i + 1])} fill="none" stroke={SIGNAL_HEX[z]} strokeWidth={10} opacity={0.85} />
      ))}
      {[0, 25, 50, 75, 100].map((t) => {
        const p = polar(t, R + 10)
        const anchor = t === 0 ? 'end' : t === 100 ? 'start' : 'middle'
        return (
          <text key={t} x={p.x} y={p.y + 3} textAnchor={anchor} fontFamily="JetBrains Mono" fontSize={9} fill="#71717a">
            {t}
          </text>
        )
      })}
      <g style={{ transformOrigin: `${CX}px ${CY}px`, transform: `rotate(${rotation}deg)`, transition: 'transform 700ms cubic-bezier(0.2, 0.8, 0.2, 1)' }}>
        <line x1={CX} y1={CY} x2={CX} y2={CY - R + 12} stroke={SIGNAL_HEX[signal]} strokeWidth={2} />
      </g>
      <circle cx={CX} cy={CY} r={4.5} fill={SIGNAL_HEX[signal]} />
    </svg>
  )
}
