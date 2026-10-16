import { useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D, { type ForceGraphMethods } from 'react-force-graph-2d'
import { Panel } from '../components/primitives/Panel'
import { IconGraph } from '../lib/icons'
import type { ExposureGraph, Finding } from '../lib/types'

// Canvas cannot read CSS variables, so the colours live here once.
// Each maps to a token in index.css.
const C = {
  entry: '#09090b',        // primary
  module: '#a1a1aa',       // outline
  package: '#71717a',      // on-surface-variant
  vulnerable: '#b42318',   // signal-critical
  edge: '#d4d4d8',         // outline-variant
  edgeActive: '#09090b',   // primary
  ring: '#71717a',
  text: '#09090b',
}

interface GNode { id: string; label: string; kind: string; x?: number; y?: number }

export function ExposureView({ graph, findings, selectedId }: {
  graph: ExposureGraph | null
  findings: Finding[]
  selectedId: string | null
}) {
  const box = useRef<HTMLDivElement>(null)
  const fg = useRef<ForceGraphMethods | undefined>(undefined)
  const [size, setSize] = useState({ w: 600, h: 480 })
  const [spotlight, setSpotlight] = useState(true)

  useEffect(() => {
    if (!box.current) return
    const ro = new ResizeObserver(([e]) => setSize({ w: e.contentRect.width, h: Math.max(360, e.contentRect.height) }))
    ro.observe(box.current)
    return () => ro.disconnect()
  }, [graph])

  const selected = findings.find((f) => f.key === selectedId) ?? null
  const path = useMemo(() => new Set(selected?.exposure?.path ?? []), [selected])
  const pathEdges = useMemo(() => {
    const p = selected?.exposure?.path ?? []
    const s = new Set<string>()
    for (let i = 0; i < p.length - 1; i++) s.add(p[i] + '>' + p[i + 1])
    return s
  }, [selected])

  const data = useMemo(() => graph && ({
    nodes: graph.nodes.map((n) => ({ ...n })),
    links: graph.links.map((l) => ({ ...l })),
  }), [graph])

  if (!graph || graph.nodes.length === 0) {
    return (
      <div className="flex flex-1 items-center justify-center text-center font-mono text-[13px] text-on-surface-variant">
        No exposure graph yet. Scan a Django project folder to trace routes to vulnerable packages.
      </div>
    )
  }

  const active = spotlight && path.size > 0
  const linkKey = (l: { source?: unknown; target?: unknown }) => {
    const s = typeof l.source === 'object' ? (l.source as GNode).id : String(l.source)
    const t = typeof l.target === 'object' ? (l.target as GNode).id : String(l.target)
    return s + '>' + t
  }

  return (
    <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
      <Panel
        title="Exposure paths"
        icon={<IconGraph size={13} className="text-primary" />}
        aside={
          <button
            type="button"
            onClick={() => setSpotlight((s) => !s)}
            aria-pressed={spotlight}
            className={`flex select-none items-center gap-1.5 border px-3 py-1 font-mono text-[11px] uppercase tracking-wide transition-colors ${
              spotlight ? 'border-signal-critical text-signal-critical' : 'border-outline-variant text-on-surface-variant hover:text-on-surface'
            }`}
          >
            spotlight {spotlight ? 'on' : 'off'}
          </button>
        }
        className="lg:col-span-8"
      >
        <div ref={box} className="h-[32rem] w-full overflow-hidden bg-surface-container-lowest">
          <ForceGraph2D
            width={size.w}
            height={size.h}
            graphData={data ?? { nodes: [], links: [] }}
            nodeRelSize={5}
            ref={fg}
            cooldownTicks={120}
            onEngineStop={() => fg.current?.zoomToFit(400, 90)}
            linkColor={(l) => (active && pathEdges.has(linkKey(l)) ? C.edgeActive : C.edge)}
            linkWidth={(l) => (active && pathEdges.has(linkKey(l)) ? 2.5 : 1)}
            linkDirectionalArrowLength={4}
            linkDirectionalArrowRelPos={1}
            nodeCanvasObject={(node, ctx, scale) => {
              const n = node as GNode
              const x = n.x ?? 0
              const y = n.y ?? 0
              const dim = active && !path.has(n.id)
              ctx.globalAlpha = dim ? 0.15 : 1
              const r = n.kind === 'entry' ? 6 : 4.5
              ctx.beginPath()
              ctx.arc(x, y, r, 0, Math.PI * 2)
              ctx.fillStyle = C[n.kind as keyof typeof C] ?? C.package
              ctx.fill()
              if (active && path.has(n.id)) {
                ctx.beginPath()
                ctx.arc(x, y, 9, 0, Math.PI * 2)
                ctx.strokeStyle = C.ring
                ctx.lineWidth = 1.5 / scale
                ctx.stroke()
              }
              if (scale > 0.9 || path.has(n.id)) {
                // 10px on screen at any zoom, placed just below the node (and its highlight ring)
                ctx.font = `${10 / scale}px JetBrains Mono, monospace`
                ctx.fillStyle = C.text
                ctx.textAlign = 'center'
                ctx.textBaseline = 'top'
                ctx.fillText(n.label, x, y + (active && path.has(n.id) ? 9 : r) + 4 / scale)
              }
              ctx.globalAlpha = 1
            }}
            nodePointerAreaPaint={(node, color, ctx) => {
              const n = node as GNode
              ctx.fillStyle = color
              ctx.beginPath()
              ctx.arc(n.x ?? 0, n.y ?? 0, 8, 0, Math.PI * 2)
              ctx.fill()
            }}
          />
        </div>
      </Panel>

      <div className="flex flex-col gap-3 lg:col-span-4">
        <Panel title="Selected finding" bodyClassName="flex flex-col gap-2 p-3">
          {selected ? (
            <>
              <p className="font-mono text-[11px] text-on-surface">{selected.id} <span className="text-on-surface-variant">{selected.package}@{selected.version}</span></p>
              {selected.exposure ? (
                <>
                  <p className={`font-mono text-[10px] uppercase tracking-wide ${selected.exposure.exposed ? 'text-signal-critical' : 'text-on-surface-variant'}`}>
                    {selected.exposure.exposed ? 'reachable from an entry point' : 'not reached from an entry point'}
                  </p>
                  <ol className="flex flex-col gap-1 border border-outline-variant bg-surface-container-lowest p-2.5 font-mono text-[10px] leading-relaxed">
                    {selected.exposure.path.map((p, i) => <li key={i} className="text-on-surface">{i + 1}. {p}</li>)}
                  </ol>
                </>
              ) : (
                <p className="font-mono text-[10px] text-on-surface-variant">No path data for this finding.</p>
              )}
            </>
          ) : (
            <p className="font-mono text-[10px] text-on-surface-variant">Pick a finding in the Findings view to highlight its path.</p>
          )}
        </Panel>
        <Panel title="Legend" bodyClassName="grid grid-cols-2 gap-2 p-3 font-mono text-[10px] text-on-surface-variant">
          {([['entry', 'route / entry point'], ['module', 'view module'], ['package', 'package'], ['vulnerable', 'vulnerable package']] as const).map(([k, label]) => (
            <span key={k} className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full" style={{ background: C[k] }} />
              {label}
            </span>
          ))}
        </Panel>
        <p className="font-mono text-[9px] leading-relaxed text-on-surface-variant opacity-80">
          {graph.limitation}
        </p>
      </div>
    </div>
  )
}
