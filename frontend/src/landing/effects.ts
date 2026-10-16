// Landing-page motion: a rotating dependency graph on the disc, faint drifting waves,
// scroll reveals and the disc shrinking as you scroll. Plain DOM + 2D canvas.
// `initLanding` returns a cleanup function, so a SPA route change leaks nothing.

type P3 = [number, number, number]

const rotY = ([x, y, z]: P3, a: number): P3 => { const c = Math.cos(a), s = Math.sin(a); return [x * c + z * s, y, -x * s + z * c] }
const rotX = ([x, y, z]: P3, a: number): P3 => { const c = Math.cos(a), s = Math.sin(a); return [x, y * c - z * s, y * s + z * c] }

interface GNode { p: P3; ring: 0 | 1 | 2; parent: number; phase: number; hot: boolean }

// Decorative only: a root package, direct dependencies on a ring, transitive ones on an outer ring.
// It does not depict any real scan.
function buildGraph(): GNode[] {
  const nodes: GNode[] = [{ p: [0, 0, 0], ring: 0, parent: -1, phase: 0, hot: false }]
  const direct = 7
  for (let i = 0; i < direct; i++) {
    const a = (i / direct) * Math.PI * 2
    const y = ((i % 3) - 1) * 0.22
    nodes.push({ p: [Math.cos(a) * 0.5, y, Math.sin(a) * 0.5], ring: 1, parent: 0, phase: i, hot: false })
  }
  const outer = 17
  for (let i = 0; i < outer; i++) {
    const parent = 1 + (i % direct)
    const base = nodes[parent].p
    const a = Math.atan2(base[2], base[0]) + ((i % 3) - 1) * 0.42
    const y = base[1] + (((i * 7) % 5) - 2) * 0.1
    nodes.push({ p: [Math.cos(a) * 0.9, y, Math.sin(a) * 0.9], ring: 2, parent, phase: i * 1.7, hot: i === 3 || i === 11 })
  }
  return nodes
}

function setupCanvas(el: HTMLCanvasElement) {
  const ctx = el.getContext('2d')
  if (!ctx) return null
  const state = { w: 0, h: 0 }
  const size = () => {
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    state.w = el.clientWidth
    state.h = el.clientHeight
    el.width = Math.round(state.w * dpr)
    el.height = Math.round(state.h * dpr)
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  }
  size()
  return { ctx, state, size }
}

export function initLanding(root: HTMLElement): () => void {
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
  const cleanups: (() => void)[] = []
  const raf = (fn: (ms: number) => void) => {
    let id = 0
    const tick = (ms: number) => { if (!document.hidden) fn(ms); id = requestAnimationFrame(tick) }
    id = requestAnimationFrame(tick)
    cleanups.push(() => cancelAnimationFrame(id))
  }

  /* ---------- Disc: rotating dependency graph ---------- */
  const graphEl = root.querySelector<HTMLCanvasElement>('#depgraph')
  const g = graphEl && setupCanvas(graphEl)
  if (graphEl && g) {
    const nodes = buildGraph()
    const tilt = 0.5
    const draw = (yaw: number) => {
      const { ctx, state } = g
      ctx.clearRect(0, 0, state.w, state.h)
      const cx = state.w / 2, cy = state.h / 2, R = Math.min(state.w, state.h) * 0.4
      const proj = nodes.map((n) => {
        const r = rotX(rotY(n.p, yaw), tilt)
        return { x: cx + r[0] * R, y: cy - r[1] * R, z: r[2] }
      })
      ctx.lineWidth = 1
      for (let i = 1; i < nodes.length; i++) {
        const a = proj[i], b = proj[nodes[i].parent]
        const depth = 0.35 + 0.65 * ((a.z + b.z) / 2 + 1) / 2
        ctx.strokeStyle = `rgba(255,255,255,${0.32 * depth})`
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke()
      }
      const now = performance.now() / 1000
      // far nodes first so near ones draw on top
      const order = proj.map((_, i) => i).sort((i, j) => proj[i].z - proj[j].z)
      for (const i of order) {
        const n = nodes[i], p = proj[i]
        const depth = 0.55 + 0.45 * (p.z + 1) / 2
        const pulse = n.hot && !reduceMotion ? 0.5 + 0.5 * Math.sin(now * 2 + n.phase) : 0
        const r = (n.ring === 0 ? 6 : n.ring === 1 ? 3.6 : 2.6) * depth
        if (n.hot) {
          ctx.beginPath(); ctx.fillStyle = `rgba(255,255,255,${0.14 + 0.1 * pulse})`
          ctx.arc(p.x, p.y, r + 7 + 4 * pulse, 0, Math.PI * 2); ctx.fill()
        }
        ctx.beginPath(); ctx.fillStyle = `rgba(255,255,255,${0.9 * depth})`
        ctx.arc(p.x, p.y, r, 0, Math.PI * 2); ctx.fill()
      }
    }
    draw(0.6)
    const ro = new ResizeObserver(() => { g.size(); if (reduceMotion) draw(0.6) })
    ro.observe(graphEl)
    cleanups.push(() => ro.disconnect())
    if (!reduceMotion) raf((ms) => draw(0.6 + (ms / 1000) * 0.09)) // one turn about 70 s
  }

  /* ---------- Waves behind the hero copy ---------- */
  const wavesEl = root.querySelector<HTMLCanvasElement>('#waves')
  const w = wavesEl && setupCanvas(wavesEl)
  if (wavesEl && w) {
    const lines = [
      { y: 0.14, amp: 16, k: 0.011, speed: 0.5, alpha: 0.16, kind: 'sine' },
      { y: 0.3, amp: 22, k: 0.007, speed: -0.35, alpha: 0.13, kind: 'am' },
      { y: 0.48, amp: 14, k: 0.016, speed: 0.7, alpha: 0.15, kind: 'fsk' },
      { y: 0.66, amp: 26, k: 0.005, speed: -0.25, alpha: 0.12, kind: 'sine' },
      { y: 0.82, amp: 18, k: 0.013, speed: 0.45, alpha: 0.14, kind: 'am' },
    ]
    const draw = (time: number) => {
      const { ctx, state } = w
      ctx.clearRect(0, 0, state.w, state.h)
      ctx.lineWidth = 1.25
      for (const l of lines) {
        ctx.strokeStyle = `rgba(0,0,0,${l.alpha})`
        ctx.beginPath()
        for (let x = 0; x <= state.w; x += 3) {
          const p = x * l.k + time * l.speed
          let a = l.amp, phase = p
          if (l.kind === 'am') a *= 0.55 + 0.45 * Math.sin(x * 0.0035 - time * 0.4)
          if (l.kind === 'fsk') phase = p * (Math.sin(x * 0.004 + time * 0.3) > 0 ? 1.7 : 1)
          const y = l.y * state.h + a * Math.sin(phase)
          if (x === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y)
        }
        ctx.stroke()
      }
    }
    draw(0)
    const ro = new ResizeObserver(() => { w.size(); if (reduceMotion) draw(0) })
    ro.observe(wavesEl)
    cleanups.push(() => ro.disconnect())
    if (!reduceMotion) raf((ms) => draw(ms / 1000))
  }

  /* ---------- Notice dismiss ---------- */
  const close = root.querySelector('.notice__close')
  const dismiss = () => root.querySelector('#notice')?.setAttribute('hidden', '')
  close?.addEventListener('click', dismiss)
  cleanups.push(() => close?.removeEventListener('click', dismiss))

  /* ---------- Reveal on scroll: toggled both ways, so scrolling up reverses it ---------- */
  const targets = root.querySelectorAll('[data-reveal]')
  if (reduceMotion || !('IntersectionObserver' in window)) {
    targets.forEach((el) => el.classList.add('is-visible'))
  } else {
    const io = new IntersectionObserver(
      (entries) => { for (const e of entries) e.target.classList.toggle('is-visible', e.isIntersecting) },
      { threshold: 0.15, rootMargin: '0px 0px -10% 0px' },
    )
    targets.forEach((el) => io.observe(el))
    cleanups.push(() => io.disconnect())
  }

  /* ---------- Disc as a scroll instrument (desktop only) ---------- */
  const disc = root.querySelector<HTMLElement>('.disc')
  const wordmark = root.querySelector<HTMLElement>('.wordmark')
  const hero = root.querySelector<HTMLElement>('.hero')
  const desktop = window.matchMedia('(min-width: 52rem)')
  if (disc && wordmark && hero && !reduceMotion) {
    const clamp01 = (v: number) => Math.min(1, Math.max(0, v))
    const easeOut = (t: number) => 1 - (1 - t) ** 3
    let ticking = false
    const paint = () => {
      ticking = false
      if (!desktop.matches) { disc.style.transform = ''; wordmark.style.opacity = ''; wordmark.style.transform = ''; return }
      const t = easeOut(clamp01(window.scrollY / (hero.offsetHeight * 0.85)))
      disc.style.transform = `translate(${-0.16 * hero.offsetHeight * t}px, ${-0.22 * hero.offsetHeight * t}px) scale(${1 - 0.4 * t})`
      wordmark.style.opacity = String(1 - t)
      wordmark.style.transform = `translateY(${-30 * t}px)`
    }
    const onScroll = () => { if (!ticking) { ticking = true; requestAnimationFrame(paint) } }
    window.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('resize', onScroll)
    cleanups.push(() => { window.removeEventListener('scroll', onScroll); window.removeEventListener('resize', onScroll) })
    paint()
  }

  return () => cleanups.forEach((fn) => fn())
}
