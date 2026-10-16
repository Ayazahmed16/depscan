import { useEffect, useRef } from 'react'
import { REQUIRED_NOTICE } from '../lib/types'
import { initLanding } from './effects'
import './landing.css'

// Real processing stages of the tool (see the project plan), in order.
const STAGES: [string, string][] = [
  ['Read your files', 'requirements.txt, package.json or a pre-generated scan report. Read-only.'],
  ['Match advisories', 'Versions are compared with affected ranges in cached OSV and NVD data, with the evidence kept.'],
  ['Score the risk', 'Severity, exploit likelihood, known exploitation, fix availability, direct or transitive, runtime or dev.'],
  ['Score the trust', 'Independent sources, agreeing ranges, withdrawn status, freshness, and whether a fix really exists.'],
  ['Trace the exposure', 'For Django projects, follow routes to views to the vulnerable package.'],
  ['Track the change', 'Dated history shows how a finding moved. Simulated points are always labelled.'],
  ['Recommend', 'A minimum fixed version and whether it is a major bump. Never applied for you.'],
  ['A person decides', 'Accept the risk, mark a false positive, or fix now. Every decision is logged.'],
]

const FEATURES: [string, string][] = [
  ['Risk and trust, side by side', 'A serious finding backed by weak data reads "verify first", not "fix now". Every signal behind both scores is shown.'],
  ['Exposure path', 'A vulnerable package that a web route can reach ranks above one used only in tests or builds.'],
  ['Change over time', 'See when a finding became more urgent, and which ones are likely to next.'],
  ['Human in the loop', 'depscan only recommends. Decisions carry a reason and an expiry, and sit in an audit log.'],
]

export default function Landing() {
  const root = useRef<HTMLDivElement>(null)
  useEffect(() => (root.current ? initLanding(root.current) : undefined), [])

  return (
    <div className="landing" ref={root}>
      <header className="nav">
        <a href="/" className="nav__logo"><b>dep</b><span>scan</span></a>
        <nav className="nav__links">
          <a href="#pipeline" className="nav__link">How it works</a>
          <a href="#features" className="nav__link">Features</a>
          <a href="/app" className="nav__launch">Launch app</a>
        </nav>
      </header>

      <main>
        <section className="hero">
          <canvas className="hero__waves" id="waves" aria-hidden="true" />
          <div className="disc" aria-hidden="true"><canvas id="depgraph" /></div>
          <p className="wordmark" aria-hidden="true"><b>dep</b><span>scan</span></p>
          <div className="hero__copy">
            <h1>Know which vulnerable dependency to fix first, and which warning to doubt.</h1>
            <p className="hero__lede">
              depscan ranks findings by risk and by how far the advisory can be trusted. It runs offline from cached data and only ever recommends.
            </p>
            <a className="button" href="/app">Launch app</a>
            <aside className="notice" id="notice" aria-label="Read-only by design">
              <div className="notice__head">
                <p className="notice__label">Read-only by design</p>
                <button className="notice__close" type="button" aria-label="Dismiss">&times;</button>
              </div>
              <h2>It never touches your dependencies.</h2>
              <p>depscan reads your manifest and reports. It does not edit files, install, or upgrade anything. {REQUIRED_NOTICE}</p>
              <a className="notice__link" href="/app">Try it in the app</a>
            </aside>
          </div>
        </section>

        <section className="section" id="what">
          <div className="inner split">
            <h2 data-reveal>Counting vulnerabilities is not the same as prioritising them.</h2>
            <div className="prose" data-reveal style={{ transitionDelay: '90ms' }}>
              <p>A scanner can list hundreds of matches. Some are stale, some are disputed, some sit in code nobody can reach. Treating them all the same wastes the time of the people who have to fix them.</p>
              <p>depscan keeps the evidence for every match, says how much to believe it, and leaves the call to a person.</p>
            </div>
          </div>
        </section>

        <section className="section on-black" id="pipeline">
          <div className="inner split">
            <h2 data-reveal>From a manifest to a decision.</h2>
            <ol className="stages">
              {STAGES.map(([title, detail], i) => (
                <li key={title} className="stages__step" data-reveal style={{ transitionDelay: `${i * 55}ms` }}>
                  <span className="stages__n" aria-hidden="true">{String(i + 1).padStart(2, '0')}</span>
                  <span className="stages__title">{title}</span>
                  <span className="stages__detail">{detail}</span>
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section className="section" id="features">
          <div className="inner">
            <h2 className="section__title" data-reveal>What makes the ranking useful.</h2>
            <ul className="features">
              {FEATURES.map(([title, body], i) => (
                <li key={title} className="features__item" data-reveal style={{ transitionDelay: `${i * 70}ms` }}>
                  <h3>{title}</h3>
                  <p>{body}</p>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section className="cta">
          <div className="inner cta__inner" data-reveal>
            <h2>Scan a dependency file and see the evidence.</h2>
            <a className="button" href="/app">Launch app</a>
          </div>
        </section>
      </main>

      <footer className="footer on-black">
        <div className="inner footer__inner">
          <p>depscan. Evidence-based prioritisation with uncertainty. <span className="footer__notice">{REQUIRED_NOTICE}</span></p>
          <a href="/app">Launch app</a>
        </div>
      </footer>
    </div>
  )
}
