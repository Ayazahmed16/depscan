// The contract between the Python backend and this frontend.
// The backend (phase 9a) must return exactly these shapes.

export type Action = 'fix_now' | 'verify_first' | 'monitor' | 'no_action'
export type MatchConfidence = 'exact' | 'probable' | 'uncertain'
export type ReviewDecision = 'accept_risk' | 'false_positive' | 'fix_now'

/** One weighted factor behind the risk score (see docs/SCORING.md). */
export interface RiskFactor {
  name: string
  value: string
  weight: number
  contribution: number
}

/** One signal behind the trust score. `effect` is the points it added or removed. */
export interface TrustSignal {
  name: string
  value: string
  effect: number
  note: string
}

export interface ReviewRecord {
  decision: ReviewDecision
  note: string
  reviewer: string
  at: string
  expires: string | null
}

export interface HistoryPoint {
  date: string
  risk: number
  epss: number | null
  event: string | null
  /** true only for points we generated, never for real dated data */
  simulated: boolean
}

export interface Finding {
  id: string
  aliases: string[]
  package: string
  version: string
  ecosystem: string
  direct: boolean
  scope: 'runtime' | 'dev'
  summary: string
  cvss: number | null
  epss: number | null
  kev: boolean
  fixed_version: string | null
  major_bump: boolean | null
  match: { confidence: MatchConfidence; evidence: string[] }
  risk: { score: number; factors: RiskFactor[] }
  trust: { score: number; signals: TrustSignal[] }
  action: Action
  recommendation: string
  exposure: { exposed: boolean; path: string[] } | null
  history: HistoryPoint[]
  watch: string | null
  review: ReviewRecord | null
}

export interface ScanResult {
  source: string
  scanned_at: string
  findings: Finding[]
}

export interface Health {
  status: 'ok'
  version: string
  /** snapshot date per data source, null if that snapshot is missing */
  snapshots: { osv: string | null; nvd: string | null; kev: string | null; epss: string | null }
}

export interface GraphNode {
  id: string
  label: string
  kind: 'entry' | 'module' | 'package' | 'vulnerable'
}
export interface GraphLink { source: string; target: string }
export interface ExposureGraph {
  nodes: GraphNode[]
  links: GraphLink[]
  limitation: string
}

export interface AuditEntry {
  at: string
  finding_id: string
  decision: ReviewDecision
  reviewer: string
  note: string
  expires: string | null
}

export const REQUIRED_NOTICE = 'No findings does not prove a project is secure.'
