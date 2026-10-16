import type { Action } from './types'

// Colour is never decoration: each one encodes a judgement.
export type Signal = 'info' | 'warning' | 'critical'

// Hex values for SVG/canvas, which cannot read Tailwind classes. They mirror the tokens in index.css.
export const SIGNAL_HEX: Record<Signal, string> = {
  info: '#047857',
  warning: '#b45309',
  critical: '#b42318',
}

export const SIGNAL_TEXT_CLASS: Record<Signal, string> = {
  info: 'text-signal-info',
  warning: 'text-signal-warning',
  critical: 'text-signal-critical',
}
export const SIGNAL_BORDER_CLASS: Record<Signal, string> = {
  info: 'border-signal-info',
  warning: 'border-signal-warning',
  critical: 'border-signal-critical',
}
export const SIGNAL_BG_CLASS: Record<Signal, string> = {
  info: 'bg-signal-info',
  warning: 'bg-signal-warning',
  critical: 'bg-signal-critical',
}

// Risk score is 0-100 (docs/SCORING.md). Cut-offs are the same ones drawn on the gauge.
export function riskSignal(score: number): Signal {
  return score >= 60 ? 'critical' : score >= 30 ? 'warning' : 'info'
}

// Trust is the opposite direction: low trust is the warning.
export function trustSignal(score: number): Signal {
  return score >= 60 ? 'info' : score >= 30 ? 'warning' : 'critical'
}

export const ACTION_SIGNAL: Record<Action, Signal> = {
  fix_now: 'critical',
  verify_first: 'warning',
  monitor: 'info',
  no_action: 'info',
}

export const ACTION_LABEL: Record<Action, string> = {
  fix_now: 'fix now',
  verify_first: 'verify first',
  monitor: 'monitor',
  no_action: 'no action',
}
