import type { AuditEntry, ExposureGraph, Health, ReviewDecision, ReviewRecord, ScanResult } from './types'

// Thin wrapper over the backend. Every call throws a readable Error on failure,
// so the UI can show "backend unreachable" instead of silently showing nothing.
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(`/api${path}`, init)
  } catch {
    throw new Error('backend unreachable')
  }
  if (!res.ok) {
    const detail = await res.text().catch(() => '')
    throw new Error(detail || `request failed (${res.status})`)
  }
  return res.json() as Promise<T>
}

export const api = {
  health: () => request<Health>('/health'),
  findings: () => request<ScanResult | null>('/findings'),
  scan: (file: File) => {
    const body = new FormData()
    body.append('file', file)
    return request<ScanResult>('/scan', { method: 'POST', body })
  },
  reset: () => request<{ ok: true }>('/reset', { method: 'POST' }),
  graph: () => request<ExposureGraph | null>('/graph'),
  audit: () => request<AuditEntry[]>('/audit'),
  review: (input: { finding_id: string; decision: ReviewDecision; note: string; reviewer: string; expires: string | null }) =>
    request<ReviewRecord>('/review', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    }),
}
