import type { AuditEntry, ExposureGraph, Health, ReviewInput, ReviewRecord, ScanResult, WeightsView } from './types'

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
  scan: (files: File[]) => {
    const body = new FormData()
    files.forEach((f) => body.append('files', f))
    return request<ScanResult>('/scan', { method: 'POST', body })
  },
  weights: () => request<WeightsView>('/config/weights'),
  setWeights: (weights: Record<string, number>) =>
    request<WeightsView>('/config/weights', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ weights }),
    }),
  resetWeights: () => request<WeightsView>('/config/weights', { method: 'DELETE' }),
  reset: () => request<{ ok: true }>('/reset', { method: 'POST' }),
  graph: () => request<ExposureGraph | null>('/graph'),
  audit: () => request<AuditEntry[]>('/audit'),
  review: (input: ReviewInput) =>
    request<ReviewRecord>('/review', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    }),
  revoke: (input: { key: string; note: string; reviewer: string }) =>
    request<{ ok: true }>('/review/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    }),
}
