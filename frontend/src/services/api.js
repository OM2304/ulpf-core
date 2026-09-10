const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  })
  if (!response.ok) {
    let detail = `Request failed (${response.status})`
    try {
      const body = await response.json()
      detail = body.detail || detail
    } catch {
      // Keep the HTTP status when the backend did not return JSON.
    }
    throw new Error(detail)
  }
  return response.json()
}

export const api = {
  metrics: () => request('/api/v1/spool/metrics'),
  getSpoolEvents: (limit = 50, status = null) => {
    const search = new URLSearchParams({ limit: String(limit) })
    if (status) search.set('status', status)
    return request(`/api/v1/spool/events?${search}`)
  },
  retrySpoolEvent: (eventId) => request(`/api/v1/spool/retry/${encodeURIComponent(eventId)}`, { method: 'POST' }),
  dropSpoolEvent: (eventId) => request(`/api/v1/spool/drop/${encodeURIComponent(eventId)}`, { method: 'DELETE' }),
  parsers: () => request('/api/v1/parsers'),
  events: (params = {}) => {
    const search = new URLSearchParams()
    if (params.limit) search.set('limit', params.limit)
    if (params.offset) search.set('offset', params.offset)
    if (params.disposition) search.set('disposition', params.disposition)
    return request(`/api/v1/events${search.toString() ? `?${search}` : ''}`)
  },
  ingest: (payloads, transport = 'http_api') => request('/api/v1/ingest', {
    method: 'POST',
    body: JSON.stringify({ payloads, transport }),
  }),
  ingestPath: (path) => request('/api/v1/ingest/path', {
    method: 'POST',
    body: JSON.stringify({ path }),
  }),
  getConsoleLogs: () => request('/api/v1/console/logs'),
  deleteParser: (parserId) => request(`/api/v1/parsers/${encodeURIComponent(parserId)}`, {
    method: 'DELETE',
  }),
  triage: () => request('/api/v1/triage/trigger', { method: 'POST' }),
}

export { API_BASE }
