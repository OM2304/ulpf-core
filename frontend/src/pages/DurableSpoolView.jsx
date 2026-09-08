import { useEffect, useState } from 'react'
import { Database, RefreshCw } from 'lucide-react'
import { api } from '../services/api'
import { CopyButton, EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge } from '../components/ui'

export default function DurableSpoolView() {
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const load = () => {
    setLoading(true)
    setError(null)
    api.getSpoolEvents(500)
      .then((data) => {
        console.log("API Response:", data)
        setEvents(data)
      })
      .catch(setError)
      .finally(() => setLoading(false))
  }
  useEffect(load, [])
  return <><PageHeader eyebrow="Forensic staging buffer" title="Durable spool" description="Every payload lands on disk before it is normalized or triaged." actions={<button className="button button-ghost" onClick={load} disabled={loading}><RefreshCw size={15} className={loading ? 'spin' : ''} /> Refresh</button>} />{error && <ErrorState error={error} onRetry={load} />}<div className="panel table-panel"><div className="table-toolbar"><div className="table-title"><Database size={17} /><span>{events.length} records returned</span></div><span className="table-note">ordered newest first</span></div>{loading ? <LoadingState /> : events.length === 0 ? <EmptyState label="No normalized records available" /> : <div className="table-scroll"><table><thead><tr><th>Event ID</th><th>Timestamp</th><th>SHA-256 hash</th><th>Status</th><th>Raw payload</th></tr></thead><tbody>{events.map((event, index) => <tr key={event.event_id || index}><td className="mono event-id">{event.event_id || '—'}</td><td className="muted">{event.received_at ? new Date(event.received_at).toLocaleString() : '—'}</td><td><span className="hash-cell mono">{event.raw_sha256 ? `${event.raw_sha256.slice(0, 16)}…` : '—'}{event.raw_sha256 && <CopyButton value={event.raw_sha256} />}</span></td><td><StatusBadge status={event.status || 'COMMITTED'} /></td><td className="payload-cell" title={event.raw_payload}>{event.raw_payload || 'OCSF record committed'}</td></tr>)}</tbody></table></div>}</div></>
}
