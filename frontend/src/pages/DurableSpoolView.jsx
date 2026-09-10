import { Fragment, useEffect, useState } from 'react'
import { ChevronDown, ChevronUp, Database, RefreshCw } from 'lucide-react'
import { api } from '../services/api'
import { CopyButton, EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge } from '../components/ui'

export default function DurableSpoolView() {
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [expandedRowId, setExpandedRowId] = useState(null)
  const [actionLoading, setActionLoading] = useState(false)
  const [activeAction, setActiveAction] = useState(null)

  const formatPayload = (payload, fallback = 'OCSF record committed') => {
    if (payload === null || payload === undefined || payload === '') return fallback
    return typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2)
  }

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

  const retryEvent = async (eventId) => {
    setActionLoading(true)
    setActiveAction(`${eventId}:retry`)
    try {
      await api.retrySpoolEvent(eventId)
      setEvents((currentEvents) => currentEvents.map((event) => event.event_id === eventId ? { ...event, status: 'PENDING_AI' } : event))
    } catch (requestError) {
      setError(requestError)
    } finally {
      setActionLoading(false)
      setActiveAction(null)
    }
  }

  const dropEvent = async (eventId) => {
    setActionLoading(true)
    setActiveAction(`${eventId}:drop`)
    try {
      await api.dropSpoolEvent(eventId)
      setEvents((currentEvents) => currentEvents.filter((event) => event.event_id !== eventId))
      setExpandedRowId(null)
    } catch (requestError) {
      setError(requestError)
    } finally {
      setActionLoading(false)
      setActiveAction(null)
    }
  }

  return <><PageHeader eyebrow="Forensic staging buffer" title="Durable spool" description="Every payload lands on disk before it is normalized or triaged." actions={<button className="button button-ghost" onClick={load} disabled={loading}><RefreshCw size={15} className={loading ? 'spin' : ''} /> Refresh</button>} />{error && <ErrorState error={error} onRetry={load} />}<div className="panel table-panel"><div className="table-toolbar"><div className="table-title"><Database size={17} /><span>{events.length} records returned</span></div><span className="table-note">ordered newest first</span></div>{loading ? <LoadingState /> : events.length === 0 ? <EmptyState label="No normalized records available" /> : <div className="table-scroll"><table><thead><tr><th>Event ID</th><th>Timestamp</th><th>SHA-256 hash</th><th>Status</th><th>Raw payload</th></tr></thead><tbody>{events.map((event, index) => {
    const rowId = event.event_id || index
    const open = expandedRowId === rowId
    const status = event.status || 'COMMITTED'
    const parsedEvent = event.ocsf_json
    return <Fragment key={rowId}>
      <tr key={rowId} className={`spool-row ${open ? 'expanded' : ''}`} onClick={() => setExpandedRowId(open ? null : rowId)} aria-expanded={open}>
        <td className="mono event-id">{event.event_id || '—'}</td>
        <td className="muted">{event.received_at ? new Date(event.received_at).toLocaleString() : '—'}</td>
        <td><span className="hash-cell mono">{event.raw_sha256 ? `${event.raw_sha256.slice(0, 16)}…` : '—'}{event.raw_sha256 && <span onClick={(clickEvent) => clickEvent.stopPropagation()}><CopyButton value={event.raw_sha256} /></span>}</span></td>
        <td><StatusBadge status={status} /></td>
        <td className="payload-cell" title={formatPayload(event.raw_payload)}><span>{formatPayload(event.raw_payload)}</span>{open ? <ChevronUp size={15} /> : <ChevronDown size={15} />}</td>
      </tr>
      {open && <tr key={`${rowId}-details`} className="spool-detail-row"><td colSpan="5"><div className="spool-detail-panel">
        <div className="spool-detail-section"><p className="code-label">Full raw payload</p><pre className="spool-code raw-payload-code">{formatPayload(event.raw_payload)}</pre></div>
        {parsedEvent !== null && parsedEvent !== undefined && <div className="spool-detail-section"><p className="code-label">Parsed event</p><pre className="spool-code parsed-event-code">{typeof parsedEvent === 'string' ? parsedEvent : JSON.stringify(parsedEvent, null, 2)}</pre></div>}
        {status === 'QUARANTINED' && <div className="quarantine-warning">Normalization Failed: AI Sandbox rejected candidate parser.</div>}
        <div className="spool-action-bar">
          <button className="spool-action-button drop" onClick={(clickEvent) => { clickEvent.stopPropagation(); dropEvent(event.event_id) }} disabled={actionLoading}>{activeAction === `${event.event_id}:drop` ? 'Dropping…' : 'Drop Event'}</button>
          <button className="spool-action-button retry" onClick={(clickEvent) => { clickEvent.stopPropagation(); retryEvent(event.event_id) }} disabled={actionLoading}>{activeAction === `${event.event_id}:retry` ? 'Retrying…' : 'Retry Triage'}</button>
        </div>
      </div></td></tr>}
    </Fragment>
  })}</tbody></table></div>}</div></>
}
