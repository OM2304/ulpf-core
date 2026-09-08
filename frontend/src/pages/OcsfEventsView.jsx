import { useEffect, useMemo, useState } from 'react'
import { ChevronDown, ChevronUp, Filter, Search } from 'lucide-react'
import { api } from '../services/api'
import { CopyButton, EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge } from '../components/ui'

export default function OcsfEventsView() {
  const [events, setEvents] = useState([])
  const [disposition, setDisposition] = useState('')
  const [search, setSearch] = useState('')
  const [expanded, setExpanded] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  useEffect(() => {
    setLoading(true)
    setError(null)
    api.events({ limit: 500, disposition: disposition || undefined })
      .then((data) => {
        console.log("API Response:", data)
        setEvents(data)
      })
      .catch(setError)
      .finally(() => setLoading(false))
  }, [disposition])
  const filtered = useMemo(() => { const term = search.toLowerCase().trim(); if (!term) return events; return events.filter((event) => [event.event_id, event.parser_id, event.src_ip, event.dst_ip, event.src_endpoint?.ip, event.dst_endpoint?.ip].some((value) => String(value || '').toLowerCase().includes(term))) }, [events, search])
  return <><PageHeader eyebrow="Normalized analytical store" title="OCSF events" description="Network activity records normalized into OCSF class 4001." /><div className="panel table-panel"><div className="event-toolbar"><div className="search-box"><Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search parser, IP, or event ID" /></div><label className="select-box"><Filter size={15} /><select value={disposition} onChange={(event) => setDisposition(event.target.value)}><option value="">All dispositions</option><option value="Allowed">Allowed</option><option value="Blocked">Blocked</option></select></label></div>{error && <ErrorState error={error} />}{loading ? <LoadingState /> : filtered.length === 0 ? <EmptyState label="No events match the current filters" /> : <div className="table-scroll"><table className="events-table"><thead><tr><th></th><th>Event ID</th><th>Parser used</th><th>Source IP</th><th>Dest IP</th><th>Protocol</th><th>Action</th><th>Disposition</th></tr></thead><tbody>{filtered.map((event, index) => <EventRow key={event.event_id || index} event={event} open={expanded === (event.event_id || index)} onToggle={() => setExpanded(expanded === (event.event_id || index) ? null : (event.event_id || index))} />)}</tbody></table></div>}</div></>
}

function EventRow({ event, open, onToggle }) {
  const source = event.src_ip || event.src_endpoint?.ip
  const destination = event.dst_ip || event.dst_endpoint?.ip
  const protocol = event.protocol || event.connection_info?.protocol_name
  return <><tr className={`event-row ${open ? 'expanded' : ''}`} onClick={onToggle}><td className="expand-cell">{open ? <ChevronUp size={15} /> : <ChevronDown size={15} />}</td><td className="mono event-id">{event.event_id || '—'}</td><td className="parser-cell">{event.parser_id || '—'}</td><td className="mono">{source || '—'}</td><td className="mono">{destination || '—'}</td><td>{protocol || '—'}</td><td>{event.action || '—'}</td><td><StatusBadge status={event.disposition || 'Unknown'} /></td></tr>{open && <tr className="detail-row"><td colSpan="8"><div className="forensic-detail"><div><p>Raw SHA-256</p><span className="hash-cell mono">{event.raw_sha256 || 'Not returned by API'}{event.raw_sha256 && <CopyButton value={event.raw_sha256} />}</span></div><div><p>Exact raw payload</p><code>{event.raw_payload || 'Not returned by API'}</code></div></div></td></tr>}</>
}
