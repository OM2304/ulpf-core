import { useEffect, useMemo, useState } from 'react'
import { ChevronDown, ChevronUp, Filter, Search } from 'lucide-react'
import { api } from '../services/api'
import { CopyButton, EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge } from '../components/ui'

export default function OcsfEventsView() {
  const [events, setEvents] = useState([])
  const [sourceTypeFilter, setSourceTypeFilter] = useState('All')
  const [dispositionFilter, setDispositionFilter] = useState('All')
  const [searchQuery, setSearchQuery] = useState('')
  const [expanded, setExpanded] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    setLoading(true)
    setError(null)
    api.events({ limit: 500 })
      .then((data) => {
        setEvents(Array.isArray(data) ? data : [])
      })
      .catch(setError)
      .finally(() => setLoading(false))
  }, [])

  const availableSourceTypes = useMemo(() => {
    const types = new Set()
    events.forEach((event) => {
      const src = event.parser_id || event.class_name
      if (src) types.add(src)
    })
    return Array.from(types).sort()
  }, [events])

  const filteredEvents = useMemo(() => {
    const term = searchQuery.toLowerCase().trim()

    return events.filter((event) => {
      // 1. Source Type filter
      if (sourceTypeFilter !== 'All') {
        const eventSource = (event.parser_id || event.class_name || '').toLowerCase()
        if (eventSource !== sourceTypeFilter.toLowerCase()) {
          return false
        }
      }

      // 2. Security Disposition filter (Strictly Allowed / Blocked / All)
      const eventDisp = (event.disposition || '').toLowerCase()
      const matchesDisposition =
        dispositionFilter === 'All' ||
        dispositionFilter === '' ||
        eventDisp === dispositionFilter.toLowerCase()

      if (!matchesDisposition) return false

      // 3. Search query filter
      if (!term) return true

      const eventIdMatch = String(event.event_id || '').toLowerCase().includes(term)
      const rawPayloadMatch = String(event.raw_payload || '').toLowerCase().includes(term)
      const rawShaMatch = String(event.raw_sha256 || '').toLowerCase().includes(term)
      const parserIdMatch = String(event.parser_id || event.class_name || '').toLowerCase().includes(term)
      const classUidMatch = String(event.class_uid || '').toLowerCase().includes(term)
      const timeMatch = String(event.time || event.timestamp || '').toLowerCase().includes(term)
      const actionMatch = String(event.action || '').toLowerCase().includes(term)
      const jsonMatch = typeof event === 'object' ? JSON.stringify(event).toLowerCase().includes(term) : false

      return (
        eventIdMatch ||
        rawPayloadMatch ||
        rawShaMatch ||
        parserIdMatch ||
        classUidMatch ||
        timeMatch ||
        actionMatch ||
        jsonMatch
      )
    })
  }, [events, searchQuery, sourceTypeFilter, dispositionFilter])

  return (
    <>
      <PageHeader
        eyebrow="Normalized analytical store"
        title="OCSF events"
        description="Network activity records normalized into OCSF class 4001."
      />
      <div className="panel table-panel">
        <div className="event-toolbar">
          <div className="search-box">
            <Search size={16} />
            <input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search parser, class ID, timestamp, payload, or event ID..."
            />
          </div>
          <label className="select-box">
            <Filter size={15} />
            <select
              value={sourceTypeFilter}
              onChange={(e) => setSourceTypeFilter(e.target.value)}
            >
              <option value="All">All Source Types</option>
              {availableSourceTypes.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </label>
          <label className="select-box">
            <Filter size={15} />
            <select
              value={dispositionFilter}
              onChange={(e) => setDispositionFilter(e.target.value)}
            >
              <option value="All">All Dispositions</option>
              <option value="Allowed">Allowed</option>
              <option value="Blocked">Blocked</option>
            </select>
          </label>
        </div>

        {error && <ErrorState error={error} />}

        {loading ? (
          <LoadingState />
        ) : filteredEvents.length === 0 ? (
          <EmptyState label="No events match the current filters" />
        ) : (
          <div className="table-scroll">
            <table className="events-table">
              <thead>
                <tr>
                  <th></th>
                  <th>Timestamp</th>
                  <th>Event ID</th>
                  <th>Parser Name</th>
                  <th>Class ID</th>
                  <th>Action</th>
                  <th>Disposition</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.map((event, index) => (
                  <EventRow
                    key={event.event_id || index}
                    event={event}
                    open={expanded === (event.event_id || index)}
                    onToggle={() =>
                      setExpanded(
                        expanded === (event.event_id || index) ? null : (event.event_id || index)
                      )
                    }
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}

function EventRow({ event, open, onToggle }) {
  const timestamp = event.time || event.timestamp || event.metadata?.time || '—'
  const eventId = event.event_id || '—'
  const parserName = event.parser_id || event.class_name || '—'
  const classUid = event.class_uid || '4001'
  const action = event.action || '—'
  const disposition = event.disposition || 'Unknown'

  return (
    <>
      <tr className={`event-row ${open ? 'expanded' : ''}`} onClick={onToggle}>
        <td className="expand-cell">{open ? <ChevronUp size={15} /> : <ChevronDown size={15} />}</td>
        <td className="mono text-[11px] text-slate-500 dark:text-slate-400">{timestamp}</td>
        <td className="mono event-id">{eventId}</td>
        <td className="parser-cell font-semibold">{parserName}</td>
        <td className="mono text-xs text-indigo-600 dark:text-indigo-400 font-semibold">{classUid}</td>
        <td>{action}</td>
        <td><StatusBadge status={disposition} /></td>
      </tr>
      {open && (
        <tr className="detail-row">
          <td colSpan="7">
            <div className="forensic-detail">
              <div>
                <p>Raw SHA-256</p>
                <span className="hash-cell mono">
                  {event.raw_sha256 || 'Not returned by API'}
                  {event.raw_sha256 && <CopyButton value={event.raw_sha256} />}
                </span>
              </div>
              <div>
                <p>Exact raw payload</p>
                <code>{event.raw_payload || 'Not returned by API'}</code>
              </div>
              <div className="ocsf-json-detail">
                <p>Full normalized OCSF JSON</p>
                <pre>{JSON.stringify(event, null, 2)}</pre>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}
