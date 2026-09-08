import type { OCSFEvent, EventsResponse } from '../api/ulpf';
import { useState, useEffect, useCallback } from 'react';
import { fetchEvents } from '../api/ulpf';

const PAGE_SIZE = 20;

function dispositionBadge(d: string | null) {
  if (!d) return <span className="badge gray">Unknown</span>;
  if (d === 'Allowed') return <span className="badge green">✓ {d}</span>;
  if (d === 'Blocked') return <span className="badge red">✗ {d}</span>;
  return <span className="badge orange">{d}</span>;
}

function parserBadge(pid: string) {
  const isAI = pid.startsWith('dynamic_ai');
  return (
    <span className={`badge ${isAI ? 'purple' : 'cyan'}`} style={{ fontSize: 9 }}>
      {isAI ? '🤖' : '⚙'} {pid.replace('builtin_', '').replace('_v1', '').replace('dynamic_ai_', 'ai_')}
    </span>
  );
}

function ExpandedRow({ event }: { event: OCSFEvent }) {
  const ocsfObj = (() => {
    try { return JSON.parse(event.ocsf_json); } catch { return {}; }
  })();

  return (
    <tr className="expanded fade-in">
      <td colSpan={9}>
        <div style={{ padding: '12px 6px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          <div>
            <div className="section-title">Raw Log Payload</div>
            <pre className="json-block" style={{ maxHeight: 120 }}>{event.raw_payload}</pre>
            <div className="section-title" style={{ marginTop: 12 }}>SHA-256 Integrity</div>
            <div className="mono" style={{ fontSize: 10, color: 'var(--text-muted)', wordBreak: 'break-all' }}>
              {event.raw_sha256}
            </div>
          </div>
          <div>
            <div className="section-title">OCSF Class 4001 (Network Activity)</div>
            <pre className="json-block">{JSON.stringify(ocsfObj, null, 2)}</pre>
          </div>
        </div>
      </td>
    </tr>
  );
}

function EventRow({ event, index }: { event: OCSFEvent; index: number }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <>
      <tr className={expanded ? 'expanded' : ''}>
        <td>
          <button
            className="expand-btn"
            onClick={() => setExpanded(!expanded)}
            id={`event-expand-${index}`}
          >
            {expanded ? '▲' : '▼'}
          </button>
        </td>
        <td>
          <span className="mono" style={{ fontSize: 10 }}>
            {event.event_id}
          </span>
        </td>
        <td style={{ color: 'var(--text-muted)', fontSize: 11 }}>
          {new Date(event.received_at).toLocaleString()}
        </td>
        <td>
          <span className="badge gray" style={{ fontSize: 9 }}>{event.source_transport}</span>
        </td>
        <td className="mono">{event.src_ip ?? '—'}{event.src_port ? `:${event.src_port}` : ''}</td>
        <td className="mono">{event.dst_ip ?? '—'}{event.dst_port ? `:${event.dst_port}` : ''}</td>
        <td>
          {event.protocol
            ? <span className="badge cyan" style={{ fontSize: 9 }}>{event.protocol}</span>
            : <span style={{ color: 'var(--text-muted)' }}>—</span>}
        </td>
        <td>{dispositionBadge(event.disposition)}</td>
        <td>{parserBadge(event.parser_id)}</td>
      </tr>
      {expanded && <ExpandedRow event={event} />}
    </>
  );
}

export default function OCSFTable() {
  const [data, setData] = useState<EventsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [disposition, setDisposition] = useState('');
  const [page, setPage] = useState(0);
  const [searchInput, setSearchInput] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchEvents({
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
        search,
        disposition,
      });
      setData(res);
    } finally {
      setLoading(false);
    }
  }, [page, search, disposition]);

  useEffect(() => { load(); }, [load]);

  // Debounce search
  useEffect(() => {
    const timer = setTimeout(() => {
      setSearch(searchInput);
      setPage(0);
    }, 350);
    return () => clearTimeout(timer);
  }, [searchInput]);

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  return (
    <div className="card fade-in">
      <div className="card-header">
        <span className="icon">🛡</span>
        <h2>OCSF Class 4001 — Network Activity</h2>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
          {data && (
            <span className="badge cyan">{data.total.toLocaleString()} events</span>
          )}
        </div>
      </div>
      <div className="card-body">
        {/* Filter bar */}
        <div className="filter-bar" style={{ marginBottom: 16 }}>
          <input
            id="ocsf-search"
            className="search-input"
            type="text"
            placeholder="Search by IP, action, parser, payload…"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
          <select
            id="ocsf-disposition-filter"
            className="select-filter"
            value={disposition}
            onChange={(e) => { setDisposition(e.target.value); setPage(0); }}
          >
            <option value="">All Dispositions</option>
            <option value="Allowed">✓ Allowed</option>
            <option value="Blocked">✗ Blocked</option>
            <option value="Unknown">? Unknown</option>
          </select>
          <button className="btn btn-ghost" onClick={load} id="btn-ocsf-refresh">
            ↺ Refresh
          </button>
        </div>

        {/* Table */}
        {loading && !data ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {[...Array(5)].map((_, i) => <div key={i} className="loading-shimmer" />)}
          </div>
        ) : data?.events.length === 0 ? (
          <div className="empty-state">
            <div className="icon">🛡</div>
            <div>No committed OCSF events yet.</div>
            <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-muted)' }}>
              POST logs to <span className="mono">/api/v1/ingest</span> then click{' '}
              <strong>Process Batch</strong> to populate this table.
            </div>
          </div>
        ) : (
          <>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th></th>
                    <th>Event ID</th>
                    <th>Timestamp</th>
                    <th>Transport</th>
                    <th>Src Endpoint</th>
                    <th>Dst Endpoint</th>
                    <th>Protocol</th>
                    <th>Disposition</th>
                    <th>Parser</th>
                  </tr>
                </thead>
                <tbody>
                  {data?.events.map((ev, i) => (
                    <EventRow key={ev.event_id} event={ev} index={i} />
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="pagination">
              <span className="page-info">
                {data ? `${page * PAGE_SIZE + 1}–${Math.min((page + 1) * PAGE_SIZE, data.total)} of ${data.total}` : ''}
              </span>
              <button
                className="btn-page"
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
                id="btn-page-prev"
              >
                ← Prev
              </button>
              <span className="page-info">{page + 1} / {totalPages}</span>
              <button
                className="btn-page"
                onClick={() => setPage(p => p + 1)}
                disabled={page >= totalPages - 1}
                id="btn-page-next"
              >
                Next →
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
