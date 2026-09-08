import type { OCSFEvent, EventsResponse } from '../api/ulpf';
import { useState, useEffect, useCallback } from 'react';
import { fetchEvents } from '../api/ulpf';

const PAGE_SIZE = 20;

function DispositionBadge({ d }: { d: string | null }) {
  if (!d) return <span className="badge badge-muted">Unknown</span>;
  if (d === 'Allowed') return <span className="badge badge-success">✓ Allowed</span>;
  if (d === 'Blocked')  return <span className="badge badge-error">✗ Blocked</span>;
  return <span className="badge badge-warning">{d}</span>;
}

function ParserBadge({ pid }: { pid: string }) {
  const isAI = pid.startsWith('dynamic_ai');
  return (
    <span className={`badge ${isAI ? 'badge-processing' : 'badge-accent'}`} style={{ fontSize: 9 }}>
      {isAI ? '🤖' : '⚙'} {pid.replace('builtin_', '').replace('_v1', '').replace('dynamic_ai_', 'ai_')}
    </span>
  );
}

function ExpandedRow({ event }: { event: OCSFEvent }) {
  const ocsfObj = (() => {
    try { return JSON.parse(event.ocsf_json); } catch { return {}; }
  })();

  return (
    <tr>
      <td colSpan={9} style={{ padding: 0 }}>
        <div style={{
          padding: '14px 16px',
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: 16,
          background: 'var(--surface-2)',
          borderBottom: '1px solid var(--border)',
        }}>
          <div>
            <div className="t-label" style={{ marginBottom: 8 }}>Raw Log Payload</div>
            <pre className="code-block" style={{ maxHeight: 120, overflowY: 'auto', fontSize: 10.5 }}>
              {event.raw_payload}
            </pre>
            <div className="t-label" style={{ margin: '10px 0 6px' }}>SHA-256 Integrity</div>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 10,
              color: 'var(--text-3)', wordBreak: 'break-all',
            }}>
              {event.raw_sha256}
            </div>
          </div>
          <div>
            <div className="t-label" style={{ marginBottom: 8 }}>OCSF Class 4001 — Network Activity</div>
            <pre className="code-block" style={{
              maxHeight: 200, overflowY: 'auto', fontSize: 10.5,
              borderLeft: '2px solid var(--success)',
            }}>
              {JSON.stringify(ocsfObj, null, 2)}
            </pre>
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
      <tr
        className={expanded ? 'selected' : ''}
        style={{ cursor: 'pointer' }}
        onClick={() => setExpanded(!expanded)}
        id={`event-row-${index}`}
        role="button"
        aria-expanded={expanded}
        tabIndex={0}
        onKeyDown={e => e.key === 'Enter' && setExpanded(!expanded)}
      >
        <td style={{ width: 32 }}>
          <span style={{
            color: expanded ? 'var(--accent)' : 'var(--text-3)',
            fontFamily: 'var(--font-mono)', fontSize: 10,
            transition: 'color 0.15s',
          }}>
            {expanded ? '▲' : '▼'}
          </span>
        </td>
        <td>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent)' }}>
            {event.event_id}
          </span>
        </td>
        <td style={{ color: 'var(--text-3)', fontSize: 11, fontFamily: 'var(--font-mono)' }}>
          {new Date(event.received_at).toLocaleString()}
        </td>
        <td>
          <span className="badge badge-muted" style={{ fontSize: 9 }}>{event.source_transport}</span>
        </td>
        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
          {event.src_ip ?? '—'}{event.src_port ? `:${event.src_port}` : ''}
        </td>
        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
          {event.dst_ip ?? '—'}{event.dst_port ? `:${event.dst_port}` : ''}
        </td>
        <td>
          {event.protocol
            ? <span className="badge badge-accent" style={{ fontSize: 9 }}>{event.protocol}</span>
            : <span style={{ color: 'var(--text-3)' }}>—</span>}
        </td>
        <td><DispositionBadge d={event.disposition} /></td>
        <td><ParserBadge pid={event.parser_id} /></td>
      </tr>
      {expanded && <ExpandedRow event={event} />}
    </>
  );
}

export default function OCSFTable() {
  const [data, setData]             = useState<EventsResponse | null>(null);
  const [loading, setLoading]       = useState(true);
  const [search, setSearch]         = useState('');
  const [disposition, setDisposition] = useState('');
  const [page, setPage]             = useState(0);
  const [searchInput, setSearchInput] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchEvents({ limit: PAGE_SIZE, offset: page * PAGE_SIZE, search, disposition });
      setData(res);
    } finally {
      setLoading(false);
    }
  }, [page, search, disposition]);

  useEffect(() => { load(); }, [load]);

  // Debounce search
  useEffect(() => {
    const t = setTimeout(() => { setSearch(searchInput); setPage(0); }, 350);
    return () => clearTimeout(t);
  }, [searchInput]);

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter bar */}
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          id="ocsf-search"
          className="input"
          style={{ maxWidth: 340 }}
          type="text"
          placeholder="Search by IP, action, parser, payload…"
          value={searchInput}
          onChange={e => setSearchInput(e.target.value)}
          aria-label="Search OCSF events"
        />
        <select
          id="ocsf-disposition-filter"
          className="select-input"
          style={{ maxWidth: 180 }}
          value={disposition}
          onChange={e => { setDisposition(e.target.value); setPage(0); }}
          aria-label="Filter by disposition"
        >
          <option value="">All Dispositions</option>
          <option value="Allowed">✓ Allowed</option>
          <option value="Blocked">✗ Blocked</option>
          <option value="Unknown">? Unknown</option>
        </select>
        <button className="btn btn-ghost btn-sm" onClick={load} id="btn-ocsf-refresh">
          ↺ Refresh
        </button>
        {data && (
          <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-3)' }}>
            {data.total.toLocaleString()} events
          </span>
        )}
      </div>

      {/* Table */}
      {loading && !data ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[...Array(5)].map((_, i) => <div key={i} className="shimmer" style={{ height: 40 }} />)}
        </div>
      ) : data?.events.length === 0 ? (
        <div style={{
          padding: 40, textAlign: 'center',
          border: '1px dashed var(--border)', borderRadius: 'var(--radius-lg)',
          color: 'var(--text-3)',
        }}>
          <div style={{ fontSize: 28, marginBottom: 10 }}>🛡</div>
          <div style={{ fontWeight: 600, color: 'var(--text-2)', marginBottom: 6 }}>
            No committed OCSF events yet
          </div>
          <div style={{ fontSize: 12 }}>
            POST logs to <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>/api/v1/ingest</code> then click <strong>Process Batch</strong> to populate this table.
          </div>
        </div>
      ) : (
        <>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table" aria-label="OCSF Class 4001 events">
              <thead>
                <tr>
                  <th style={{ width: 32 }} />
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
          <div style={{
            display: 'flex', alignItems: 'center', gap: 10,
            padding: '10px 0', borderTop: '1px solid var(--border)',
          }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-3)' }}>
              {data ? `${page * PAGE_SIZE + 1}–${Math.min((page + 1) * PAGE_SIZE, data.total)} of ${data.total}` : ''}
            </span>
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
                id="btn-page-prev"
              >
                ← Prev
              </button>
              <span style={{
                padding: '6px 12px', background: 'var(--surface-2)',
                borderRadius: 'var(--radius)', fontSize: 12,
                fontFamily: 'var(--font-mono)', color: 'var(--text-2)',
              }}>
                {page + 1} / {totalPages}
              </span>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setPage(p => p + 1)}
                disabled={page >= totalPages - 1}
                id="btn-page-next"
              >
                Next →
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
