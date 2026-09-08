import { useState, useEffect, useCallback } from 'react';
import { fetchEvents, OCSFEvent } from '../api/ulpf';

const POLL_INTERVAL = 5000;

function DispositionBadge({ disposition }: { disposition: string | null }) {
  if (!disposition) return <span className="badge badge-muted">Unknown</span>;
  const d = disposition.toLowerCase();
  if (d === 'allowed') return <span className="badge badge-success">✓ Allowed</span>;
  if (d === 'blocked') return <span className="badge badge-error">✗ Blocked</span>;
  return <span className="badge badge-warning">{disposition}</span>;
}

export default function LogExplorer() {
  const [events, setEvents] = useState<OCSFEvent[]>([]);
  const [selected, setSelected] = useState<OCSFEvent | null>(null);
  const [filter, setFilter] = useState('');
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const res = await fetchEvents({ limit: 15 });
      setEvents(res.events);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, POLL_INTERVAL);
    return () => clearInterval(t);
  }, [load]);

  const filtered = events.filter(log => {
    const q = filter.toLowerCase();
    if (!q) return true;
    return (
      (log.event_id && log.event_id.toLowerCase().includes(q)) ||
      (log.raw_payload && log.raw_payload.toLowerCase().includes(q)) ||
      (log.src_ip && log.src_ip.includes(q)) ||
      (log.dst_ip && log.dst_ip.includes(q)) ||
      (log.parser_id && log.parser_id.toLowerCase().includes(q))
    );
  });

  return (
    <div id="logs">
      <div style={{ marginBottom: 24 }}>
        <div className="t-label" style={{ marginBottom: 8 }}>Live Event Stream</div>
        <h2 style={{ fontSize: 28, fontWeight: 700, letterSpacing: '-0.02em', marginBottom: 8 }}>
          Log Explorer
        </h2>
        <p style={{ color: 'var(--text-2)', fontSize: 14 }}>
          Recent committed events. Click any event to inspect its raw payload and OCSF normalization.
        </p>
      </div>

      <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
        <input
          id="log-search"
          className="input"
          style={{ maxWidth: 320 }}
          type="text"
          placeholder="Search IDs, IPs, raw payloads…"
          value={filter}
          onChange={e => setFilter(e.target.value)}
          aria-label="Search logs"
        />
        {filter && (
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => setFilter('')}
            id="log-clear-filter"
          >
            Clear
          </button>
        )}
      </div>

      <div className="explorer-layout card">
        <div className="explorer-table-wrap">
          {loading && events.length === 0 ? (
             <div style={{ padding: 40, textAlign: 'center' }}>
               <div className="shimmer" style={{ height: 200 }} />
             </div>
          ) : filtered.length === 0 ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>
              No matching events found.
            </div>
          ) : (
            <table className="data-table" aria-label="Log events table">
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>Timestamp</th>
                  <th>Src IP</th>
                  <th>Dst IP</th>
                  <th>Protocol</th>
                  <th>Disposition</th>
                  <th>Parser</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(log => (
                  <tr
                    key={log.event_id}
                    onClick={() => setSelected(selected?.event_id === log.event_id ? null : log)}
                    className={selected?.event_id === log.event_id ? 'selected' : ''}
                    role="button"
                    tabIndex={0}
                    onKeyDown={e => e.key === 'Enter' && setSelected(log)}
                    aria-selected={selected?.event_id === log.event_id}
                  >
                    <td>
                      <span className="t-mono" style={{ fontSize: 10, color: 'var(--accent)' }}>
                        {log.event_id}
                      </span>
                    </td>
                    <td>
                      <span className="t-mono" style={{ fontSize: 11, color: 'var(--text-3)' }}>
                        {new Date(log.received_at).toLocaleTimeString()}
                      </span>
                    </td>
                    <td className="t-mono" style={{ fontSize: 11 }}>{log.src_ip ?? '—'}</td>
                    <td className="t-mono" style={{ fontSize: 11 }}>{log.dst_ip ?? '—'}</td>
                    <td>
                      {log.protocol
                        ? <span className="badge badge-accent" style={{ fontSize: 9 }}>{log.protocol}</span>
                        : <span style={{ color: 'var(--text-3)' }}>—</span>}
                    </td>
                    <td><DispositionBadge disposition={log.disposition} /></td>
                    <td>
                      <span className={`badge ${log.parser_id.startsWith('dynamic_ai') ? 'badge-processing' : 'badge-muted'}`} style={{ fontSize: 9 }}>
                        {log.parser_id.startsWith('dynamic_ai') ? '🤖' : '⚙'} {log.parser_id.replace('builtin_', '').replace('_v1', '').replace('dynamic_ai_', 'ai_')}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="explorer-inspector" id="event-inspector-panel">
          {!selected ? (
            <div className="inspector-empty">
              <div className="inspector-empty-icon">⬡</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-3)' }}>
                Select an event<br />to inspect its transformation
              </div>
            </div>
          ) : (
            <EventDetail log={selected} />
          )}
        </div>
      </div>
    </div>
  );
}

function EventDetail({ log }: { log: OCSFEvent }) {
  const [tab, setTab] = useState<'raw' | 'normalized'>('raw');
  const ocsfObj = log.ocsf || (() => {
    try { return JSON.parse(log.ocsf_json); } catch { return {}; }
  })();

  return (
    <div className="inspector-panel">
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>
            {log.event_id}
          </span>
          <span className="badge badge-muted">{new Date(log.received_at).toLocaleString()}</span>
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <span className="badge badge-muted">{log.source_transport}</span>
          <span className={`badge ${log.parser_id.startsWith('dynamic_ai') ? 'badge-processing' : 'badge-accent'}`}>
            {log.parser_id}
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', gap: 0, margin: '0 -20px', padding: '0 20px' }}>
        {(['raw', 'normalized'] as const).map((t) => (
          <button
            key={t}
            id={`inspector-tab-${t}`}
            onClick={() => setTab(t)}
            style={{
              padding: '8px 14px',
              fontSize: 11,
              fontFamily: 'var(--font-mono)',
              fontWeight: 500,
              letterSpacing: '0.06em',
              textTransform: 'uppercase',
              color: tab === t ? 'var(--accent)' : 'var(--text-3)',
              borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent',
              marginBottom: -1,
              transition: 'color 0.15s',
            }}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === 'raw' && (
        <div>
          <div className="inspector-section-title">Raw Event Payload</div>
          <pre className="code-block" style={{ fontSize: 10.5, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {log.raw_payload}
          </pre>
          <div className="inspector-section-title" style={{ marginTop: 16 }}>SHA-256 Integrity</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-3)', wordBreak: 'break-all' }}>
            {log.raw_sha256}
          </div>
        </div>
      )}

      {tab === 'normalized' && (
        <div>
          <div className="inspector-section-title">OCSF Class 4001 — Network Activity</div>
          <pre className="code-block" style={{ fontSize: 10.5, maxHeight: 400, overflowY: 'auto', borderLeft: '2px solid var(--success)' }}>
            {JSON.stringify(ocsfObj, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
