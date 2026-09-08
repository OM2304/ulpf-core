import { useEffect, useRef, useState } from 'react';
import { fetchMetrics } from '../api/ulpf';

const PIPELINE_COMPONENTS = [
  { name: 'INGESTION',    desc: 'UDP Syslog + HTTP API',   status: 'active' as const },
  { name: 'WAL BUFFER',   desc: 'SQLite WAL durability',   status: 'active' as const },
  { name: 'PARSER',       desc: 'Deterministic engine',    status: 'active' as const },
  { name: 'AI AGENT',     desc: 'Parser synthesis worker', status: 'active' as const },
  { name: 'NORMALIZER',   desc: 'OCSF Class 4001 mapping', status: 'active' as const },
  { name: 'VALIDATOR',    desc: 'Schema + ReDoS guard',    status: 'active' as const },
];

const STATUS_LABEL: Record<string, string> = {
  active:  'ACTIVE',
  warning: 'DEGRADED',
  error:   'DOWN',
};
const STATUS_CLASS: Record<string, string> = {
  active:  'badge-success',
  warning: 'badge-warning',
  error:   'badge-error',
};
const DOT_CLASS: Record<string, string> = {
  active:  'dot-success',
  warning: 'dot-warning',
  error:   'dot-error',
};

interface LiveMetric {
  total: number;
  committed: number;
  pending_ai: number;
  worker_active: boolean;
  worker_poll_interval: number;
}

export default function SystemStatus() {
  const [live, setLive] = useState<LiveMetric | null>(null);
  const [error, setError] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const data = await fetchMetrics();
        setLive({
          total:        data.spool.total,
          committed:    data.spool.committed,
          pending_ai:   data.spool.pending_ai,
          worker_active: data.worker.is_running,
          worker_poll_interval: data.worker.poll_interval,
        });
        setError(false);
      } catch {
        setError(true);
      }
    };
    load();
    intervalRef.current = setInterval(load, 5000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, []);

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <div className="t-label" style={{ marginBottom: 8 }}>Infrastructure</div>
        <h2 style={{ fontSize: 28, fontWeight: 700, letterSpacing: '-0.02em', marginBottom: 8 }}>
          System Status
        </h2>
        <p style={{ color: 'var(--text-2)', fontSize: 14 }}>
          Real-time health of each pipeline component.
          {error ? (
            <span style={{ marginLeft: 8, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--error)' }}>
              ⚠ METRICS UNAVAILABLE
            </span>
          ) : live ? (
            <span style={{ marginLeft: 8, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--success)' }}>
              ● Live
            </span>
          ) : (
            <span style={{ marginLeft: 8, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-3)' }}>
              ○ Connecting...
            </span>
          )}
        </p>
      </div>

      <div className="status-grid">
        {PIPELINE_COMPONENTS.map((comp, i) => {
          const isWorker = comp.name === 'AI AGENT';
          const s = isWorker
            ? (live ? (live.worker_active ? 'active' : 'warning') : (error ? 'error' : 'active'))
            : (error ? 'warning' : comp.status);
          return (
            <div className="status-cell" key={i} id={`status-${comp.name.toLowerCase().replace(' ', '-')}`}>
              <span className={`dot ${DOT_CLASS[s]}`} />
              <div className="status-cell-info">
                <div className="status-cell-name">{comp.name}</div>
                <div className="status-cell-desc">{comp.desc}</div>
              </div>
              <span className={`badge ${STATUS_CLASS[s]} status-cell-badge`}>
                {STATUS_LABEL[s]}
              </span>
            </div>
          );
        })}
      </div>

      {/* Live metrics strip */}
      <div className="metric-strip" style={{ marginTop: 1 }}>
        {[
          {
            label: 'EVENTS SPOOLED',
            val: error ? '—' : (live?.total.toLocaleString() ?? '—'),
            sub: 'all-time',
            color: 'var(--text)',
          },
          {
            label: 'COMMITTED',
            val: error ? '—' : (live?.committed.toLocaleString() ?? '—'),
            sub: 'OCSF normalized',
            color: 'var(--success)',
          },
          {
            label: 'PENDING AI',
            val: error ? '—' : (live?.pending_ai.toLocaleString() ?? '—'),
            sub: 'awaiting synthesis',
            color: 'var(--warning)',
          },
          {
            label: 'PARSE RATE',
            val: error || !live
              ? '—'
              : `${live.total > 0 ? Math.round((live.committed / live.total) * 100) : 100}%`,
            sub: 'committed / total',
            color: 'var(--accent)',
          },
          {
            label: 'AI AGENT',
            val: error ? 'UNKNOWN' : (live ? (live.worker_active ? 'RUNNING' : 'STOPPED') : '—'),
            sub: live?.worker_poll_interval ? `poll interval: ${live.worker_poll_interval}s` : 'poll interval: ?',
            color: error ? 'var(--error)' : (live?.worker_active ? 'var(--success)' : 'var(--warning)'),
          },
        ].map(({ label, val, sub, color }) => (
          <div className="metric-cell" key={label}>
            <div className="metric-label">{label}</div>
            <div className="metric-value" style={{ fontSize: 22, color }}>{val}</div>
            <div className="metric-sub">{sub}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
