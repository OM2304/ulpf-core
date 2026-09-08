import type { MetricsResponse } from '../api/ulpf';

interface Props {
  metrics: MetricsResponse | null;
  loading: boolean;
}

function MetricCell({ label, value, sub, color = 'var(--text)' }: {
  label: string; value: string | number; sub?: string; color?: string;
}) {
  return (
    <div className="console-metric-cell">
      <div className="metric-label">{label}</div>
      <div className="metric-value" style={{ fontSize: 24, color }}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      {sub && <div className="metric-sub">{sub}</div>}
    </div>
  );
}

export default function MetricsPanel({ metrics, loading }: Props) {
  if (loading && !metrics) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {[...Array(3)].map((_, i) => (
          <div key={i} className="shimmer" style={{ height: 20 }} />
        ))}
      </div>
    );
  }
  if (!metrics) return null;

  const { spool, worker, storage } = metrics;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Spool */}
      <div>
        <div className="t-label" style={{ marginBottom: 10 }}>Durable Spool (WAL-SQLite)</div>
        <div className="console-metric-grid">
          <MetricCell label="TOTAL SPOOLED" value={spool.total} sub="all-time events" color="var(--text)" />
          <MetricCell label="COMMITTED"     value={spool.committed} sub="OCSF normalized" color="var(--success)" />
          <MetricCell label="PENDING AI"    value={spool.pending_ai} sub="awaiting synthesis" color="var(--warning)" />
          <MetricCell label="STORED"        value={spool.durably_stored} sub="durably persisted" color="var(--accent)" />
        </div>
      </div>

      {/* Worker */}
      <div>
        <div className="t-label" style={{ marginBottom: 10 }}>AI Agent Worker</div>
        <div className="console-metric-grid">
          <MetricCell label="TRIAGED"  value={worker.total_triaged}           sub={`batch: ${worker.batch_size}`} color="var(--accent)" />
          <MetricCell label="CLUSTERS" value={worker.total_clusters}          sub="structural groups" color="var(--processing)" />
          <MetricCell label="PARSERS"  value={worker.total_parsers_onboarded} sub="AI-synthesized" color="var(--success)" />
          <MetricCell label="COMMITTED"value={worker.total_committed}          sub="via AI path" color="var(--success)" />
        </div>
      </div>

      {/* Storage */}
      <div>
        <div className="t-label" style={{ marginBottom: 10 }}>Normalized Storage</div>
        <div className="console-metric-grid">
          <MetricCell label="TOTAL"    value={storage.total_committed} sub="OCSF events"     color="var(--success)" />
          <MetricCell label="SRC IPs"  value={storage.unique_src_ips}  sub="unique sources"  color="var(--accent)" />
          <MetricCell label="ALLOWED"  value={storage.by_disposition?.Allowed ?? 0} sub="disposition" color="var(--success)" />
          <MetricCell label="BLOCKED"  value={storage.by_disposition?.Blocked ?? 0} sub="disposition" color="var(--error)" />
        </div>
      </div>

      {/* Worker config */}
      <div style={{
        background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 'var(--radius)',
        padding: '14px 16px', display: 'flex', gap: 24, flexWrap: 'wrap',
      }}>
        {[
          { k: 'Status',        v: worker.is_running ? 'RUNNING' : 'STOPPED',
            c: worker.is_running ? 'var(--success)' : 'var(--warning)' },
          { k: 'Poll Interval', v: `${worker.poll_interval}s`,      c: 'var(--text-2)' },
          { k: 'Batch Size',    v: `${worker.batch_size} events`,   c: 'var(--text-2)' },
        ].map(({ k, v, c }) => (
          <div key={k}>
            <div style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--text-3)', letterSpacing: '0.08em', marginBottom: 3 }}>{k}</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: c, fontWeight: 600 }}>{v}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
