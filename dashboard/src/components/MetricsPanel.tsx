import type { MetricsResponse } from '../api/ulpf';

interface Props {
  metrics: MetricsResponse | null;
  loading: boolean;
}

interface MetricCardProps {
  label: string;
  value: number | string;
  sub?: string;
  color: string;
}

function MetricCard({ label, value, sub, color }: MetricCardProps) {
  return (
    <div className={`metric-card ${color}`}>
      <div className="label">{label}</div>
      <div className="value">{typeof value === 'number' ? value.toLocaleString() : value}</div>
      {sub && <div className="sub">{sub}</div>}
    </div>
  );
}

export default function MetricsPanel({ metrics, loading }: Props) {
  if (loading && !metrics) {
    return (
      <div className="card fade-in">
        <div className="card-header">
          <span className="icon">📊</span>
          <h2>Pipeline Metrics</h2>
        </div>
        <div className="card-body">
          <div className="metric-grid">
            {[...Array(6)].map((_, i) => (
              <div key={i} className="loading-shimmer" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (!metrics) return null;

  const { spool, worker, storage } = metrics;

  return (
    <div className="card fade-in">
      <div className="card-header">
        <span className="icon">📊</span>
        <h2>Pipeline Metrics</h2>
        <span className="badge cyan" style={{ marginLeft: 'auto' }}>
          OCSF Class 4001
        </span>
      </div>
      <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

        {/* Spool Section */}
        <div>
          <div className="section-title">Durable Spool (WAL-SQLite)</div>
          <div className="metric-grid">
            <MetricCard label="Total Spooled" value={spool.total} color="cyan" sub="all-time events" />
            <MetricCard label="Committed" value={spool.committed} color="green" sub="OCSF normalized" />
            <MetricCard label="Pending AI" value={spool.pending_ai} color="orange" sub="awaiting synthesis" />
            <MetricCard label="Durably Stored" value={spool.durably_stored} color="purple" sub="raw persisted" />
          </div>
        </div>

        {/* Agent Worker Section */}
        <div>
          <div className="section-title">AI Agent Worker (AgentWorker)</div>
          <div className="metric-grid">
            <MetricCard label="Total Triaged" value={worker.total_triaged} color="cyan" sub={`batch: ${worker.batch_size}`} />
            <MetricCard label="Clusters Detected" value={worker.total_clusters} color="purple" sub="structural groups" />
            <MetricCard label="Parsers Onboarded" value={worker.total_parsers_onboarded} color="green" sub="AI-synthesized" />
            <MetricCard label="Events Committed" value={worker.total_committed} color="green" sub="via AI path" />
          </div>
        </div>

        {/* Storage Section */}
        <div>
          <div className="section-title">Normalized Storage</div>
          <div className="metric-grid">
            <MetricCard label="Total Committed" value={storage.total_committed} color="green" sub="OCSF events" />
            <MetricCard label="Unique Src IPs" value={storage.unique_src_ips} color="cyan" sub="distinct sources" />
            {Object.entries(storage.by_disposition || {}).map(([disp, cnt]) => (
              <MetricCard
                key={disp}
                label={disp}
                value={cnt}
                color={disp === 'Allowed' ? 'green' : disp === 'Blocked' ? 'red' : 'orange'}
                sub="disposition"
              />
            ))}
          </div>
        </div>

        {/* Worker status row */}
        <div>
          <div className="section-title">Worker Configuration</div>
          <div className="worker-row">
            <span className="wlabel">Status</span>
            <span className={`badge ${worker.is_running ? 'green' : 'orange'}`}>
              <span className="dot" />
              {worker.is_running ? 'Running' : 'Stopped'}
            </span>
          </div>
          <div className="worker-row">
            <span className="wlabel">Poll Interval</span>
            <span className="wvalue">{worker.poll_interval}s</span>
          </div>
          <div className="worker-row">
            <span className="wlabel">Batch Size</span>
            <span className="wvalue">{worker.batch_size} events</span>
          </div>
          {Object.entries(storage.by_parser || {}).slice(0, 3).map(([pid, cnt]) => (
            <div className="worker-row" key={pid}>
              <span className="wlabel mono">{pid}</span>
              <span className="wvalue">{cnt} events</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
