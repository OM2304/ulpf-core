import type { ClustersResponse, ClusterInfo } from '../api/ulpf';
import { useState } from 'react';

interface Props {
  clusters: ClustersResponse | null;
  loading: boolean;
}

function ClusterCard({ cluster }: { cluster: ClusterInfo }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="cluster-card fade-in">
      <div className="cluster-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span className="cluster-id">#{cluster.cluster_id}</span>
          <span className="badge orange" style={{ fontSize: 9 }}>
            {cluster.sample_count} event{cluster.sample_count !== 1 ? 's' : ''}
          </span>
        </div>
        <button
          className="expand-btn"
          onClick={() => setExpanded(!expanded)}
          id={`cluster-expand-${cluster.cluster_id}`}
        >
          {expanded ? '▲ Collapse' : '▼ Samples'}
        </button>
      </div>

      <div>
        <div style={{ fontSize: 9, color: 'var(--text-muted)', marginBottom: 4, letterSpacing: '0.08em' }}>
          STRUCTURAL SKELETON
        </div>
        <div className="cluster-skeleton">{cluster.skeleton}</div>
      </div>

      {expanded && cluster.sample_logs.length > 0 && (
        <div className="fade-in">
          <div style={{ fontSize: 9, color: 'var(--text-muted)', marginBottom: 6, letterSpacing: '0.08em' }}>
            RAW SAMPLE LOGS
          </div>
          <div className="cluster-samples">
            {cluster.sample_logs.map((log, i) => (
              <div key={i} className="cluster-sample" title={log}>
                {log}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function ClustersPanel({ clusters, loading }: Props) {
  if (loading && !clusters) {
    return (
      <div className="card fade-in">
        <div className="card-header">
          <span className="icon">🧬</span>
          <h2>Cluster Skeletons</h2>
        </div>
        <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {[...Array(3)].map((_, i) => <div key={i} className="loading-shimmer" style={{ height: 80 }} />)}
        </div>
      </div>
    );
  }

  const clusterList = clusters?.clusters ?? [];
  const totalPending = clusters?.total_pending_ai ?? 0;

  return (
    <div className="card fade-in">
      <div className="card-header">
        <span className="icon">🧬</span>
        <h2>AI Cluster Skeletons</h2>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          <span className="badge orange">{totalPending} pending AI</span>
          <span className="badge purple">{clusterList.length} clusters</span>
        </div>
      </div>
      <div className="card-body">
        {clusterList.length === 0 ? (
          <div className="empty-state">
            <div className="icon">✅</div>
            <div>No PENDING_AI events — all logs are normalized!</div>
            <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-muted)' }}>
              Ingest unrecognized log formats to see cluster skeletons appear here.
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
              Structural fingerprints extracted from PENDING_AI spool events. Each cluster represents a
              unique log format the AI agent will synthesize a parser for.
            </div>
            {clusterList.map((c) => (
              <ClusterCard key={c.cluster_id} cluster={c} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
