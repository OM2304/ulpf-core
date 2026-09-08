import type { ClustersResponse, ClusterInfo } from '../api/ulpf';
import { useState } from 'react';

interface Props {
  clusters: ClustersResponse | null;
  loading: boolean;
}

function ClusterCard({ cluster }: { cluster: ClusterInfo }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div style={{
      background: 'var(--bg)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '10px 14px',
        borderBottom: '1px solid var(--border)',
        gap: 10,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 12,
            fontWeight: 600,
            color: 'var(--text)',
          }}>
            #{cluster.cluster_id}
          </span>
          <span className="badge badge-warning" style={{ fontSize: 9 }}>
            {cluster.sample_count} event{cluster.sample_count !== 1 ? 's' : ''}
          </span>
        </div>
        <button
          className="btn btn-ghost btn-sm"
          onClick={() => setExpanded(!expanded)}
          id={`cluster-expand-${cluster.cluster_id}`}
          aria-expanded={expanded}
        >
          {expanded ? '▲ Collapse' : '▼ Samples'}
        </button>
      </div>

      {/* Skeleton */}
      <div style={{ padding: '10px 14px' }}>
        <div className="t-label" style={{ marginBottom: 6 }}>Structural Skeleton</div>
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 12,
          color: 'var(--accent)',
          background: 'var(--surface-2)',
          padding: '8px 10px',
          borderRadius: 'var(--radius-sm)',
          wordBreak: 'break-all',
          lineHeight: 1.6,
        }}>
          {cluster.skeleton}
        </div>
      </div>

      {/* Expanded samples */}
      {expanded && cluster.sample_logs.length > 0 && (
        <div style={{ padding: '0 14px 12px', borderTop: '1px solid var(--border)' }}>
          <div className="t-label" style={{ margin: '10px 0 6px' }}>Raw Sample Logs</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {cluster.sample_logs.map((log, i) => (
              <div
                key={i}
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 10.5,
                  color: 'var(--text-2)',
                  background: 'var(--surface)',
                  padding: '6px 8px',
                  borderRadius: 3,
                  overflow: 'hidden',
                  whiteSpace: 'nowrap',
                  textOverflow: 'ellipsis',
                }}
                title={log}
              >
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
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {[...Array(3)].map((_, i) => (
          <div key={i} className="shimmer" style={{ height: 80 }} />
        ))}
      </div>
    );
  }

  const clusterList = clusters?.clusters ?? [];
  const totalPending = clusters?.total_pending_ai ?? 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Summary */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <span className="badge badge-warning">{totalPending} pending AI</span>
        <span className="badge badge-processing">{clusterList.length} clusters</span>
        <span style={{ fontSize: 12, color: 'var(--text-3)', alignSelf: 'center', marginLeft: 4 }}>
          Structural fingerprints extracted from PENDING_AI spool events.
          Each cluster represents a unique log format the AI agent will synthesize a parser for.
        </span>
      </div>

      {/* Cluster list */}
      {clusterList.length === 0 ? (
        <div style={{
          padding: 40, textAlign: 'center', border: '1px dashed var(--border)',
          borderRadius: 'var(--radius-lg)', color: 'var(--text-3)',
        }}>
          <div style={{ fontSize: 28, marginBottom: 10 }}>✅</div>
          <div style={{ fontWeight: 600, color: 'var(--text-2)', marginBottom: 6 }}>
            No PENDING_AI events
          </div>
          <div style={{ fontSize: 12 }}>
            All logs are normalized. Ingest unrecognized formats to see cluster skeletons appear here.
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {clusterList.map((c) => (
            <ClusterCard key={c.cluster_id} cluster={c} />
          ))}
        </div>
      )}
    </div>
  );
}
