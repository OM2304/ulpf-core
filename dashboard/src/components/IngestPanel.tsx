import { useState } from 'react';
import { triggerIngest, triggerProcessBatch } from '../api/ulpf';

interface Props {
  onRefresh: () => void;
}

export default function IngestPanel({ onRefresh }: Props) {
  const [logs, setLogs] = useState('');
  const [status, setStatus] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleIngest = async () => {
    const lines = logs.split('\n').filter(l => l.trim());
    if (!lines.length) return;
    setLoading(true);
    setStatus(null);
    try {
      const res = await triggerIngest(lines) as { ingested_count?: number };
      await triggerProcessBatch();
      setStatus(`✓ Ingested & processed ${res.ingested_count ?? lines.length} log(s)`);
      setLogs('');
      onRefresh();
    } catch (e) {
      setStatus(`✗ Error: ${e}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card fade-in">
      <div className="card-header">
        <span className="icon">⬆</span>
        <h2>Ingest Logs</h2>
      </div>
      <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          Paste raw log lines (one per line). They'll be spooled → deterministically parsed → committed or routed to AI.
        </div>
        <textarea
          id="ingest-textarea"
          className="ingest-textarea"
          placeholder={`Aug 31 14:15:20 auth-server sshd[12345]: Accepted password for root from 192.168.1.20 port 49152 ssh2\nCEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|drop|1|src=10.0.0.15 dst=172.16.0.40 proto=UDP act=drop`}
          value={logs}
          onChange={(e) => setLogs(e.target.value)}
          rows={4}
        />
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <button
            id="btn-ingest"
            className="btn btn-primary"
            onClick={handleIngest}
            disabled={loading || !logs.trim()}
          >
            {loading ? '⟳ Ingesting…' : '⬆ Ingest & Process'}
          </button>
          {status && (
            <span style={{
              fontSize: 12,
              color: status.startsWith('✓') ? 'var(--accent-green)' : 'var(--accent-red)',
              fontFamily: 'var(--font-mono)',
            }}>
              {status}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
