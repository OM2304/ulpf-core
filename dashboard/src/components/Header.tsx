import type { MetricsResponse } from '../api/ulpf';
import { triggerProcessBatch } from '../api/ulpf';
import { useState } from 'react';

interface Props {
  metrics: MetricsResponse | null;
  lastUpdated: Date | null;
  onRefresh: () => void;
}

export default function Header({ metrics, lastUpdated, onRefresh }: Props) {
  const [processing, setProcessing] = useState(false);

  const handleProcess = async () => {
    setProcessing(true);
    try {
      await triggerProcessBatch();
      onRefresh();
    } finally {
      setProcessing(false);
    }
  };

  const workerActive = metrics?.worker?.is_running ?? false;

  return (
    <header className="header">
      <div className="header-brand">
        <div className="header-logo">UL</div>
        <div>
          <div className="header-title">ULPF Dashboard</div>
          <div className="header-sub">UNIVERSAL LOG PRE-PROCESSING FRAMEWORK v0.2.0</div>
        </div>
      </div>

      <div className="header-right">
        {lastUpdated && (
          <span className="last-updated">
            Updated {lastUpdated.toLocaleTimeString()}
          </span>
        )}
        <span className={`badge ${workerActive ? 'green' : 'orange'}`}>
          <span className="dot" />
          Agent {workerActive ? 'Active' : 'Idle'}
        </span>
        <button
          className="btn btn-ghost"
          onClick={handleProcess}
          disabled={processing}
          id="btn-process-batch"
        >
          {processing ? '⟳ Processing…' : '▶ Process Batch'}
        </button>
        <button
          className="btn btn-primary"
          onClick={onRefresh}
          id="btn-refresh"
        >
          ↺ Refresh
        </button>
      </div>
    </header>
  );
}
