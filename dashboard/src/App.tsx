import { useState, useEffect, useCallback, useRef } from 'react';
import { fetchMetrics, fetchParsers, fetchClusters } from './api/ulpf';
import type { MetricsResponse, ParsersResponse, ClustersResponse } from './api/ulpf';
import Header from './components/Header';
import MetricsPanel from './components/MetricsPanel';
import SpoolChart from './components/SpoolChart';
import ParsersPanel from './components/ParsersPanel';
import ClustersPanel from './components/ClustersPanel';
import OCSFTable from './components/OCSFTable';
import IngestPanel from './components/IngestPanel';

interface SpoolPoint {
  time: string;
  total: number;
  committed: number;
  pending_ai: number;
}

const POLL_MS = 3000;
const MAX_HISTORY = 30;

export default function App() {
  const [metrics, setMetrics] = useState<MetricsResponse | null>(null);
  const [parsers, setParsers] = useState<ParsersResponse | null>(null);
  const [clusters, setClusters] = useState<ClustersResponse | null>(null);
  const [history, setHistory] = useState<SpoolPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [error, setError] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const refresh = useCallback(async () => {
    setError(null);
    try {
      const [m, p, c] = await Promise.all([
        fetchMetrics(),
        fetchParsers(),
        fetchClusters(),
      ]);
      setMetrics(m);
      setParsers(p);
      setClusters(c);
      setLastUpdated(new Date());

      // Update rolling sparkline history
      const now = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
      setHistory(prev => [
        ...prev.slice(-MAX_HISTORY + 1),
        {
          time: now,
          total: m.spool.total,
          committed: m.spool.committed,
          pending_ai: m.spool.pending_ai,
        },
      ]);
    } catch (e) {
      setError(`Backend unreachable: ${e}. Make sure uvicorn ulpf.listener:app is running on port 8000.`);
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    refresh();
  }, [refresh]);

  // Auto-poll
  useEffect(() => {
    timerRef.current = setInterval(refresh, POLL_MS);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [refresh]);

  return (
    <div className="app-shell">
      <Header metrics={metrics} lastUpdated={lastUpdated} onRefresh={refresh} />

      <main className="main-content">
        {error && (
          <div style={{
            background: 'rgba(239,68,68,0.08)',
            border: '1px solid rgba(239,68,68,0.25)',
            borderRadius: 10,
            padding: '14px 18px',
            color: 'var(--accent-red)',
            fontSize: 12,
            fontFamily: 'var(--font-mono)',
          }}>
            ⚠ {error}
          </div>
        )}

        {/* Top row: Metrics + Spool Chart */}
        <div className="panel-grid-2">
          <MetricsPanel metrics={metrics} loading={loading} />
          <SpoolChart history={history} />
        </div>

        {/* Ingest Panel */}
        <IngestPanel onRefresh={refresh} />

        {/* Middle row: Parsers + Clusters */}
        <div className="panel-grid-2">
          <ParsersPanel parsers={parsers} loading={loading} />
          <ClustersPanel clusters={clusters} loading={loading} />
        </div>

        {/* Full-width OCSF Table */}
        <OCSFTable />
      </main>
    </div>
  );
}
