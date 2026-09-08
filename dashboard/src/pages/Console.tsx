import { useState, useEffect, useCallback } from 'react';
import { NavLink } from 'react-router-dom';
import MetricsPanel from '../components/MetricsPanel';
import ParsersPanel from '../components/ParsersPanel';
import ClustersPanel from '../components/ClustersPanel';
import OCSFTable from '../components/OCSFTable';
import IngestPanel from '../components/IngestPanel';
import type { MetricsResponse, ParsersResponse, ClustersResponse } from '../api/ulpf';
import { fetchMetrics, fetchParsers, fetchClusters } from '../api/ulpf';

const POLL_MS = 3000;
const MAX_HIST = 30;

interface SpoolPoint { time: string; total: number; committed: number; pending_ai: number; }

const SIDEBAR_ITEMS = [
  { id: 'metrics',   label: 'Pipeline Metrics', icon: '📊' },
  { id: 'ingest',    label: 'Ingest Logs',       icon: '⬆' },
  { id: 'parsers',   label: 'Parser Registry',   icon: '🔌' },
  { id: 'clusters',  label: 'Cluster Skeletons', icon: '🧬' },
  { id: 'events',    label: 'OCSF Events',       icon: '🛡' },
];

export default function Console() {
  const [activeSection, setActiveSection] = useState('metrics');
  const [metrics, setMetrics]   = useState<MetricsResponse | null>(null);
  const [parsers, setParsers]   = useState<ParsersResponse | null>(null);
  const [clusters, setClusters] = useState<ClustersResponse | null>(null);
  const [, setHistory]   = useState<SpoolPoint[]>([]);
  const [loading, setLoading]   = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setError(null);
    try {
      const [m, p, c] = await Promise.all([fetchMetrics(), fetchParsers(), fetchClusters()]);
      setMetrics(m); setParsers(p); setClusters(c);
      setLastUpdated(new Date());
      const now = new Date().toLocaleTimeString('en-US', { hour12: false });
      setHistory(prev => [
        ...prev.slice(-MAX_HIST + 1),
        { time: now, total: m.spool.total, committed: m.spool.committed, pending_ai: m.spool.pending_ai },
      ]);
    } catch (e) {
      setError(`Backend unreachable — run: uvicorn ulpf.listener:app`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => {
    const t = setInterval(refresh, POLL_MS);
    return () => clearInterval(t);
  }, [refresh]);

  return (
    <div className="console-layout">
      {/* Sidebar */}
      <aside className="console-sidebar" aria-label="Console navigation">
        <div className="console-sidebar-section">
          <div className="console-sidebar-label">Analytics</div>
          {SIDEBAR_ITEMS.map(item => (
            <button
              key={item.id}
              id={`sidebar-${item.id}`}
              className={`console-sidebar-link ${activeSection === item.id ? 'active' : ''}`}
              onClick={() => setActiveSection(item.id)}
            >
              <span>{item.icon}</span>
              <span>{item.label}</span>
            </button>
          ))}
        </div>

        <div className="console-sidebar-section">
          <div className="console-sidebar-label">Links</div>
          <NavLink to="/" className="console-sidebar-link">
            ← Overview
          </NavLink>
          <a
            href="http://localhost:8000/docs"
            target="_blank"
            rel="noreferrer"
            className="console-sidebar-link"
          >
            API Docs ↗
          </a>
        </div>

        {/* Worker status */}
        <div style={{ padding: '0 12px', marginTop: 'auto' }}>
          <div style={{
            background: 'var(--bg)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius)', padding: '10px 12px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
              <span className={`dot ${metrics?.worker?.is_running ? 'dot-success' : 'dot-warning'}`} />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 600, letterSpacing: '0.08em', color: 'var(--text-2)' }}>
                AGENT WORKER
              </span>
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-3)' }}>
              {metrics?.worker?.is_running ? 'Active · poll 2s' : 'Inactive'}
            </div>
            {lastUpdated && (
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-4)', marginTop: 4 }}>
                {lastUpdated.toLocaleTimeString()}
              </div>
            )}
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="console-main" aria-label="Console main content">
        {/* Header */}
        <div className="console-header">
          <div>
            <h1 className="console-title">
              {SIDEBAR_ITEMS.find(i => i.id === activeSection)?.label ?? 'Console'}
            </h1>
            <div className="console-sub">
              Universal Log Pre-Processing System · OCSF Class 4001
              {lastUpdated && <span style={{ marginLeft: 8, fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-3)' }}>
                · updated {lastUpdated.toLocaleTimeString()}
              </span>}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-ghost btn-sm" onClick={refresh} id="console-refresh">
              ↺ Refresh
            </button>
          </div>
        </div>

        {/* Error banner */}
        {error && (
          <div style={{
            background: 'var(--error-dim)', border: '1px solid rgba(239,68,68,0.2)',
            borderRadius: 'var(--radius)', padding: '12px 16px',
            fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--error)',
          }}>
            ⚠ {error}
          </div>
        )}

        {/* Section content */}
        {activeSection === 'metrics' && (
          <div className="console-card">
            <div className="console-card-header">
              <span>📊</span>
              <span className="console-card-title">Pipeline Metrics</span>
              <span className="badge badge-accent" style={{ marginLeft: 'auto' }}>Live · 3s</span>
            </div>
            <div className="console-card-body">
              <MetricsPanel metrics={metrics} loading={loading} />
            </div>
          </div>
        )}

        {activeSection === 'ingest' && (
          <div className="console-card">
            <div className="console-card-header">
              <span>⬆</span>
              <span className="console-card-title">Ingest Logs</span>
            </div>
            <div className="console-card-body">
              <IngestPanel onRefresh={refresh} />
            </div>
          </div>
        )}

        {activeSection === 'parsers' && (
          <div className="console-card">
            <div className="console-card-header">
              <span>🔌</span>
              <span className="console-card-title">Parser Registry</span>
              {parsers && (
                <span className="badge badge-muted" style={{ marginLeft: 'auto' }}>
                  {parsers.total} active
                </span>
              )}
            </div>
            <div className="console-card-body">
              <ParsersPanel parsers={parsers} loading={loading} />
            </div>
          </div>
        )}

        {activeSection === 'clusters' && (
          <div className="console-card">
            <div className="console-card-header">
              <span>🧬</span>
              <span className="console-card-title">AI Cluster Skeletons</span>
            </div>
            <div className="console-card-body">
              <ClustersPanel clusters={clusters} loading={loading} />
            </div>
          </div>
        )}

        {activeSection === 'events' && (
          <div className="console-card">
            <div className="console-card-header">
              <span>🛡</span>
              <span className="console-card-title">OCSF Class 4001 — Network Activity Events</span>
            </div>
            <div className="console-card-body">
              <OCSFTable />
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
