import { useEffect, useState } from 'react'
import { BrainCircuit, CheckCircle2, Database, FileCode2, RefreshCw, ShieldAlert, Sparkles } from 'lucide-react'
import { api } from '../services/api'
import { ErrorState, LoadingState, PageHeader } from '../components/ui'

function MetricCard({ label, value, detail, icon: Icon, tone = 'cyan' }) {
  return <div className={`metric-card ${tone}`}><div className="metric-icon"><Icon size={18} /></div><p className="metric-label">{label}</p><strong className="metric-value">{value ?? '—'}</strong><p className="metric-detail">{detail}</p></div>
}

export default function DashboardOverview() {
  const [metrics, setMetrics] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [triaging, setTriaging] = useState(false)
  const [triageResult, setTriageResult] = useState(null)

  const load = () => { setLoading(true); setError(null); api.metrics().then(setMetrics).catch(setError).finally(() => setLoading(false)) }
  useEffect(load, [])

  const triggerTriage = async () => {
    setTriaging(true); setTriageResult(null)
    try { const result = await api.triage(); setTriageResult(result); load() } catch (triageError) { setError(triageError) } finally { setTriaging(false) }
  }

  const quarantineCount = metrics?.spool_counts?.QUARANTINED || 0
  return <>
    <PageHeader eyebrow="Operational overview" title="Pipeline overview" description="A live view of ingestion, normalization, and autonomous parser learning." actions={<button className="button button-ghost" onClick={load} disabled={loading}><RefreshCw size={15} className={loading ? 'spin' : ''} /> Refresh</button>} />
    {error && <ErrorState error={error} onRetry={load} />}
    {loading && !metrics ? <LoadingState /> : <>
      <section className="metric-grid">
        <MetricCard label="Total ingested" value={metrics?.total_spooled} detail="durable spool records" icon={Database} />
        <MetricCard label="OCSF committed" value={metrics?.total_ocsf_committed} detail="normalized class 4001" icon={CheckCircle2} tone="mint" />
        <MetricCard label="Active parsers" value={metrics?.active_parsers_count} detail="deterministic registry" icon={FileCode2} tone="amber" />
        <MetricCard label="Quarantined" value={quarantineCount} detail="poison pills isolated" icon={ShieldAlert} tone={quarantineCount ? 'coral' : 'cyan'} />
      </section>
      <section className="overview-grid">
        <div className="panel triage-panel"><div className="panel-heading"><div><p className="eyebrow">Control plane</p><h2>Autonomous triage</h2></div><div className="panel-symbol"><BrainCircuit size={20} /></div></div><p className="panel-copy">Cluster unrecognized formats, synthesize validated regex parsers, and move eligible events into the normalized store.</p><button className="button button-primary" onClick={triggerTriage} disabled={triaging}><Sparkles size={16} />{triaging ? 'Running triage…' : 'Trigger AI triage'}</button>{triageResult && <div className="triage-result"><div><span>Clusters</span><strong>{triageResult.clusters_detected}</strong></div><div><span>Parsers built</span><strong>{triageResult.onboarded_parsers}</strong></div><div><span>Committed</span><strong>{triageResult.committed}</strong></div></div>}</div>
        <div className="panel signal-panel"><div className="panel-heading"><div><p className="eyebrow">Spool distribution</p><h2>Queue health</h2></div><span className="live-pill"><span className="pulse-dot" /> live</span></div><div className="distribution"><DistributionRow label="Committed" value={metrics?.spool_counts?.COMMITTED || 0} total={metrics?.total_spooled} tone="mint" /><DistributionRow label="Pending AI" value={metrics?.spool_counts?.PENDING_AI || 0} total={metrics?.total_spooled} tone="amber" /><DistributionRow label="Quarantined" value={quarantineCount} total={metrics?.total_spooled} tone="coral" /></div></div>
      </section>
    </>}
  </>
}

function DistributionRow({ label, value, total, tone }) {
  const percentage = total ? Math.round((value / total) * 100) : 0
  return <div className="distribution-row"><div><span>{label}</span><strong>{value}</strong></div><div className="bar"><span className={tone} style={{ width: `${percentage}%` }} /></div><small>{percentage}%</small></div>
}
