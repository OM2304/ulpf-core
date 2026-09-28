import { useEffect, useRef, useState } from 'react'
import {
  Activity,
  BrainCircuit,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Database,
  FileCode2,
  Maximize2,
  Minimize2,
  PieChart as PieIcon,
  RefreshCw,
  ShieldAlert,
  Sparkles,
  Terminal,
  Trash2,
} from 'lucide-react'
import {
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { api } from '../services/api'

const PARSER_FRIENDLY_NAMES = {
  core_apache_web_v1: 'Apache Web',
  core_nginx_web_v1: 'Nginx Web',
  core_pam_auth_v1: 'Linux PAM Auth',
  core_iptables_net_v1: 'IPtables Net',
  core_aws_vpc_v1: 'AWS VPC Flow',
  core_cisco_asa_v1: 'Cisco ASA FW',
  builtin_firewall_kv_v1: 'Firewall KV',
}

function formatParserName(id) {
  if (!id || id === 'unassigned') return 'Unassigned'
  if (PARSER_FRIENDLY_NAMES[id]) return PARSER_FRIENDLY_NAMES[id]
  return id
    .replace(/^core_|^ai_/, '')
    .replace(/_v\d+$/, '')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

const PIE_COLORS = [
  '#06b6d4', // Cyan
  '#10b981', // Emerald
  '#f59e0b', // Amber
  '#8b5cf6', // Violet
  '#ec4899', // Pink
  '#3b82f6', // Blue
  '#14b8a6', // Teal
  '#f97316', // Orange
]

const CustomPieTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const data = payload[0]
    return (
      <div className="bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-[11px] font-mono text-white shadow-lg">
        <span className="font-semibold text-cyan-400">{data.name}</span>: {data.value} records
      </div>
    )
  }
  return null
}

function DistributionRow({ label, value, total, colorClass, barColorClass }) {
  const percentage = total ? Math.round((value / total) * 100) : 0
  return (
    <div className="space-y-1.5">
      <div className="flex justify-between items-center text-xs font-mono">
        <span className="text-slate-600 dark:text-slate-400 font-medium">{label}</span>
        <div className="flex items-center gap-2">
          <strong className="text-slate-900 dark:text-slate-100 font-bold">{value.toLocaleString()}</strong>
          <span className="text-slate-400 dark:text-slate-500 text-[10px]">({percentage}%)</span>
        </div>
      </div>
      <div className="h-2 w-full bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
        <div
          className={`h-full transition-all duration-500 rounded-full ${barColorClass}`}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  )
}

export default function TelemetryDashboard() {
  // --- Telemetry Metrics State ---
  const [metrics, setMetrics] = useState(null)
  const [initialLoad, setInitialLoad] = useState(true)
  const [prevTotalSpooled, setPrevTotalSpooled] = useState(0)
  const [loadingMetrics, setLoadingMetrics] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [metricsError, setMetricsError] = useState(null)

  // --- AI Triage State ---
  const [triaging, setTriaging] = useState(false)
  const [triageResult, setTriageResult] = useState(null)

  // --- Chart Historical Data State ---
  const [chartData, setChartData] = useState([])

  // --- Terminal Console State ---
  const [terminalLogs, setTerminalLogs] = useState([
    {
      id: 1,
      time: new Date().toLocaleTimeString(),
      type: 'system',
      text: 'ULPF Telemetry Daemon initialized. Connected to http://127.0.0.1:8000',
    },
    {
      id: 2,
      time: new Date().toLocaleTimeString(),
      type: 'info',
      text: 'WAL Spool SQLite engine active. Telemetry polling started (2.5s interval).',
    },
  ])
  const [showVerboseLogs, setShowVerboseLogs] = useState(false)
  const [backendLogs, setBackendLogs] = useState([])
  const [isTerminalExpanded, setIsTerminalExpanded] = useState(false)
  const [isTerminalFullscreen, setIsTerminalFullscreen] = useState(false)
  const terminalContainerRef = useRef(null)
  const terminalWasAtBottomRef = useRef(true)

  // --- Auto-scroll Terminal internally without window hijacking ---
  useEffect(() => {
    const container = terminalContainerRef.current
    if (!container) return

    if (terminalWasAtBottomRef.current) {
      container.scrollTop = container.scrollHeight
    }
  }, [terminalLogs, backendLogs, showVerboseLogs])

  // --- Helper to append terminal logs ---
  const logToTerminal = (type, text, payload = null) => {
    setTerminalLogs((prev) => [
      ...prev,
      {
        id: Date.now() + Math.random(),
        time: new Date().toLocaleTimeString(),
        type,
        text,
        payload,
      },
    ])
  }

  // --- Poll Metrics & Console Logs ---
  const fetchMetricsAndLogs = async () => {
    try {
      const mData = await api.metrics()
      setMetrics(mData)
      setMetricsError(null)
      setInitialLoad(false)

      // Calculate ingestion throughput delta
      const nowStr = new Date().toLocaleTimeString()
      const newTotal = mData.total_spooled || 0
      const throughput = prevTotalSpooled > 0 ? Math.max(0, newTotal - prevTotalSpooled) : 0
      setPrevTotalSpooled(newTotal)

      // Update recharts historical queue
      setChartData((prev) => {
        const nextPoint = {
          time: nowStr,
          throughput: throughput,
          committed: mData.spool_counts?.COMMITTED || 0,
          pendingAi: mData.spool_counts?.PENDING_AI || 0,
          quarantined: mData.spool_counts?.QUARANTINED || 0,
        }
        const updated = [...prev, nextPoint]
        return updated.slice(-20) // Keep last 20 data points
      })
    } catch (err) {
      setMetricsError(err.message || 'Failed to fetch metrics')
    } finally {
      setLoadingMetrics(false)
    }

    try {
      const cData = await api.getConsoleLogs()
      if (cData && Array.isArray(cData.logs)) {
        setBackendLogs(cData.logs)
      }
    } catch (err) {
      // Non-blocking error for console logs stream
    }
  }

  useEffect(() => {
    fetchMetricsAndLogs()
    const interval = setInterval(fetchMetricsAndLogs, 2500)
    return () => clearInterval(interval)
  }, [prevTotalSpooled])

  // --- Trigger AI Triage Handler ---
  const handleTriggerTriage = async () => {
    setTriaging(true)
    setTriageResult(null)
    logToTerminal('info', '[TRIAGE_TRIGGER] Manual autonomous triage execution requested.')
    try {
      const result = await api.triage()
      setTriageResult(result)
      logToTerminal('success', `[TRIAGE_COMPLETE] Clusters: ${result.clusters_detected}, Parsers: ${result.onboarded_parsers}, Committed: ${result.committed}`)
      await fetchMetricsAndLogs()
    } catch (err) {
      const msg = err.message || 'Triage failed'
      logToTerminal('error', `[TRIAGE_ERROR] ${msg}`)
    } finally {
      setTriaging(false)
    }
  }

  // --- Manual Refresh Handler ---
  const handleManualRefresh = async () => {
    setIsRefreshing(true)
    logToTerminal('info', '[REFRESH] Manually triggering telemetry metrics fetch...')
    try {
      await fetchMetricsAndLogs()
    } catch (err) {
      logToTerminal('error', `[REFRESH_ERROR] ${err.message || 'Refresh failed'}`)
    } finally {
      setIsRefreshing(false)
    }
  }

  // Destructure metrics counters
  const committedCount = metrics?.spool_counts?.COMMITTED || metrics?.total_ocsf_committed || 0
  const pendingAiCount = metrics?.spool_counts?.PENDING_AI || 0
  const quarantinedCount = metrics?.spool_counts?.QUARANTINED || 0
  const totalSpooled = metrics?.total_spooled || 0
  const activeParsersCount = metrics?.active_parsers_count || 0

  // Log Source Distribution Data
  const rawDistribution = metrics?.source_distribution || {}
  const sourceData = Object.entries(rawDistribution)
    .map(([key, count]) => ({
      name: formatParserName(key),
      rawId: key,
      value: Number(count) || 0,
    }))
    .filter((item) => item.value > 0)
    .sort((a, b) => b.value - a.value)

  const totalSourceCount = sourceData.reduce((acc, curr) => acc + curr.value, 0)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-200 dark:border-gray-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-cyan-600 dark:bg-cyan-400 animate-pulse" />
            <p className="text-xs uppercase tracking-widest text-cyan-700 dark:text-cyan-400 font-mono font-semibold">
              Live Telemetry & Control Plane
            </p>
          </div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-gray-100 tracking-tight mt-1">
            ULPF Command Center
          </h1>
          <p className="text-xs text-slate-600 dark:text-gray-400 mt-1">
            High-Level Pipeline Metrics, Log Source Distribution, WAL Queue Health, Real-Time Throughput, and Autonomous AI Triage.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleManualRefresh}
            disabled={isRefreshing || loadingMetrics}
            className="flex items-center gap-2 px-3 py-2 text-xs font-semibold text-slate-700 dark:text-gray-300 bg-white dark:bg-gray-900 border border-slate-300 dark:border-gray-800 rounded hover:border-cyan-500 hover:text-cyan-600 dark:hover:border-cyan-400 dark:hover:text-cyan-400 transition-all cursor-pointer disabled:opacity-50 shadow-sm"
          >
            <RefreshCw size={14} className={isRefreshing ? 'animate-spin' : ''} />
            <span>Refresh Now</span>
          </button>
        </div>
      </div>

      {/* 1. Five Real-Time Telemetry Counters */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Total Committed Card */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm rounded-lg p-4 relative overflow-hidden group hover:border-emerald-500/50 transition-all">
          <div className="flex justify-between items-start">
            <span className="text-xs font-mono font-bold text-slate-500 dark:text-gray-400 uppercase tracking-wider">
              Total Committed
            </span>
            <div className="p-2 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 rounded">
              <CheckCircle2 size={18} />
            </div>
          </div>
          <div className="mt-3">
            {initialLoad ? (
              <div className="h-10 w-28 bg-slate-200 dark:bg-gray-800 animate-pulse rounded" />
            ) : (
              <span className="text-3xl sm:text-4xl font-bold font-mono text-emerald-600 dark:text-emerald-400 tracking-tight">
                {committedCount.toLocaleString()}
              </span>
            )}
            <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 font-mono">
              Deterministic OCSF events
            </p>
          </div>
          <div className="absolute top-0 right-0 w-24 h-1 bg-emerald-500" />
        </div>

        {/* Pending AI Card */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm rounded-lg p-4 relative overflow-hidden group hover:border-amber-500/50 transition-all">
          <div className="flex justify-between items-start">
            <span className="text-xs font-mono font-bold text-slate-500 dark:text-gray-400 uppercase tracking-wider">
              Pending AI Triage
            </span>
            <div className="p-2 bg-amber-500/10 text-amber-600 dark:text-amber-400 rounded">
              <Sparkles size={18} />
            </div>
          </div>
          <div className="mt-3">
            {initialLoad ? (
              <div className="h-10 w-28 bg-slate-200 dark:bg-gray-800 animate-pulse rounded" />
            ) : (
              <span className="text-3xl sm:text-4xl font-bold font-mono text-amber-600 dark:text-amber-400 tracking-tight">
                {pendingAiCount.toLocaleString()}
              </span>
            )}
            <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 font-mono">
              Queued for RAG synthesis
            </p>
          </div>
          <div className="absolute top-0 right-0 w-24 h-1 bg-amber-500" />
        </div>

        {/* Quarantined Card */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm rounded-lg p-4 relative overflow-hidden group hover:border-rose-500/50 transition-all">
          <div className="flex justify-between items-start">
            <span className="text-xs font-mono font-bold text-slate-500 dark:text-gray-400 uppercase tracking-wider">
              Quarantined
            </span>
            <div className="p-2 bg-rose-500/10 text-rose-600 dark:text-rose-400 rounded">
              <ShieldAlert size={18} />
            </div>
          </div>
          <div className="mt-3">
            {initialLoad ? (
              <div className="h-10 w-28 bg-slate-200 dark:bg-gray-800 animate-pulse rounded" />
            ) : (
              <span className="text-3xl sm:text-4xl font-bold font-mono text-rose-600 dark:text-rose-400 tracking-tight">
                {quarantinedCount.toLocaleString()}
              </span>
            )}
            <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 font-mono">
              Poison pill logs isolated
            </p>
          </div>
          <div className="absolute top-0 right-0 w-24 h-1 bg-rose-500" />
        </div>

        {/* Total Spooled Card */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm rounded-lg p-4 relative overflow-hidden group hover:border-cyan-500/50 transition-all">
          <div className="flex justify-between items-start">
            <span className="text-xs font-mono font-bold text-slate-500 dark:text-gray-400 uppercase tracking-wider">
              Total Ingested
            </span>
            <div className="p-2 bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 rounded">
              <Database size={18} />
            </div>
          </div>
          <div className="mt-3">
            {initialLoad ? (
              <div className="h-10 w-28 bg-slate-200 dark:bg-gray-800 animate-pulse rounded" />
            ) : (
              <span className="text-3xl sm:text-4xl font-bold font-mono text-cyan-600 dark:text-cyan-400 tracking-tight">
                {totalSpooled.toLocaleString()}
              </span>
            )}
            <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 font-mono">
              Durable spool records
            </p>
          </div>
          <div className="absolute top-0 right-0 w-24 h-1 bg-cyan-500 dark:bg-cyan-400" />
        </div>

        {/* Active Parsers Card (Migrated from Overview) */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm rounded-lg p-4 relative overflow-hidden group hover:border-indigo-500/50 transition-all">
          <div className="flex justify-between items-start">
            <span className="text-xs font-mono font-bold text-slate-500 dark:text-gray-400 uppercase tracking-wider">
              Active Parsers
            </span>
            <div className="p-2 bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 rounded">
              <FileCode2 size={18} />
            </div>
          </div>
          <div className="mt-3">
            {initialLoad ? (
              <div className="h-10 w-28 bg-slate-200 dark:bg-gray-800 animate-pulse rounded" />
            ) : (
              <span className="text-3xl sm:text-4xl font-bold font-mono text-indigo-600 dark:text-indigo-400 tracking-tight">
                {activeParsersCount.toLocaleString()}
              </span>
            )}
            <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 font-mono">
              Deterministic registry
            </p>
          </div>
          <div className="absolute top-0 right-0 w-24 h-1 bg-indigo-500 dark:bg-indigo-400" />
        </div>
      </div>

      {/* Row 2: Throughput Chart (6 Cols) & Log Source Distribution Donut Chart (6 Cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Dynamic Load Spikes & Ingestion Chart (6 Cols) */}
        <div className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm rounded-lg p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Activity size={18} className="text-cyan-600 dark:text-cyan-400" />
              <h2 className="text-sm font-semibold text-slate-800 dark:text-gray-200 uppercase tracking-wider font-mono">
                Real-Time Ingestion Throughput
              </h2>
            </div>
            <div className="flex items-center gap-3 text-[10px] font-mono text-slate-600 dark:text-gray-400">
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-cyan-500" /> Throughput (delta/s)
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-amber-500" /> Pending AI Queue
              </span>
            </div>
          </div>

          <div className="h-64 w-full mt-2">
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#94a3b8" strokeOpacity={0.25} />
                  <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} />
                  <YAxis stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(15, 23, 42, 0.95)',
                      borderColor: '#334155',
                      borderRadius: '0.375rem',
                      fontSize: '11px',
                      fontFamily: 'monospace',
                      color: '#f8fafc',
                    }}
                    itemStyle={{ color: '#38bdf8' }}
                  />
                  <Line
                    type="monotone"
                    dataKey="throughput"
                    name="Throughput Rate"
                    stroke="#06b6d4"
                    strokeWidth={2}
                    dot={{ r: 2, fill: '#06b6d4' }}
                    activeDot={{ r: 5 }}
                  />
                  <Line
                    type="monotone"
                    dataKey="pendingAi"
                    name="Pending AI Queue"
                    stroke="#f59e0b"
                    strokeWidth={2}
                    dot={{ r: 2, fill: '#f59e0b' }}
                    activeDot={{ r: 5 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500 dark:text-gray-500 font-mono">
                Gathering real-time telemetry data points...
              </div>
            )}
          </div>
        </div>

        {/* Log Source & Parser Distribution Donut Chart (6 Cols) */}
        <div className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm rounded-lg p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2 border-b border-slate-100 dark:border-slate-800/80 pb-2.5">
            <div className="flex items-center gap-2">
              <PieIcon size={18} className="text-cyan-600 dark:text-cyan-400" />
              <h2 className="text-sm font-semibold text-slate-800 dark:text-gray-200 uppercase tracking-wider font-mono">
                Log Source & Parser Distribution
              </h2>
            </div>
            <span className="text-[10px] font-mono text-cyan-700 dark:text-cyan-400 font-semibold bg-cyan-50 dark:bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-200 dark:border-cyan-800">
              {sourceData.length} Source{sourceData.length === 1 ? '' : 's'} Active
            </span>
          </div>

          <div className="h-64 w-full flex items-center justify-center">
            {sourceData.length > 0 ? (
              <div className="w-full h-full flex flex-col sm:flex-row items-center justify-center gap-4">
                <div className="h-52 w-52 shrink-0">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={sourceData}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={75}
                        paddingAngle={3}
                        dataKey="value"
                      >
                        {sourceData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip content={<CustomPieTooltip />} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex-1 w-full max-h-52 overflow-y-auto space-y-1.5 pr-2 font-mono text-xs">
                  {sourceData.map((item, idx) => {
                    const color = PIE_COLORS[idx % PIE_COLORS.length]
                    const pct = totalSourceCount > 0 ? Math.round((item.value / totalSourceCount) * 100) : 0
                    return (
                      <div key={item.name} className="flex items-center justify-between p-1.5 rounded hover:bg-slate-50 dark:hover:bg-slate-800/40">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: color }} />
                          <span className="truncate text-slate-700 dark:text-slate-300 font-medium text-[11px]">{item.name}</span>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0 ml-2">
                          <strong className="text-slate-900 dark:text-slate-100 font-semibold text-[11px]">{item.value.toLocaleString()}</strong>
                          <span className="text-slate-400 dark:text-slate-500 text-[10px]">({pct}%)</span>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-xs text-slate-500 dark:text-gray-500 font-mono text-center px-4">
                <Database size={24} className="mb-2 text-slate-400 opacity-60" />
                <span>No parsed log sources committed yet.</span>
                <span className="text-[10px] mt-1 text-slate-400">Stream logs via Data Ingestion to populate live distribution.</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Row 3: Queue Health (6 Cols) & Autonomous Triage Engine (6 Cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Spool Distribution / Queue Health (6 Cols) */}
        <div className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3 border-b border-slate-100 dark:border-slate-800/80 pb-2.5">
              <div className="flex items-center gap-2">
                <Database size={16} className="text-cyan-600 dark:text-cyan-400" />
                <h2 className="text-sm font-semibold text-slate-800 dark:text-gray-200 uppercase tracking-wider font-mono">
                  Queue Health & Distribution
                </h2>
              </div>
              <span className="flex items-center gap-1.5 text-[10px] font-mono text-emerald-600 dark:text-emerald-400 uppercase font-semibold">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" /> Live
              </span>
            </div>

            <div className="space-y-3.5 mt-2">
              <DistributionRow
                label="Committed (Deterministic)"
                value={committedCount}
                total={totalSpooled}
                colorClass="text-emerald-600 dark:text-emerald-400"
                barColorClass="bg-emerald-500"
              />
              <DistributionRow
                label="Pending AI Triage"
                value={pendingAiCount}
                total={totalSpooled}
                colorClass="text-amber-600 dark:text-amber-400"
                barColorClass="bg-amber-500"
              />
              <DistributionRow
                label="Quarantined (Poison Pills)"
                value={quarantinedCount}
                total={totalSpooled}
                colorClass="text-rose-600 dark:text-rose-400"
                barColorClass="bg-rose-500"
              />
            </div>
          </div>
        </div>

        {/* Autonomous AI Triage Control (6 Cols) */}
        <div className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <BrainCircuit size={17} className="text-cyan-600 dark:text-cyan-400" />
                <h2 className="text-sm font-semibold text-slate-800 dark:text-gray-200 uppercase tracking-wider font-mono">
                  Autonomous Triage Engine
                </h2>
              </div>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed mb-4">
              Cluster unrecognized formats, synthesize validated regex parsers with few-shot RAG, and promote new parsers to the registry.
            </p>
          </div>

          <div>
            <button
              onClick={handleTriggerTriage}
              disabled={triaging}
              className="w-full py-2.5 px-4 rounded font-medium text-xs bg-slate-900 text-white hover:bg-slate-800 transition-colors shadow-sm dark:bg-cyan-500 dark:text-slate-950 dark:hover:bg-cyan-400 dark:font-semibold flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {triaging ? (
                <>
                  <RefreshCw size={14} className="animate-spin" />
                  <span>Running AI Triage Cycle...</span>
                </>
              ) : (
                <>
                  <Sparkles size={14} />
                  <span>Trigger Autonomous AI Triage</span>
                </>
              )}
            </button>

            {triageResult && (
              <div className="mt-3.5 pt-3 border-t border-slate-100 dark:border-slate-800 grid grid-cols-3 gap-2 text-center font-mono">
                <div className="p-1.5 bg-slate-50 dark:bg-slate-950/50 rounded border border-slate-200 dark:border-slate-800">
                  <span className="block text-[10px] text-slate-500 uppercase">Clusters</span>
                  <strong className="text-xs text-cyan-600 dark:text-cyan-400">{triageResult.clusters_detected}</strong>
                </div>
                <div className="p-1.5 bg-slate-50 dark:bg-slate-950/50 rounded border border-slate-200 dark:border-slate-800">
                  <span className="block text-[10px] text-slate-500 uppercase">Synthesized</span>
                  <strong className="text-xs text-amber-600 dark:text-amber-400">{triageResult.onboarded_parsers}</strong>
                </div>
                <div className="p-1.5 bg-slate-50 dark:bg-slate-950/50 rounded border border-slate-200 dark:border-slate-800">
                  <span className="block text-[10px] text-slate-500 uppercase">Committed</span>
                  <strong className="text-xs text-emerald-600 dark:text-emerald-400">{triageResult.committed}</strong>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 3. Daemon Console Terminal Component */}
      <div
        className={`bg-slate-900 border border-slate-300 dark:border-slate-800 rounded-lg overflow-hidden transition-all shadow-md ${
          isTerminalFullscreen ? 'fixed inset-4 z-50 shadow-2xl flex flex-col' : ''
        }`}
      >
        {/* Terminal Header */}
        <div className="bg-slate-900 border-b border-slate-800 px-4 py-2.5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block" />
              <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
              <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
            </div>
            <div className="flex items-center gap-2 ml-2">
              <Terminal size={14} className="text-cyan-400" />
              <span className="text-xs font-mono font-semibold text-slate-100">
                ULPF Daemon Console Terminal
              </span>
            </div>
            <span className="px-2 py-0.5 text-[9px] font-mono font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800 rounded">
              LIVE STREAMING
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setShowVerboseLogs((prev) => !prev)}
              className="text-cyan-400 hover:underline font-bold text-xs mr-2 cursor-pointer"
            >
              {showVerboseLogs ? 'Hide Backend Logs' : 'Show Backend Logs'}
            </button>
            <button
              onClick={() => setIsTerminalExpanded(!isTerminalExpanded)}
              className="p-1 text-slate-400 hover:text-cyan-400 hover:bg-slate-800 rounded transition-colors cursor-pointer"
              title={isTerminalExpanded ? 'Collapse Height' : 'Expand Height'}
            >
              {isTerminalExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
            </button>
            <button
              onClick={() => setIsTerminalFullscreen(!isTerminalFullscreen)}
              className="p-1 text-slate-400 hover:text-cyan-400 hover:bg-slate-800 rounded transition-colors cursor-pointer"
              title={isTerminalFullscreen ? 'Exit Fullscreen' : 'Fullscreen View Mode'}
            >
              {isTerminalFullscreen ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
            </button>
            <button
              onClick={() => {
                if (showVerboseLogs) setBackendLogs([])
                else setTerminalLogs([])
              }}
              className="p-1 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors cursor-pointer"
              title="Clear Terminal Output"
            >
              <Trash2 size={16} />
            </button>
          </div>
        </div>

        {/* Terminal Body */}
        <div
          ref={terminalContainerRef}
          onScroll={(event) => {
            const container = event.currentTarget
            terminalWasAtBottomRef.current =
              container.scrollHeight - container.scrollTop - container.clientHeight < 80
          }}
          className={`p-4 font-mono text-xs overflow-y-auto space-y-1.5 bg-slate-900 dark:bg-black text-slate-100 ${
            isTerminalFullscreen
              ? 'flex-1'
              : isTerminalExpanded
              ? 'h-96'
              : 'h-56'
          }`}
        >
          {showVerboseLogs ? (
            backendLogs.length > 0 ? (
              backendLogs.map((logStr, idx) => (
                <div key={idx} className="flex items-start gap-2 leading-relaxed hover:bg-slate-800/50 px-1 py-0.5 rounded">
                  <span className="text-cyan-400 font-bold shrink-0 text-[10px] select-none">[BACKEND]</span>
                  <span className="text-slate-200 break-all">{logStr}</span>
                </div>
              ))
            ) : (
              <div className="text-slate-400 italic py-2">
                No backend AI processing logs recorded yet. Trigger AI triage to generate logs.
              </div>
            )
          ) : (
            terminalLogs.map((log) => (
              <div key={log.id} className="flex items-start gap-2 leading-relaxed hover:bg-slate-800/50 px-1 py-0.5 rounded">
                <span className="text-slate-400 shrink-0 text-[10px] select-none">[{log.time}]</span>
                {log.type === 'error' && (
                  <span className="px-1.5 py-0.2 bg-rose-950 text-rose-400 border border-rose-800 rounded text-[10px] shrink-0 font-semibold">
                    ERROR
                  </span>
                )}
                {log.type === 'success' && (
                  <span className="px-1.5 py-0.2 bg-emerald-950 text-emerald-400 border border-emerald-800 rounded text-[10px] shrink-0 font-semibold">
                    SUCCESS
                  </span>
                )}
                {log.type === 'info' && (
                  <span className="px-1.5 py-0.2 bg-cyan-950 text-cyan-400 border border-cyan-800 rounded text-[10px] shrink-0 font-semibold">
                    INFO
                  </span>
                )}
                {log.type === 'system' && (
                  <span className="px-1.5 py-0.2 bg-slate-800 text-slate-300 rounded text-[10px] shrink-0 font-semibold">
                    SYSTEM
                  </span>
                )}
                <span className="text-slate-100 break-all">{log.text}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
