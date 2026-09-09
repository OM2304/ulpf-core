import { useEffect, useRef, useState } from 'react'
import {
  Activity,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Database,
  FileText,
  FolderInput,
  Maximize2,
  Minimize2,
  Play,
  RefreshCw,
  Search,
  ShieldAlert,
  Sparkles,
  Terminal,
  Trash2,
} from 'lucide-react'
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from 'recharts'
import { api } from '../services/api'

export default function TelemetryDashboard() {
  // --- Telemetry Metrics State ---
  const [metrics, setMetrics] = useState(null)
  const [prevTotalSpooled, setPrevTotalSpooled] = useState(0)
  const [loadingMetrics, setLoadingMetrics] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [metricsError, setMetricsError] = useState(null)

  // --- Chart Historical Data State ---
  const [chartData, setChartData] = useState([])

  // --- Path Ingestion State ---
  const [inputPath, setInputPath] = useState('C:\\Users\\ombat\\ULPF\\chaos_stream.log')
  const [ingesting, setIngesting] = useState(false)
  const [ingestStatus, setIngestStatus] = useState(null)

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

  // --- Event Stream Table State ---
  const [events, setEvents] = useState([])
  const [expandedEventId, setExpandedEventId] = useState(null)
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [searchTerm, setSearchTerm] = useState('')

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

  // --- Poll Metrics, Events & Console Logs ---
  const fetchMetricsAndEvents = async () => {
    try {
      const mData = await api.metrics()
      setMetrics(mData)
      setMetricsError(null)

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
      const eData = await api.getSpoolEvents(50)
      setEvents(eData)
    } catch (err) {
      // Non-blocking error for table stream
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
    fetchMetricsAndEvents()
    const interval = setInterval(fetchMetricsAndEvents, 2500)
    return () => clearInterval(interval)
  }, [prevTotalSpooled])

  // --- Handle Path Ingestion Submit ---
  const handleIngestPath = async (e) => {
    if (e) e.preventDefault()
    const target = inputPath.trim()
    if (!target) return

    setIngesting(true)
    setIngestStatus(null)
    logToTerminal('info', `[INGEST_REQUEST] Triggering path pump for: ${target}`)

    try {
      const res = await api.ingestPath(target)
      setIngestStatus({ type: 'success', text: `Successfully ingested ${res.total_ingested} logs from ${res.path}` })
      logToTerminal('success', `[INGEST_SUCCESS] Total Ingested: ${res.total_ingested} lines from file`, res)
      setInputPath('') // Clear input field upon successful ingestion
      // Immediately refresh telemetry
      fetchMetricsAndEvents()
    } catch (err) {
      const errMsg = err.message || 'Ingestion failed'
      setIngestStatus({ type: 'error', text: errMsg })
      logToTerminal('error', `[INGEST_ERROR] ${errMsg}`)
    } finally {
      setIngesting(false)
    }
  }

  // --- Manual Refresh Handler ---
  const handleManualRefresh = async () => {
    setIsRefreshing(true)
    logToTerminal('info', '[REFRESH] Manually triggering telemetry metrics & event fetch...')
    try {
      await fetchMetricsAndEvents()
    } catch (err) {
      logToTerminal('error', `[REFRESH_ERROR] ${err.message || 'Refresh failed'}`)
    } finally {
      setIsRefreshing(false)
    }
  }

  // --- Quick Path Select Handler ---
  const handleQuickPathSelect = (filename) => {
    const fullPath = `C:\\Users\\ombat\\ULPF\\${filename}`
    setInputPath(fullPath)
    logToTerminal('info', `[QUICK_PATH] Selected preset log file path: ${fullPath}`)
  }

  // --- Filtered Events for Table ---
  const filteredEvents = events.filter((ev) => {
    const matchesFilter =
      statusFilter === 'ALL' ||
      (statusFilter === 'COMMITTED' && ev.status === 'COMMITTED') ||
      (statusFilter === 'PENDING_AI' && ev.status === 'PENDING_AI') ||
      (statusFilter === 'QUARANTINED' && ev.status === 'QUARANTINED')
    const searchLower = searchTerm.toLowerCase()
    const matchesSearch =
      !searchTerm ||
      (ev.event_id && ev.event_id.toLowerCase().includes(searchLower)) ||
      (ev.raw_payload && ev.raw_payload.toLowerCase().includes(searchLower)) ||
      (ev.parser_id && ev.parser_id.toLowerCase().includes(searchLower)) ||
      (ev.status && ev.status.toLowerCase().includes(searchLower))
    return matchesFilter && matchesSearch
  })

  // Destructure metrics counters
  const committedCount = metrics?.spool_counts?.COMMITTED || metrics?.total_ocsf_committed || 0
  const pendingAiCount = metrics?.spool_counts?.PENDING_AI || 0
  const quarantinedCount = metrics?.spool_counts?.QUARANTINED || 0
  const totalSpooled = metrics?.total_spooled || 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-gray-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
            <p className="text-xs uppercase tracking-widest text-cyan-400 font-mono font-semibold">
              Live Telemetry & Ingestion Dashboard
            </p>
          </div>
          <h1 className="text-2xl font-bold text-gray-100 tracking-tight mt-1">
            ULPF Command Center
          </h1>
          <p className="text-xs text-gray-400 mt-1">
            Real-Time Path Log Pumping, WAL Spool Monitoring, and Hybrid Few-Shot RAG AI Parsing Engine.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleManualRefresh}
            disabled={isRefreshing || loadingMetrics}
            className="flex items-center gap-2 px-3 py-2 text-xs font-semibold text-gray-300 bg-gray-900 border border-gray-800 rounded hover:border-cyan-400 hover:text-cyan-400 transition-all cursor-pointer disabled:opacity-50"
          >
            <RefreshCw size={14} className={isRefreshing ? 'animate-spin' : ''} />
            <span>Refresh Now</span>
          </button>
        </div>
      </div>

      {/* 1. Real-Time Telemetry Counters */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Committed Card */}
        <div className="bg-gray-950 border border-gray-800 p-4 rounded-lg relative overflow-hidden group hover:border-emerald-500/50 transition-all">
          <div className="flex justify-between items-start">
            <span className="text-xs font-mono font-bold text-gray-400 uppercase tracking-wider">
              Total Committed
            </span>
            <div className="p-2 bg-emerald-500/10 text-emerald-400 rounded">
              <CheckCircle2 size={18} />
            </div>
          </div>
          <div className="mt-3">
            <span className="text-3xl font-extrabold font-mono text-emerald-400 tracking-tight">
              {committedCount.toLocaleString()}
            </span>
            <p className="text-[11px] text-gray-500 mt-1 font-mono">
              Deterministic OCSF committed events
            </p>
          </div>
          <div className="absolute top-0 right-0 w-24 h-1 bg-emerald-500" />
        </div>

        {/* Pending AI Card */}
        <div className="bg-gray-950 border border-gray-800 p-4 rounded-lg relative overflow-hidden group hover:border-amber-500/50 transition-all">
          <div className="flex justify-between items-start">
            <span className="text-xs font-mono font-bold text-gray-400 uppercase tracking-wider">
              Pending AI Triage
            </span>
            <div className="p-2 bg-amber-500/10 text-amber-400 rounded">
              <Sparkles size={18} />
            </div>
          </div>
          <div className="mt-3">
            <span className="text-3xl font-extrabold font-mono text-amber-400 tracking-tight">
              {pendingAiCount.toLocaleString()}
            </span>
            <p className="text-[11px] text-gray-500 mt-1 font-mono">
              Queued for RAG agentic synthesis
            </p>
          </div>
          <div className="absolute top-0 right-0 w-24 h-1 bg-amber-500" />
        </div>

        {/* Quarantined Card */}
        <div className="bg-gray-950 border border-gray-800 p-4 rounded-lg relative overflow-hidden group hover:border-rose-500/50 transition-all">
          <div className="flex justify-between items-start">
            <span className="text-xs font-mono font-bold text-gray-400 uppercase tracking-wider">
              Quarantined
            </span>
            <div className="p-2 bg-rose-500/10 text-rose-400 rounded">
              <ShieldAlert size={18} />
            </div>
          </div>
          <div className="mt-3">
            <span className="text-3xl font-extrabold font-mono text-rose-400 tracking-tight">
              {quarantinedCount.toLocaleString()}
            </span>
            <p className="text-[11px] text-gray-500 mt-1 font-mono">
              Poison pill / unparseable logs isolated
            </p>
          </div>
          <div className="absolute top-0 right-0 w-24 h-1 bg-rose-500" />
        </div>

        {/* Total Spooled Card */}
        <div className="bg-gray-950 border border-gray-800 p-4 rounded-lg relative overflow-hidden group hover:border-cyan-500/50 transition-all">
          <div className="flex justify-between items-start">
            <span className="text-xs font-mono font-bold text-gray-400 uppercase tracking-wider">
              Total WAL Spooled
            </span>
            <div className="p-2 bg-cyan-500/10 text-cyan-400 rounded">
              <Database size={18} />
            </div>
          </div>
          <div className="mt-3">
            <span className="text-3xl font-extrabold font-mono text-cyan-400 tracking-tight">
              {totalSpooled.toLocaleString()}
            </span>
            <p className="text-[11px] text-gray-500 mt-1 font-mono">
              Disk WAL envelope records total
            </p>
          </div>
          <div className="absolute top-0 right-0 w-24 h-1 bg-cyan-400" />
        </div>
      </div>

      {/* Main Grid: Path Input & Load Spikes Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* 2. Path Input Form (5 Cols) */}
        <div className="lg:col-span-5 bg-gray-950 border border-gray-800 rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-3">
              <FolderInput size={18} className="text-cyan-400" />
              <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider font-mono">
                Log Path Ingestion Pump
              </h2>
            </div>
            <p className="text-xs text-gray-400 mb-4">
              Paste an absolute log file path on your local file system to stream lines directly through the high-throughput parser and spool engine.
            </p>

            <form onSubmit={handleIngestPath} className="space-y-4">
              <div>
                <label className="block text-[11px] font-mono text-gray-400 uppercase mb-1">
                  Absolute File Path
                </label>
                <div className="relative">
                  <input
                    type="text"
                    value={inputPath}
                    onChange={(e) => setInputPath(e.target.value)}
                    placeholder="e.g. C:\Users\ombat\ULPF\chaos_stream.log"
                    className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-2.5 text-xs text-cyan-300 font-mono focus:outline-none focus:border-cyan-400 placeholder-gray-600 pr-10"
                  />
                  <FileText size={16} className="absolute right-3 top-3 text-gray-500 pointer-events-none" />
                </div>
              </div>

              {/* Sample Quick Path Chips */}
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono text-gray-500 uppercase">Quick Path:</span>
                <button
                  type="button"
                  onClick={() => handleQuickPathSelect('chaos_stream.log')}
                  className="px-2 py-1 text-[10px] font-mono text-gray-300 bg-gray-900 border border-gray-800 rounded hover:border-cyan-400 hover:text-cyan-400 transition-colors cursor-pointer"
                >
                  chaos_stream.log
                </button>
                <button
                  type="button"
                  onClick={() => handleQuickPathSelect('sample_logs.txt')}
                  className="px-2 py-1 text-[10px] font-mono text-gray-300 bg-gray-900 border border-gray-800 rounded hover:border-cyan-400 hover:text-cyan-400 transition-colors cursor-pointer"
                >
                  sample_logs.txt
                </button>
              </div>

              <button
                type="submit"
                disabled={ingesting || !inputPath.trim()}
                className="w-full py-2.5 px-4 bg-cyan-500 hover:bg-cyan-400 text-gray-950 font-bold text-xs rounded transition-all flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {ingesting ? (
                  <>
                    <RefreshCw size={15} className="animate-spin" />
                    <span>Pumping Logs from File...</span>
                  </>
                ) : (
                  <>
                    <Play size={15} fill="currentColor" />
                    <span>Stream File Logs via HTTP</span>
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Status Message Display */}
          {ingestStatus && (
            <div
              className={`mt-4 p-3 rounded text-xs font-mono border ${
                ingestStatus.type === 'success'
                  ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                  : 'bg-rose-950/40 border-rose-800 text-rose-300'
              }`}
            >
              {ingestStatus.text}
            </div>
          )}
        </div>

        {/* 3. Dynamic Load Spikes Chart (7 Cols) */}
        <div className="lg:col-span-7 bg-gray-950 border border-gray-800 rounded-lg p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Activity size={18} className="text-cyan-400" />
              <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider font-mono">
                Real-Time Ingestion Throughput & Load Spikes
              </h2>
            </div>
            <div className="flex items-center gap-3 text-[10px] font-mono text-gray-400">
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-cyan-400" /> Throughput (delta/s)
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-amber-400" /> Pending AI Queue
              </span>
            </div>
          </div>

          <div className="h-64 w-full mt-2">
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} />
                  <YAxis stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#090d16',
                      borderColor: '#1e293b',
                      borderRadius: '0.375rem',
                      fontSize: '11px',
                      fontFamily: 'monospace',
                    }}
                    itemStyle={{ color: '#67e8f9' }}
                  />
                  <Line
                    type="monotone"
                    dataKey="throughput"
                    name="Throughput Rate"
                    stroke="#22d3ee"
                    strokeWidth={2}
                    dot={{ r: 2, fill: '#22d3ee' }}
                    activeDot={{ r: 5 }}
                  />
                  <Line
                    type="monotone"
                    dataKey="pendingAi"
                    name="Pending AI Queue"
                    stroke="#fbbf24"
                    strokeWidth={2}
                    dot={{ r: 2, fill: '#fbbf24' }}
                    activeDot={{ r: 5 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-gray-500 font-mono">
                Gathering real-time telemetry data points...
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 4. Dark-Theme Terminal Console */}
      <div
        className={`bg-gray-950 border border-gray-800 rounded-lg overflow-hidden transition-all ${
          isTerminalFullscreen ? 'fixed inset-4 z-50 shadow-2xl flex flex-col' : ''
        }`}
      >
        {/* Terminal Header */}
        <div className="bg-gray-900 border-b border-gray-800 px-4 py-2.5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block" />
              <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
              <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
            </div>
            <div className="flex items-center gap-2 ml-2">
              <Terminal size={14} className="text-cyan-400" />
              <span className="text-xs font-mono font-semibold text-gray-300">
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
              className="p-1 text-gray-400 hover:text-cyan-400 hover:bg-gray-800 rounded transition-colors"
              title={isTerminalExpanded ? 'Collapse Height' : 'Expand Height'}
            >
              {isTerminalExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
            </button>
            <button
              onClick={() => setIsTerminalFullscreen(!isTerminalFullscreen)}
              className="p-1 text-gray-400 hover:text-cyan-400 hover:bg-gray-800 rounded transition-colors"
              title={isTerminalFullscreen ? 'Exit Fullscreen' : 'Fullscreen View Mode'}
            >
              {isTerminalFullscreen ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
            </button>
            <button
              onClick={() => {
                if (showVerboseLogs) setBackendLogs([])
                else setTerminalLogs([])
              }}
              className="p-1 text-gray-400 hover:text-rose-400 hover:bg-gray-800 rounded transition-colors"
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
          className={`p-4 font-mono text-xs overflow-y-auto space-y-1.5 bg-[#080c10] text-gray-300 ${
            isTerminalFullscreen
              ? 'flex-1'
              : isTerminalExpanded
              ? 'h-96'
              : 'h-52'
          }`}
        >
          {showVerboseLogs ? (
            backendLogs.length > 0 ? (
              backendLogs.map((logStr, idx) => (
                <div key={idx} className="flex items-start gap-2 leading-relaxed hover:bg-gray-900/50 px-1 py-0.5 rounded">
                  <span className="text-cyan-400 font-bold shrink-0 text-[10px] select-none">[BACKEND]</span>
                  <span className="text-gray-200 break-all">{logStr}</span>
                </div>
              ))
            ) : (
              <div className="text-gray-500 italic py-2">
                No backend AI processing logs recorded yet. Trigger AI triage to generate logs.
              </div>
            )
          ) : (
            terminalLogs.map((log) => (
              <div key={log.id} className="flex items-start gap-2 leading-relaxed hover:bg-gray-900/50 px-1 py-0.5 rounded">
                <span className="text-gray-600 shrink-0 text-[10px] select-none">[{log.time}]</span>
                {log.type === 'error' && (
                  <span className="px-1.5 py-0.2 bg-rose-950 text-rose-400 border border-rose-800 rounded text-[10px] shrink-0">
                    ERROR
                  </span>
                )}
                {log.type === 'success' && (
                  <span className="px-1.5 py-0.2 bg-emerald-950 text-emerald-400 border border-emerald-800 rounded text-[10px] shrink-0">
                    SUCCESS
                  </span>
                )}
                {log.type === 'info' && (
                  <span className="px-1.5 py-0.2 bg-cyan-950 text-cyan-400 border border-cyan-800 rounded text-[10px] shrink-0">
                    INFO
                  </span>
                )}
                {log.type === 'system' && (
                  <span className="px-1.5 py-0.2 bg-gray-800 text-gray-400 rounded text-[10px] shrink-0">
                    SYSTEM
                  </span>
                )}
                <span className="text-gray-200 break-all">{log.text}</span>
              </div>
            ))
          )}
        </div>
      </div>

      {/* 5. Normalized Event Stream Table */}
      <div className="bg-gray-950 border border-gray-800 rounded-lg overflow-hidden">
        {/* Table Toolbar */}
        <div className="bg-gray-900 border-b border-gray-800 p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Database size={18} className="text-cyan-400" />
            <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider font-mono">
              Normalized Event Stream Table
            </h2>
            <span className="text-xs text-gray-500 font-mono ml-2">
              ({filteredEvents.length} events loaded)
            </span>
          </div>

          <div className="flex items-center gap-3">
            {/* Search Input */}
            <div className="relative">
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search raw log / SHA256 / parser..."
                className="bg-gray-950 border border-gray-800 rounded px-3 py-1.5 pl-8 text-xs font-mono text-gray-300 focus:outline-none focus:border-cyan-400 w-64"
              />
              <Search size={14} className="absolute left-2.5 top-2 text-gray-500" />
            </div>

            {/* Status Filter */}
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-gray-950 border border-gray-800 rounded px-3 py-1.5 text-xs font-mono text-gray-300 focus:outline-none focus:border-cyan-400"
            >
              <option value="ALL">All Statuses</option>
              <option value="COMMITTED">COMMITTED</option>
              <option value="PENDING_AI">PENDING_AI</option>
              <option value="QUARANTINED">QUARANTINED</option>
            </select>
          </div>
        </div>

        {/* Table Content */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-gray-900/60 border-b border-gray-800 text-[10px] font-mono text-gray-400 uppercase tracking-wider">
                <th className="py-3 px-4">Event Signature (SHA256)</th>
                <th className="py-3 px-4">Category / Action</th>
                <th className="py-3 px-4">Router / Parser ID</th>
                <th className="py-3 px-4">State Status</th>
                <th className="py-3 px-4">Raw Log Payload</th>
                <th className="py-3 px-4 text-right">OCSF JSON</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60 text-xs font-mono">
              {filteredEvents.length > 0 ? (
                filteredEvents.map((ev) => {
                  const isExpanded = expandedEventId === ev.event_id
                  return (
                    <tr key={ev.event_id} className="hover:bg-gray-900/40 transition-colors">
                      <td className="py-3 px-4 text-cyan-400 font-mono text-[11px]">
                        {ev.raw_sha256 ? `${ev.raw_sha256.substring(0, 14)}...` : ev.event_id.substring(0, 8)}
                      </td>
                      <td className="py-3 px-4 text-gray-300">
                        {ev.raw_payload.includes('deny') || ev.raw_payload.includes('Failed') ? (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-rose-950 text-rose-300 border border-rose-800">
                            Blocked / Denied
                          </span>
                        ) : ev.raw_payload.includes('allow') || ev.raw_payload.includes('Accepted') ? (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-800">
                            Allowed / Pass
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-gray-800 text-gray-400">
                            General Telemetry
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-amber-300">
                        {ev.parser_id || (
                          <span className="text-gray-500 italic">Unassigned (Pending AI)</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {ev.status === 'COMMITTED' ? (
                          <span className="text-emerald-400 font-bold">COMMITTED</span>
                        ) : ev.status === 'PENDING_AI' ? (
                          <span className="text-amber-400 font-bold">PENDING_AI</span>
                        ) : (
                          <span className="text-rose-400 font-bold">{ev.status}</span>
                        )}
                      </td>
                      <td className="py-3 px-4 max-w-xs truncate text-gray-400" title={ev.raw_payload}>
                        {ev.raw_payload}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => setExpandedEventId(isExpanded ? null : ev.event_id)}
                          className="px-2.5 py-1 text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800 rounded hover:bg-cyan-900 transition-colors"
                        >
                          {isExpanded ? 'Hide OCSF' : 'View OCSF'}
                        </button>
                      </td>
                    </tr>
                  )
                })
              ) : (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-gray-500 font-mono text-xs">
                    No spooled log events found matching the selected filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
