import { useEffect, useState } from 'react'
import {
  ArrowUpRight,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Circle,
  Copy,
  FileInput,
  Loader2,
  Sparkles,
  TerminalSquare,
  TriangleAlert,
} from 'lucide-react'
import { api } from '../services/api'
import { ErrorState, PageHeader, StatusBadge } from '../components/ui'

const TRIAGE_STEPS = [
  { label: 'Durable Spool commit & cryptographic SHA-256 hashing', at: '00:00' },
  { label: 'Structural clustering & template masking', at: '00:01' },
  { label: 'Synthesizing regex via local LLM (qwen2.5-coder:3b)', at: '00:02.5' },
  { label: 'Validating Semantic IP gates & OCSF Class 4001 schema', at: '00:04.5' },
  { label: 'Dynamic parser promoted to registry & storage commit', at: '00:06' },
]

const STEP_DELAYS = [0, 1000, 2500, 4500, 6000]

function eventField(event, directKey, nestedPath, fallback = '—') {
  if (event?.[directKey] !== undefined && event[directKey] !== null && event[directKey] !== '') return event[directKey]
  const nestedValue = nestedPath?.reduce((value, key) => value?.[key], event)
  return nestedValue || fallback
}

function AgentTriageSteps({ activeStep, completed = false, showTimes = false }) {
  return (
    <div className="space-y-1.5">
      {TRIAGE_STEPS.map((step, index) => {
        const isComplete = completed || index < activeStep
        const isActive = !completed && index === activeStep
        return (
          <div
            key={step.label}
            className={`flex items-start gap-2.5 transition-colors duration-200 ${
              isComplete ? 'text-slate-400' : isActive ? 'font-medium text-cyan-400' : 'text-slate-600'
            }`}
          >
            <span className="mt-0.5 shrink-0">
              {isComplete ? (
                <CheckCircle2 size={14} className="text-emerald-400" />
              ) : isActive ? (
                <Loader2 size={14} className="animate-spin text-cyan-400" />
              ) : (
                <Circle size={14} className="text-slate-700" />
              )}
            </span>
            <span className="min-w-0 flex-1">{step.label}</span>
            {showTimes && <span className="shrink-0 text-[10px] text-slate-500 font-mono">{step.at}</span>}
          </div>
        )
      })}
    </div>
  )
}

function AgentTriageConsole({ activeStep }) {
  return (
    <div className="rounded-xl border border-cyan-500/30 bg-slate-950/80 p-5 font-mono text-xs backdrop-blur-xl shadow-[0_0_30px_-5px_rgba(6,182,212,0.15)] animate-float-in">
      <div className="mb-4 flex items-center gap-2.5 border-b border-slate-800/80 pb-3 text-cyan-400">
        <span className="relative flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyan-400 opacity-75" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-cyan-400" />
        </span>
        <span className="font-semibold tracking-wide">AI Parser Agent Running...</span>
      </div>
      <AgentTriageSteps activeStep={activeStep} />
    </div>
  )
}

function ExecutionTrace({ isOpen, onToggle }) {
  return (
    <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 backdrop-blur-md shadow-lg shadow-black/40 transition-all duration-300 ease-out hover:border-slate-700 animate-float-in">
      <button
        className="flex w-full cursor-pointer items-center justify-between gap-3 px-4 py-3 text-left transition"
        onClick={onToggle}
        aria-expanded={isOpen}
      >
        <span className="flex min-w-0 items-center gap-2.5">
          <Sparkles size={15} className="shrink-0 text-cyan-400 animate-pulse" />
          <span className="truncate text-xs font-medium text-slate-300">Pipeline execution trace</span>
          <span className="shrink-0 rounded border border-emerald-400/30 bg-emerald-400/10 px-2 py-0.5 font-mono text-[9px] text-emerald-300">
            5/5 Stages Succeeded
          </span>
        </span>
        {isOpen ? (
          <ChevronDown size={15} className="shrink-0 text-slate-400 transition-transform duration-200" />
        ) : (
          <ChevronRight size={15} className="shrink-0 text-slate-400 transition-transform duration-200" />
        )}
      </button>
      {isOpen && (
        <div className="border-t border-slate-800/80 bg-slate-950/40 px-4 py-3 font-mono text-[10px] leading-6 animate-float-in">
          <AgentTriageSteps activeStep={5} completed showTimes />
        </div>
      )}
    </div>
  )
}

function NormalizedEventCard({ event, spoolEvent, fastPath }) {
  const [rawOpen, setRawOpen] = useState(false)
  const [copied, setCopied] = useState(false)

  const eventId = eventField(event, 'event_id') || eventField(spoolEvent, 'event_id')
  const hash = eventField(event, 'raw_sha256', null, '') || eventField(spoolEvent, 'raw_sha256', null, '')
  const parserId = eventField(event, 'parser_id', null, 'unknown')
  const disposition = eventField(event, 'disposition', null, 'Unknown')
  const sourceIp = eventField(event, 'src_ip', ['src_endpoint', 'ip'])
  const destinationIp = eventField(event, 'dst_ip', ['dst_endpoint', 'ip'])
  const protocol = eventField(event, 'protocol', ['connection_info', 'protocol_name'])
  const action = eventField(event, 'action')

  const copyHash = async () => {
    if (!hash) return
    try {
      await navigator.clipboard.writeText(hash)
      setCopied(true)
      setTimeout(() => setCopied(false), 1300)
    } catch {
      setCopied(false)
    }
  }

  return (
    <div className="mt-3 space-y-4 rounded-xl border border-emerald-500/30 bg-slate-900/75 p-5 backdrop-blur-xl shadow-[0_10px_35px_-10px_rgba(16,185,129,0.2)] transition-all duration-500 ease-out animate-float-in hover:shadow-[0_15px_40px_-8px_rgba(6,182,212,0.25)] hover:-translate-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded-full border border-cyan-400/30 bg-cyan-400/10 px-2.5 py-1 font-mono text-[10px] text-cyan-300">
          OCSF Class 4001: Network Activity
        </span>
        {fastPath && (
          <span className="rounded border border-emerald-400/30 bg-emerald-400/10 px-2 py-1 font-mono text-[10px] text-emerald-300">
            Engine: Deterministic Fast-Path
          </span>
        )}
        <span className="rounded border border-slate-700 bg-slate-950/60 px-2 py-1 font-mono text-[10px] text-slate-300">
          {parserId}
        </span>
        <StatusBadge status={disposition} />
      </div>

      <div className="grid grid-cols-2 gap-3 rounded-lg border border-slate-800/90 bg-slate-950/70 p-4 sm:grid-cols-4">
        <EventDatum label="Source endpoint" value={sourceIp} />
        <EventDatum label="Destination endpoint" value={destinationIp} />
        <EventDatum label="Protocol" value={protocol} />
        <EventDatum label="Action" value={action} />
      </div>

      <div className="space-y-3 border-t border-slate-800/80 pt-4 text-[10px]">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-slate-400">
            Event ID <strong className="ml-2 font-mono font-medium text-slate-200">{eventId}</strong>
          </span>
          <span className="flex items-center gap-1.5 text-slate-400">
            SHA-256 <span className="font-mono text-slate-300">{hash ? `${hash.slice(0, 16)}...` : '—'}</span>
            {hash && (
              <button
                className="ml-1 text-slate-400 transition hover:text-cyan-300"
                onClick={copyHash}
                aria-label="Copy SHA-256 hash"
              >
                {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
              </button>
            )}
          </span>
        </div>

        <button
          className="font-medium text-cyan-400 transition hover:text-cyan-200 underline decoration-cyan-400/40 underline-offset-4"
          onClick={() => setRawOpen((open) => !open)}
        >
          {rawOpen ? 'Hide Raw OCSF Payload' : 'View Raw OCSF Payload'}
        </button>

        {rawOpen && (
          <pre className="max-h-64 overflow-auto rounded-lg border border-slate-800/80 bg-slate-950/90 p-3.5 font-mono text-[10px] leading-5 text-slate-300 shadow-inner animate-float-in">
            {JSON.stringify(event, null, 2)}
          </pre>
        )}
      </div>
    </div>
  )
}

function EventDatum({ label, value }) {
  return (
    <div className="min-w-0">
      <p className="mb-1 text-[9px] uppercase tracking-[.12em] text-slate-500">{label}</p>
      <strong className="block truncate font-mono text-[11px] text-white">{value}</strong>
    </div>
  )
}

export default function LiveSimulator() {
  const [payload, setPayload] = useState('')
  const [result, setResult] = useState(null)
  const [status, setStatus] = useState('idle')
  const [activeStep, setActiveStep] = useState(0)
  const [isTraceOpen, setIsTraceOpen] = useState(false)
  const [normalizedEvent, setNormalizedEvent] = useState(null)
  const [rawSpoolEvent, setRawSpoolEvent] = useState(null)
  const [fastPath, setFastPath] = useState(false)
  const [error, setError] = useState(null)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (status !== 'processing' || !result?.event_ids?.[0]) return undefined
    let cancelled = false
    const timers = STEP_DELAYS.slice(1).map((delay, index) =>
      setTimeout(() => setActiveStep(index + 1), delay)
    )

    const completionTimer = setTimeout(async () => {
      try {
        const [events, spoolEvents] = await Promise.all([
          api.events({ limit: 500 }),
          api.getSpoolEvents(500),
        ])
        if (cancelled) return
        const eventId = result.event_ids[0]
        setNormalizedEvent(events.find((event) => event.event_id === eventId) || events[0] || null)
        setRawSpoolEvent(spoolEvents.find((event) => event.event_id === eventId) || spoolEvents[0] || null)
        setActiveStep(4)
        setIsTraceOpen(false)
        setStatus('completed')
      } catch (fetchError) {
        if (!cancelled) {
          setError(fetchError)
          setStatus('error')
        }
      }
    }, 6500)

    return () => {
      cancelled = true
      timers.forEach(clearTimeout)
      clearTimeout(completionTimer)
    }
  }, [status, result])

  const loadImmediateResult = async (eventId) => {
    const [events, spoolEvents] = await Promise.all([
      api.events({ limit: 500 }),
      api.getSpoolEvents(500),
    ])
    setNormalizedEvent(events.find((event) => event.event_id === eventId) || events[0] || null)
    setRawSpoolEvent(spoolEvents.find((event) => event.event_id === eventId) || spoolEvents[0] || null)
    setIsTraceOpen(false)
    setStatus('completed')
  }

  const submit = async (event) => {
    event.preventDefault()
    if (!payload.trim()) return
    setSubmitting(true)
    setError(null)
    setResult(null)
    setNormalizedEvent(null)
    setRawSpoolEvent(null)
    setActiveStep(0)
    setIsTraceOpen(true)
    setFastPath(false)
    setStatus('idle')

    try {
      const response = await api.ingest([payload])
      setResult(response)
      const eventId = response.event_ids?.[0]
      if (response.queued_for_ai > 0) {
        setActiveStep(0)
        setIsTraceOpen(true)
        setStatus('processing')
      } else if (response.fast_path_committed > 0) {
        setFastPath(true)
        await loadImmediateResult(eventId)
      }
    } catch (submitError) {
      setError(submitError)
      setStatus('error')
    } finally {
      setSubmitting(false)
    }
  }

  const showResults = status !== 'idle' && result

  return (
    <>
      <style>{`
        @keyframes floatIn {
          0% {
            opacity: 0;
            transform: translateY(14px) scale(0.98);
          }
          100% {
            opacity: 1;
            transform: translateY(0) scale(1);
          }
        }
        .animate-float-in {
          animation: floatIn 0.45s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
      `}</style>

      <PageHeader
        eyebrow="Ingestion layer"
        title="Live simulator"
        description="Send raw firewall and system logs through the production ingestion path."
      />
      {error && <ErrorState error={error} />}

      <div className="ingest-grid">
        <form className="panel ingest-form" onSubmit={submit}>
          <div className="panel-heading">
            <div>
              <p className="eyebrow">HTTP API / http_api</p>
              <h2>Submit payload</h2>
            </div>
            <FileInput size={20} className="heading-icon" />
          </div>

          <label className="field-label" htmlFor="raw-log">
            Raw log line
          </label>
          <textarea
            id="raw-log"
            value={payload}
            onChange={(event) => setPayload(event.target.value)}
            placeholder="src=10.0.0.1 dst=8.8.8.8 spt=1234 dpt=53 proto=UDP action=ALLOW"
            spellCheck="false"
          />

          <div className="form-footer">
            <span className="character-count">{payload.length} characters</span>
            <button
              className="button button-primary"
              type="submit"
              disabled={submitting || !payload.trim()}
            >
              {submitting ? 'Submitting...' : 'Submit payload'}
              <ArrowUpRight size={16} />
            </button>
          </div>
        </form>

        <div className="panel processing-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Response channel</p>
              <h2>Processing results</h2>
            </div>
            <TerminalSquare size={20} className="heading-icon" />
          </div>

          {!showResults ? (
            <div className="awaiting">
              <span className="awaiting-icon">
                <TriangleAlert size={18} />
              </span>
              <p>
                {status === 'error'
                  ? 'The ingestion request could not be completed.'
                  : 'Results will appear here after the payload is accepted.'}
              </p>
            </div>
          ) : (
            <div className="result-stack">
              {status === 'processing' && <AgentTriageConsole activeStep={activeStep} />}
              {status === 'completed' && !fastPath && (
                <ExecutionTrace
                  isOpen={isTraceOpen}
                  onToggle={() => setIsTraceOpen((open) => !open)}
                />
              )}
              {status === 'completed' && (
                <NormalizedEventCard
                  event={normalizedEvent}
                  spoolEvent={rawSpoolEvent}
                  fastPath={fastPath}
                />
              )}
              {status === 'processing' && (
                <div className="ingest-summary animate-float-in">
                  <span>
                    Ingested <strong>{result.ingested}</strong>
                  </span>
                  <span className="mono">{result.event_ids?.[0] || '—'}</span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </>
  )
}