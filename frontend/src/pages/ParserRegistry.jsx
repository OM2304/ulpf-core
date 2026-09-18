import { useEffect, useState } from 'react'
import { Braces, FileCode2, RefreshCw, Shield, Sparkles, Trash2 } from 'lucide-react'
import { api } from '../services/api'
import { EmptyState, ErrorState, LoadingState, PageHeader } from '../components/ui'

export default function ParserRegistry() {
  const [parsers, setParsers] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)
  const [deletingId, setDeletingId] = useState(null)

  const fetchParsers = async () => {
    setIsLoading(true)
    setError(null)
    try {
      const data = await api.parsers()
      setParsers(Array.isArray(data) ? data : (data.parsers || []))
    } catch (err) {
      setError(err.message || 'Failed to fetch parser registry')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchParsers()
  }, [])

  const handleDelete = async (parserId) => {
    if (!window.confirm(`Are you sure you want to delete generated parser "${parserId}"?`)) {
      return
    }
    setDeletingId(parserId)
    try {
      await api.deleteParser(parserId)
      // Remove from local React state immediately without reload
      setParsers((prev) => prev.filter((p) => p.parser_id !== parserId))
    } catch (err) {
      alert(`Failed to delete parser: ${err.message || err}`)
    } finally {
      setDeletingId(null)
    }
  }

  const coreCount = parsers.filter((p) => p.origin === 'core' || p.parser_type === 'core').length
  const generatedCount = parsers.filter((p) => p.origin === 'generated' || p.parser_type === 'generated' || p.is_generated).length

  return (
    <>
      <PageHeader
        eyebrow="Deterministic data plane"
        title="Parser registry"
        description="Active validated core and AI-synthesized parsers currently available to the normalization engine."
        actions={
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-slate-600 dark:text-slate-200 hidden sm:inline">
              Core: <strong className="text-green-700 dark:text-green-400">{coreCount}</strong> | Generated: <strong className="text-blue-700 dark:text-blue-400">{generatedCount}</strong>
            </span>
            <button
              className="button button-ghost flex items-center gap-2"
              onClick={fetchParsers}
              disabled={isLoading}
            >
              <RefreshCw size={14} className={isLoading ? 'spin' : ''} />
              <span>Refresh</span>
            </button>
          </div>
        }
      />

      {error && <ErrorState error={error} onRetry={fetchParsers} />}

      {isLoading ? (
        <LoadingState />
      ) : parsers.length === 0 ? (
        <div className="panel p-8 text-center">
          <EmptyState label="No active parsers found in registry" />
        </div>
      ) : (
        <div className="parser-grid">
          {parsers.map((parser) => (
            <ParserCard
              key={parser.parser_id}
              parser={parser}
              onDelete={handleDelete}
              isDeleting={deletingId === parser.parser_id}
            />
          ))}
        </div>
      )}
    </>
  )
}

function renderRegexTokens(pattern) {
  if (!pattern) return '—'
  const tokenRegex = /(\(\?P?<[a-zA-Z0-9_]+>)|(\(|\))|(\^|\$|\+|\*|\?|\{\d+,?\d*\}|\|)|(\\[dswDSWbB]|\\[0-9a-zA-Z]|\[[^\]]+\])|([^\s()^$+*?{|]+|\s+)/g
  const parts = []
  let match
  let key = 0

  while ((match = tokenRegex.exec(pattern)) !== null) {
    const [full, namedGroup, paren, quantifier, charClass] = match
    if (namedGroup) {
      const varName = namedGroup.replace(/^\(\?P?</, '').replace(/>$/, '')
      parts.push(
        <span key={key++} className="text-indigo-800 dark:text-indigo-300 font-bold">(?&lt;</span>,
        <span key={key++} className="text-blue-800 dark:text-sky-400 font-semibold">{varName}</span>,
        <span key={key++} className="text-indigo-800 dark:text-indigo-300 font-bold">&gt;</span>
      )
    } else if (paren || quantifier) {
      parts.push(
        <span key={key++} className="text-indigo-800 dark:text-indigo-300 font-bold">{full}</span>
      )
    } else if (charClass) {
      parts.push(
        <span key={key++} className="text-teal-800 dark:text-teal-400 font-medium">{full}</span>
      )
    } else {
      parts.push(
        <span key={key++} className="text-slate-900 dark:text-slate-200">{full}</span>
      )
    }
  }

  return parts.length > 0 ? parts : pattern
}

function ParserCard({ parser, onDelete, isDeleting }) {
  const isGenerated =
    parser.origin === 'generated' ||
    parser.parser_type === 'generated' ||
    parser.is_generated === true ||
    parser.deletable === true

  return (
    <article className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm rounded-lg flex flex-col justify-between overflow-hidden">
      <div>
        <div className="p-4 flex items-center justify-between gap-3 border-b border-slate-200/80 dark:border-slate-800">
          <div className="flex items-center gap-2 min-w-0">
            <FileCode2 size={17} className="shrink-0 text-teal-700 dark:text-cyan-400" />
            <strong className="truncate font-mono text-xs text-slate-800 dark:text-gray-100" title={parser.parser_id}>
              {parser.parser_id}
            </strong>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {isGenerated ? (
              <span className="origin-badge bg-blue-100 text-blue-800 border border-blue-300 dark:bg-blue-900/40 dark:text-blue-400 dark:border-blue-800 flex items-center gap-1 font-semibold">
                <Sparkles size={11} />
                generated
              </span>
            ) : (
              <span className="origin-badge bg-green-100 text-green-800 border border-green-300 dark:bg-green-900/40 dark:text-green-400 dark:border-green-800 flex items-center gap-1 font-semibold">
                <Shield size={11} />
                core (read-only)
              </span>
            )}

            {isGenerated && (
              <button
                type="button"
                onClick={() => onDelete(parser.parser_id)}
                disabled={isDeleting}
                className="px-2 py-1 text-[11px] font-mono text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/80 border border-rose-300 dark:border-rose-800 rounded hover:bg-rose-100 dark:hover:bg-rose-900 transition-colors flex items-center gap-1 cursor-pointer disabled:opacity-50"
                title="Delete generated parser"
              >
                <Trash2 size={12} />
                <span>{isDeleting ? 'Deleting...' : 'Delete'}</span>
              </button>
            )}
          </div>
        </div>

        {/* Description */}
        <div className="px-4 pt-3 pb-1">
          <p className="text-xs text-slate-600 dark:text-slate-200 leading-relaxed font-sans">
            {parser.description || 'No description provided.'}
          </p>
        </div>

        {/* Regex Pattern Block */}
        <div className="mx-4 my-3 p-3 rounded-md border bg-slate-50 border-slate-200 text-slate-800 dark:bg-slate-950/60 dark:border-slate-800 dark:text-slate-200">
          <div className="flex items-center gap-1.5 text-[10px] uppercase font-bold tracking-wider mb-2 text-slate-600 dark:text-slate-200 font-mono">
            <Braces size={13} className="text-teal-700 dark:text-cyan-400" /> regex pattern
          </div>
          <code className="block font-mono text-[11px] leading-relaxed break-all">
            {renderRegexTokens(parser.regex_pattern)}
          </code>
        </div>
      </div>

      {/* Field Mappings Block */}
      {parser.field_mappings && Object.keys(parser.field_mappings).length > 0 && (
        <div className="mx-4 mb-4 p-3 rounded-md border bg-slate-50 border-slate-200 text-slate-800 dark:bg-slate-950/60 dark:border-slate-800 dark:text-slate-200">
          <p className="text-[10px] uppercase font-bold tracking-wider mb-2 text-slate-600 dark:text-slate-200 font-mono">
            field mappings
          </p>
          <div className="space-y-1 font-mono text-[11px]">
            {Object.entries(parser.field_mappings).map(([key, value]) => (
              <div className="flex items-center justify-between gap-2 py-0.5 text-slate-700 dark:text-slate-200" key={key}>
                <span className="text-blue-800 dark:text-sky-400 font-semibold">{key}</span>
                <i className="text-slate-500 dark:text-slate-300 not-italic">→</i>
                <strong className="text-teal-800 dark:text-teal-400 font-semibold">{value}</strong>
              </div>
            ))}
          </div>
        </div>
      )}
    </article>
  )
}
