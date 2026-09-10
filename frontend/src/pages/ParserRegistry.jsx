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
            <span className="text-xs font-mono text-gray-400 hidden sm:inline">
              Core: <strong className="text-cyan-400">{coreCount}</strong> | Generated: <strong className="text-amber-400">{generatedCount}</strong>
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

function ParserCard({ parser, onDelete, isDeleting }) {
  const isGenerated =
    parser.origin === 'generated' ||
    parser.parser_type === 'generated' ||
    parser.is_generated === true ||
    parser.deletable === true

  return (
    <article className="parser-card flex flex-col justify-between">
      <div>
        <div className="parser-card-header flex items-center justify-between gap-3">
          <div className="parser-title flex items-center gap-2 min-w-0">
            <FileCode2 size={17} className="shrink-0 text-cyan-400" />
            <strong className="truncate font-mono text-xs text-gray-100" title={parser.parser_id}>
              {parser.parser_id}
            </strong>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {isGenerated ? (
              <span className="origin-badge bg-amber-950/60 border border-amber-800/80 text-amber-300 flex items-center gap-1">
                <Sparkles size={11} />
                generated
              </span>
            ) : (
              <span className="origin-badge bg-cyan-950/60 border border-cyan-800/80 text-cyan-300 flex items-center gap-1">
                <Shield size={11} />
                core (read-only)
              </span>
            )}

            {isGenerated && (
              <button
                type="button"
                onClick={() => onDelete(parser.parser_id)}
                disabled={isDeleting}
                className="px-2 py-1 text-[11px] font-mono text-rose-300 bg-rose-950/80 border border-rose-800 rounded hover:bg-rose-900 transition-colors flex items-center gap-1 cursor-pointer disabled:opacity-50"
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
          <p className="text-xs text-gray-400 leading-relaxed font-sans">
            {parser.description || 'No description provided.'}
          </p>
        </div>

        {/* Regex Pattern Block */}
        <div className="regex-block">
          <div className="code-label">
            <Braces size={13} /> regex pattern
          </div>
          <code>{parser.regex_pattern || '—'}</code>
        </div>
      </div>

      {/* Field Mappings Block */}
      {parser.field_mappings && Object.keys(parser.field_mappings).length > 0 && (
        <div className="mapping-block">
          <p className="code-label">field mappings</p>
          {Object.entries(parser.field_mappings).map(([key, value]) => (
            <div className="mapping-row" key={key}>
              <span>{key}</span>
              <i>→</i>
              <strong>{value}</strong>
            </div>
          ))}
        </div>
      )}
    </article>
  )
}
