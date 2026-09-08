import { useEffect, useState } from 'react'
import { Braces, FileCode2, RefreshCw } from 'lucide-react'
import { api } from '../services/api'
import { EmptyState, ErrorState, LoadingState, PageHeader } from '../components/ui'

export default function ParserRegistry() {
  const [parsers, setParsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const load = () => { setLoading(true); setError(null); api.parsers().then(setParsers).catch(setError).finally(() => setLoading(false)) }
  useEffect(load, [])
  return <><PageHeader eyebrow="Deterministic data plane" title="Parser registry" description="Active validated parsers currently available to the normalization engine." actions={<button className="button button-ghost" onClick={load} disabled={loading}><RefreshCw size={15} className={loading ? 'spin' : ''} /> Refresh</button>} />{error && <ErrorState error={error} onRetry={load} />}{loading ? <LoadingState /> : parsers.length === 0 ? <div className="panel"><EmptyState label="No active parsers found" /></div> : <div className="parser-grid">{parsers.map((parser) => <ParserCard key={parser.parser_id} parser={parser} />)}</div>}</>
}

function ParserCard({ parser }) {
  return <article className="parser-card"><div className="parser-card-header"><div className="parser-title"><FileCode2 size={17} /><strong>{parser.parser_id}</strong></div><span className="origin-badge">{parser.origin || 'unknown'}</span></div><div className="regex-block"><div className="code-label"><Braces size={13} /> regex pattern</div><code>{parser.regex_pattern || '—'}</code></div><div className="mapping-block"><p className="code-label">field mappings</p>{Object.entries(parser.field_mappings || {}).map(([key, value]) => <div className="mapping-row" key={key}><span>{key}</span><i>→</i><strong>{value}</strong></div>)}</div></article>
}
