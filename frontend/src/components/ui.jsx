import { AlertCircle, Check, Clipboard, LoaderCircle, RefreshCw } from 'lucide-react'
import { useState } from 'react'

export function PageHeader({ eyebrow, title, description, actions }) {
  return <div className="page-header"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1>{description && <p className="page-description">{description}</p>}</div>{actions && <div className="page-actions">{actions}</div>}</div>
}

export function LoadingState({ label = 'Loading telemetry' }) {
  return <div className="loading-state"><LoaderCircle size={18} className="spin" /><span>{label}</span></div>
}

export function ErrorState({ error, onRetry }) {
  return <div className="error-state"><AlertCircle size={18} /><div><strong>Unable to reach the daemon</strong><p>{error?.message || 'Check that the FastAPI service is running.'}</p></div>{onRetry && <button className="button button-ghost" onClick={onRetry}><RefreshCw size={14} /> Retry</button>}</div>
}

export function CopyButton({ value }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1300) } catch { setCopied(false) }
  }
  return <button className="copy-button" onClick={copy} aria-label="Copy value" title="Copy value">{copied ? <Check size={14} /> : <Clipboard size={14} />}</button>
}

export function StatusBadge({ status }) {
  const tone = status === 'COMMITTED' || status === 'Allowed' ? 'success' : status === 'QUARANTINED' || status === 'Blocked' ? 'danger' : 'warning'
  return <span className={`status-badge ${tone}`}><span />{status || 'UNKNOWN'}</span>
}

export function EmptyState({ label }) { return <div className="empty-state"><span className="empty-line" />{label}<span className="empty-line" /></div> }
