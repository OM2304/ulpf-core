import type { ParsersResponse, ParserDef } from '../api/ulpf';
import { useState } from 'react';

interface Props {
  parsers: ParsersResponse | null;
  loading: boolean;
}

function ParserRow({ parser, index }: { parser: ParserDef; index: number }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <>
      <tr className={expanded ? 'expanded' : ''}>
        <td>
          <span
            className={`badge ${parser.type === 'dynamic_ai' ? 'purple' : 'cyan'}`}
            style={{ fontSize: 9 }}
          >
            {parser.type === 'dynamic_ai' ? '🤖 AI' : '⚙ Builtin'}
          </span>
        </td>
        <td>
          <span className="mono">{parser.parser_id}</span>
        </td>
        <td style={{ color: 'var(--text-secondary)' }}>
          {parser.description}
        </td>
        <td>
          <div className="parser-regex" title={parser.regex_pattern}>
            {parser.regex_pattern.length > 60
              ? parser.regex_pattern.slice(0, 60) + '…'
              : parser.regex_pattern}
          </div>
        </td>
        <td>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {Object.entries(parser.field_mappings).map(([k, v]) => (
              <span key={k} className="badge gray" style={{ fontSize: 9 }}>
                {k}→{v}
              </span>
            ))}
          </div>
        </td>
        <td>
          <button
            className="expand-btn"
            onClick={() => setExpanded(!expanded)}
            id={`parser-expand-${index}`}
          >
            {expanded ? '▲ Hide' : '▼ Details'}
          </button>
        </td>
      </tr>
      {expanded && (
        <tr className="expanded fade-in">
          <td colSpan={6}>
            <div style={{ padding: '8px 4px' }}>
              <div className="section-title" style={{ marginBottom: 8 }}>Full Regex Pattern</div>
              <pre className="json-block">{parser.regex_pattern}</pre>
              <div className="section-title" style={{ marginTop: 12, marginBottom: 8 }}>Field Mappings</div>
              <pre className="json-block">{JSON.stringify(parser.field_mappings, null, 2)}</pre>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function ParsersPanel({ parsers, loading }: Props) {
  const [activeTab, setActiveTab] = useState<'all' | 'builtin' | 'dynamic_ai'>('all');

  if (loading && !parsers) {
    return (
      <div className="card fade-in">
        <div className="card-header">
          <span className="icon">🔌</span>
          <h2>Active Parsers</h2>
        </div>
        <div className="card-body">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="loading-shimmer" style={{ marginBottom: 10 }} />
          ))}
        </div>
      </div>
    );
  }

  if (!parsers) return null;

  const all = [...parsers.builtin, ...parsers.dynamic_ai];
  const displayed =
    activeTab === 'builtin'
      ? parsers.builtin
      : activeTab === 'dynamic_ai'
        ? parsers.dynamic_ai
        : all;

  return (
    <div className="card fade-in">
      <div className="card-header">
        <span className="icon">🔌</span>
        <h2>Active Parsers Registry</h2>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          <span className="badge cyan">{parsers.total} total</span>
          <span className="badge purple">{parsers.dynamic_ai.length} AI</span>
          <span className="badge gray">{parsers.builtin.length} builtin</span>
        </div>
      </div>
      <div className="card-body">
        <div className="tab-nav">
          {(['all', 'builtin', 'dynamic_ai'] as const).map((tab) => (
            <button
              key={tab}
              id={`tab-parser-${tab}`}
              className={`tab-btn ${activeTab === tab ? 'active' : ''}`}
              onClick={() => setActiveTab(tab)}
            >
              {tab === 'all' ? 'All Parsers' : tab === 'builtin' ? '⚙ Built-in' : '🤖 AI-Synthesized'}
            </button>
          ))}
        </div>

        {displayed.length === 0 ? (
          <div className="empty-state">
            <div className="icon">🔍</div>
            {activeTab === 'dynamic_ai'
              ? 'No AI-synthesized parsers yet. Ingest unrecognized logs to trigger synthesis.'
              : 'No parsers found.'}
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Parser ID</th>
                  <th>Description</th>
                  <th>Regex Pattern</th>
                  <th>Field Mappings</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {displayed.map((p, i) => (
                  <ParserRow key={p.parser_id} parser={p} index={i} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
