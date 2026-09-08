import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid
} from 'recharts';

interface SpoolPoint {
  time: string;
  total: number;
  committed: number;
  pending_ai: number;
}

interface Props {
  history: SpoolPoint[];
}

const CustomTooltip = ({ active, payload, label }: {
  active?: boolean;
  payload?: Array<{ color: string; name: string; value: number }>;
  label?: string;
}) => {
  if (active && payload && payload.length) {
    return (
      <div style={{
        background: 'rgba(8,13,20,0.95)',
        border: '1px solid rgba(0,200,255,0.2)',
        borderRadius: 8,
        padding: '10px 14px',
        fontSize: 11,
        fontFamily: 'JetBrains Mono, monospace',
      }}>
        <div style={{ color: '#8fa3c0', marginBottom: 6 }}>{label}</div>
        {payload.map((p) => (
          <div key={p.name} style={{ color: p.color, marginBottom: 3 }}>
            {p.name}: <strong>{p.value}</strong>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

export default function SpoolChart({ history }: Props) {
  if (history.length === 0) {
    return (
      <div className="card fade-in">
        <div className="card-header">
          <span className="icon">📈</span>
          <h2>Spool Trend</h2>
        </div>
        <div className="card-body">
          <div className="empty-state">
            <div className="icon">〰</div>
            Collecting data points…
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="card fade-in">
      <div className="card-header">
        <span className="icon">📈</span>
        <h2>Spool Activity Trend</h2>
        <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
          Live · 3s poll
        </span>
      </div>
      <div className="card-body">
        <div className="chart-container">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={history} margin={{ top: 4, right: 10, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="gradTotal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00c8ff" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#00c8ff" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradCommitted" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10d48a" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#10d48a" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradPending" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
              <XAxis
                dataKey="time"
                tick={{ fontSize: 9, fill: '#4d6280', fontFamily: 'monospace' }}
                tickLine={false}
                axisLine={{ stroke: 'rgba(255,255,255,0.06)' }}
              />
              <YAxis
                tick={{ fontSize: 9, fill: '#4d6280', fontFamily: 'monospace' }}
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
              />
              <Tooltip content={<CustomTooltip />} />
              <Area
                type="monotone"
                dataKey="total"
                name="Total Spooled"
                stroke="#00c8ff"
                strokeWidth={1.5}
                fill="url(#gradTotal)"
                dot={false}
              />
              <Area
                type="monotone"
                dataKey="committed"
                name="Committed"
                stroke="#10d48a"
                strokeWidth={1.5}
                fill="url(#gradCommitted)"
                dot={false}
              />
              <Area
                type="monotone"
                dataKey="pending_ai"
                name="Pending AI"
                stroke="#f59e0b"
                strokeWidth={1.5}
                fill="url(#gradPending)"
                dot={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div style={{ display: 'flex', gap: 16, marginTop: 10, justifyContent: 'center' }}>
          {[
            { color: '#00c8ff', label: 'Total Spooled' },
            { color: '#10d48a', label: 'Committed' },
            { color: '#f59e0b', label: 'Pending AI' },
          ].map(({ color, label }) => (
            <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, color: 'var(--text-muted)' }}>
              <div style={{ width: 10, height: 3, background: color, borderRadius: 2 }} />
              {label}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
