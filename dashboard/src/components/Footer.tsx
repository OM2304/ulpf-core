export default function Footer() {
  return (
    <footer className="footer">
      <div className="container">
        <div className="footer-inner">
          <div className="footer-brand">
            <div style={{
              width: 24, height: 24, background: 'var(--accent)',
              borderRadius: 4, display: 'flex', alignItems: 'center',
              justifyContent: 'center', fontSize: 9, fontWeight: 700, color: '#000',
            }}>UL</div>
            <span>ULPS — Universal Log Pre-Processing System</span>
          </div>
          <div style={{ display: 'flex', gap: 20, alignItems: 'center' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-3)' }}>
              OCSF Class 4001 · WAL-SQLite · FastAPI · AgentWorker
            </span>
            <span className="badge badge-success" style={{ fontSize: 9 }}>
              v0.2.0
            </span>
          </div>
        </div>
      </div>
    </footer>
  );
}
