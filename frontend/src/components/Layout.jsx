import { useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { Activity, Boxes, ChevronRight, Database, FileCode2, Menu, Radio, Server, X } from 'lucide-react'
import { API_BASE } from '../services/api'

const navItems = [
  { to: '/', label: 'Overview', icon: Activity, end: true },
  { to: '/ingest', label: 'Live Ingest', icon: Radio },
  { to: '/spool', label: 'Durable Spool', icon: Database },
  { to: '/registry', label: 'Parser Registry', icon: FileCode2 },
  { to: '/events', label: 'OCSF Events', icon: Boxes },
]

function Sidebar({ onNavigate }) {
  return (
    <aside className="sidebar">
      <div className="brand-block">
        <div className="brand-mark"><span>U</span></div>
        <div>
          <p className="brand-name">ULPF</p>
          <p className="brand-subtitle">command center</p>
        </div>
      </div>
      <div className="system-chip"><span className="pulse-dot" /> Pipeline online</div>
      <nav className="nav-list" aria-label="Primary navigation">
        <p className="nav-label">Workspace</p>
        {navItems.map(({ to, label, icon: Icon, end }) => (
          <NavLink key={to} to={to} end={end} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`} onClick={onNavigate}>
            <Icon size={17} strokeWidth={1.7} />
            <span>{label}</span>
            <ChevronRight size={14} className="nav-arrow" />
          </NavLink>
        ))}
      </nav>
      <div className="sidebar-footer">
        <div className="daemon-status"><Server size={15} /><span><strong>Daemon</strong><small>FastAPI / localhost:8000</small></span><span className="status-led" /></div>
        <p className="api-endpoint">{API_BASE}</p>
      </div>
    </aside>
  )
}

export default function Layout({ children }) {
  const [menuOpen, setMenuOpen] = useState(false)
  const location = useLocation()
  const current = navItems.find((item) => item.to === location.pathname)?.label || 'Command Center'
  return (
    <div className="app-shell">
      <div className={`mobile-drawer ${menuOpen ? 'open' : ''}`}><Sidebar onNavigate={() => setMenuOpen(false)} /></div>
      <Sidebar />
      <main className="main-shell">
        <header className="topbar">
          <button className="icon-btn mobile-menu" onClick={() => setMenuOpen((open) => !open)} aria-label="Toggle navigation">{menuOpen ? <X size={19} /> : <Menu size={19} />}</button>
          <div className="breadcrumb"><span>ULPF</span><ChevronRight size={13} /><strong>{current}</strong></div>
          <div className="topbar-meta"><span className="live-indicator"><span className="pulse-dot" /> live telemetry</span><span className="topbar-divider" /><span className="mono">v1.0.0</span></div>
        </header>
        <div className="page-wrap">{children}</div>
      </main>
    </div>
  )
}
