import { useEffect, useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { Activity, Boxes, ChevronRight, Database, FileCode2, Menu, Moon, Radio, Server, Sun, X } from 'lucide-react'
import { API_BASE } from '../services/api'

const navItems = [
  { to: '/', label: 'Telemetry', icon: Activity, end: true },
  { to: '/overview', label: 'Pipeline Overview', icon: Server },
  { to: '/ingest', label: 'Live Ingest', icon: Radio },
  { to: '/spool', label: 'Durable Spool', icon: Database },
  { to: '/registry', label: 'Parser Registry', icon: FileCode2 },
  { to: '/events', label: 'OCSF Events', icon: Boxes },
]

function ThemeToggle() {
  const [isDark, setIsDark] = useState(() => {
    if (typeof window !== 'undefined') {
      return document.documentElement.classList.contains('dark')
    }
    return false
  })

  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark')
      document.documentElement.classList.remove('light-mode')
      localStorage.setItem('ulpf-theme', 'dark')
    } else {
      document.documentElement.classList.remove('dark')
      document.documentElement.classList.add('light-mode')
      localStorage.setItem('ulpf-theme', 'light')
    }
  }, [isDark])

  const toggleTheme = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDark((prev) => !prev)
  }

  return (
    <button
      type="button"
      onClick={toggleTheme}
      className={`flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-mono font-medium rounded transition-all cursor-pointer shadow-sm ${
        isDark
          ? 'text-slate-200 hover:text-white bg-slate-800 border border-slate-700'
          : 'text-slate-800 hover:text-slate-950 bg-slate-100 border border-slate-300'
      }`}
      aria-label="Toggle display theme"
    >
      {isDark ? (
        <>
          <Sun size={14} className="text-amber-400" />
          <span>LIGHT</span>
        </>
      ) : (
        <>
          <Moon size={14} className="text-slate-700" />
          <span>DARK</span>
        </>
      )}
    </button>
  )
}

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
    <div className="app-shell min-h-screen bg-slate-50 dark:bg-[#0b101b]">
      <div className={`mobile-drawer ${menuOpen ? 'open' : ''}`}><Sidebar onNavigate={() => setMenuOpen(false)} /></div>
      <Sidebar />
      <main className="main-shell bg-slate-50 dark:bg-[#0b101b]">
        <header className="topbar">
          <button className="icon-btn mobile-menu" onClick={() => setMenuOpen((open) => !open)} aria-label="Toggle navigation">{menuOpen ? <X size={19} /> : <Menu size={19} />}</button>
          <div className="breadcrumb"><span>ULPF</span><ChevronRight size={13} /><strong>{current}</strong></div>
          <div className="topbar-meta">
            <span className="live-indicator"><span className="pulse-dot" /> live telemetry</span>
            <span className="topbar-divider" />
            <span className="mono">v1.0.0</span>
            <span className="topbar-divider" />
            <ThemeToggle />
          </div>
        </header>
        <div className="page-wrap">{children}</div>
      </main>
    </div>
  )
}
