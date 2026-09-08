import { useEffect, useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import ThemeToggle, { useTheme } from './ThemeToggle';

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const location = useLocation();
  const isConsole = location.pathname === '/console';
  const { theme, toggle } = useTheme();

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <nav className={`navbar ${scrolled ? 'scrolled' : ''}`} role="navigation" aria-label="Main navigation">
      <div className="navbar-inner">
        {/* Logo */}
        <NavLink to="/" className="navbar-logo" id="nav-logo">
          <div className="navbar-logo-mark">UL</div>
          <span>ULPS</span>
        </NavLink>

        {/* Nav Links — only show on landing */}
        {!isConsole && (
          <div className="navbar-nav" role="menubar">
            <a href="#overview"  id="nav-overview">Overview</a>
            <a href="#pipeline"  id="nav-pipeline">Pipeline</a>
            <a href="#logs"      id="nav-logs">Logs</a>
            <a href="#output"    id="nav-output">Output</a>
          </div>
        )}

        {/* Right side */}
        <div className="navbar-right">
          <div className="navbar-status" aria-label="System status">
            <span className="dot dot-success" />
            ACTIVE
          </div>

          {/* Theme toggle */}
          <ThemeToggle theme={theme} toggle={toggle} />

          {isConsole ? (
            <NavLink to="/" className="btn btn-ghost btn-sm" id="nav-landing-link">
              ← Overview
            </NavLink>
          ) : (
            <NavLink to="/console" className="btn btn-primary btn-sm" id="nav-console-link">
              Console →
            </NavLink>
          )}
        </div>
      </div>
    </nav>
  );
}
