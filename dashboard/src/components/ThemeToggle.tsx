import { useState, useEffect } from 'react';

export type Theme = 'dark' | 'light';

const STORAGE_KEY = 'ulps-theme';

function getInitial(): Theme {
  const stored = localStorage.getItem(STORAGE_KEY) as Theme | null;
  if (stored === 'light' || stored === 'dark') return stored;
  return 'dark';
}

function applyTheme(t: Theme) {
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem(STORAGE_KEY, t);
}

export function useTheme() {
  const [theme, setTheme] = useState<Theme>(getInitial);

  useEffect(() => { applyTheme(theme); }, [theme]);

  const toggle = () => setTheme(t => t === 'dark' ? 'light' : 'dark');
  return { theme, toggle };
}

interface Props {
  theme: Theme;
  toggle: () => void;
}

export default function ThemeToggle({ theme, toggle }: Props) {
  return (
    <button
      id="theme-toggle"
      onClick={toggle}
      className="btn btn-ghost btn-sm"
      aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
      title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
      style={{ padding: '6px 10px', fontSize: 14, lineHeight: 1 }}
    >
      {theme === 'dark' ? '☀' : '☾'}
    </button>
  );
}
