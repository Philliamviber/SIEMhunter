import { NavLink } from 'react-router-dom';
import clsx from 'clsx';
import type { ReactNode } from 'react';
import { useState, useEffect, useCallback } from 'react';
import { IncidentSelector } from './IncidentSelector';
import { GlobalSearchBar } from './GlobalSearchBar';
import { ClaudeChatbar } from './ClaudeChatbar';
import { logout } from '../api/client';

async function handleLogout() {
  try {
    await logout();
  } finally {
    window.location.reload();
  }
}

interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
}

const NAV_ITEMS: NavItem[] = [
  {
    to: '/',
    label: 'Overview',
    icon: (
      <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
      </svg>
    ),
  },
  {
    to: '/events',
    label: 'Events',
    icon: (
      <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
      </svg>
    ),
  },
  {
    to: '/detections',
    label: 'Detections',
    icon: (
      <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    ),
  },
  {
    to: '/rules',
    label: 'Rules',
    icon: (
      <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    ),
  },
  {
    to: '/ingestion',
    label: 'Ingestion',
    icon: (
      <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
      </svg>
    ),
  },
  {
    to: '/health',
    label: 'Health',
    icon: (
      <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
      </svg>
    ),
  },
  {
    to: '/query',
    label: 'Query Console',
    icon: (
      <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
      </svg>
    ),
  },
  {
    to: '/categories',
    label: 'Categories',
    icon: (
      <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
      </svg>
    ),
  },
  {
    to: '/incidents',
    label: 'Incidents',
    icon: (
      <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
      </svg>
    ),
  },
  {
    to: '/correlation',
    label: 'Correlation',
    icon: (
      <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
      </svg>
    ),
  },
];

const STORAGE_KEY = 'sidebar-collapsed';

// Chevron icons for toggle button
function ChevronLeft() {
  return (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
    </svg>
  );
}

function ChevronRight() {
  return (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
    </svg>
  );
}

interface PageLayoutProps {
  children: ReactNode;
}

export function PageLayout({ children }: PageLayoutProps) {
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem(STORAGE_KEY) === 'true';
    } catch {
      return false;
    }
  });

  const toggle = useCallback(() => {
    setCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(STORAGE_KEY, String(next));
      } catch {
        // ignore storage errors (e.g. private browsing quota)
      }
      return next;
    });
  }, []);

  // Auto-collapse when viewport is ≤768px; restore when widened.
  // Does not override an explicit user choice — it only fires when the
  // viewport crosses the breakpoint, not continuously.
  useEffect(() => {
    const mq = window.matchMedia('(max-width: 768px)');
    const applyBreakpoint = (narrow: boolean) => {
      if (narrow) {
        setCollapsed(true);
        // Don't persist auto-collapse to localStorage so the desktop pref is
        // not clobbered when the user resizes back.
      } else {
        // Restore from localStorage when widening past breakpoint
        try {
          setCollapsed(localStorage.getItem(STORAGE_KEY) === 'true');
        } catch {
          setCollapsed(false);
        }
      }
    };

    applyBreakpoint(mq.matches);
    const handler = (e: MediaQueryListEvent) => applyBreakpoint(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, []);

  return (
    <div className="flex min-h-screen bg-gray-950 w-full overflow-hidden">
      {/* Sidebar */}
      <aside
        data-testid="sidebar"
        data-collapsed={collapsed}
        className={clsx(
          'flex-shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col transition-[width] duration-200 overflow-hidden',
          collapsed ? 'w-14' : 'w-56',
        )}
      >
        {/* Logo / brand + collapse toggle */}
        <div
          className={clsx(
            'border-b border-gray-800 flex items-center min-h-[65px]',
            collapsed ? 'flex-col justify-center gap-2 py-3 px-1' : 'px-4 py-5 justify-between',
          )}
        >
          {!collapsed && (
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-red-500 flex-shrink-0">
                  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </span>
                <span className="text-white font-bold text-base tracking-tight truncate">SIEMhunter</span>
              </div>
              <p className="text-gray-600 text-xs mt-0.5">Security Console</p>
            </div>
          )}
          {collapsed && (
            <span className="text-red-500">
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </span>
          )}
          <button
            type="button"
            onClick={toggle}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className="p-1 rounded text-gray-500 hover:text-gray-200 hover:bg-gray-800/60 transition-colors flex-shrink-0"
          >
            {collapsed ? <ChevronRight /> : <ChevronLeft />}
          </button>
        </div>

        {/* Nav items */}
        <nav className="flex-1 py-3 px-2 overflow-y-auto">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              title={collapsed ? item.label : undefined}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-2.5 px-3 py-2 rounded-md text-sm font-medium mb-0.5 transition-colors',
                  collapsed && 'justify-center px-2',
                  isActive
                    ? 'bg-gray-800 text-white'
                    : 'text-gray-400 hover:bg-gray-800/50 hover:text-gray-200',
                )
              }
            >
              {item.icon}
              {!collapsed && <span className="truncate">{item.label}</span>}
            </NavLink>
          ))}
        </nav>

        {/* Incident scope selector — hidden when collapsed to save space */}
        {!collapsed && (
          <div className="px-3 py-2.5 border-t border-gray-800">
            <p className="text-xs text-gray-600 mb-1.5 px-1">Incident Scope</p>
            <IncidentSelector />
          </div>
        )}

        {/* Logout control */}
        <div className={clsx('py-2.5 border-t border-gray-800', collapsed ? 'px-2' : 'px-3')}>
          <button
            type="button"
            onClick={handleLogout}
            title={collapsed ? 'Log out' : undefined}
            className={clsx(
              'w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-sm font-medium text-gray-400 hover:bg-gray-800/50 hover:text-gray-200 transition-colors',
              collapsed && 'justify-center px-2',
            )}
          >
            <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
            </svg>
            {!collapsed && 'Log out'}
          </button>
        </div>

        {/* Footer — hidden when collapsed */}
        {!collapsed && (
          <div className="px-4 py-3 border-t border-gray-800 text-xs text-gray-600">
            v3.0.0 · localhost:8080
          </div>
        )}
      </aside>

      {/* Main content */}
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Global search bar — sticky at the top */}
        <div className="flex-shrink-0 sticky top-0 z-40">
          <GlobalSearchBar />
        </div>
        {/* Page content */}
        <div className="flex-1 overflow-y-auto">
          {children}
        </div>
      </main>

      {/* Global AI chatbar — single instance, persists across navigation */}
      <ClaudeChatbar />
    </div>
  );
}
