/**
 * PrefsContext.tsx — Per-analyst preferences context.
 *
 * Loads preferences from the API on mount and exposes them to every consumer
 * without prop-drilling. Preferences are keyed to the server-side analyst
 * identity; the client never supplies an owner field.
 *
 * Three preference fields are surfaced:
 *   - default_time_range  — applied as a default in filter hooks
 *   - table_density       — read by DataTable (and wrappers) to set row sizing
 *   - default_landing_page — read by App.tsx to redirect on first authenticated load
 *
 * Values are rendered as text only; no preference field is ever set as innerHTML
 * or used in a dangerouslySetInnerHTML context.
 */
import {
  createContext,
  useContext,
  useMemo,
  useEffect,
  useRef,
  type ReactNode,
} from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { usePreferences, useSetPreferences } from '../hooks/useApi';
import type { AnalystPreferences, AnalystPreferencesUpdate } from '../types/api';

const DEFAULTS: AnalystPreferences = {
  default_time_range: '24h',
  table_density: 'comfortable',
  default_landing_page: '/',
};

interface PrefsContextValue {
  prefs: AnalystPreferences;
  isLoading: boolean;
  setPrefs: (update: AnalystPreferencesUpdate) => void;
}

const PrefsContext = createContext<PrefsContextValue | null>(null);

function PrefsNavigator({ landingPage }: { landingPage: string }) {
  const navigate = useNavigate();
  const location = useLocation();
  const redirected = useRef(false);

  useEffect(() => {
    if (redirected.current) return;
    // Only redirect if the analyst is on the root path and their preference
    // points elsewhere. Never redirect away from a deep-link.
    if (location.pathname === '/' && landingPage !== '/') {
      redirected.current = true;
      navigate(landingPage, { replace: true });
    }
  }, [landingPage, navigate, location.pathname]);

  return null;
}

export function PrefsProvider({ children }: { children: ReactNode }) {
  const { data, isLoading } = usePreferences();
  const { mutate } = useSetPreferences();

  const prefs: AnalystPreferences = useMemo(
    () => (data ?? DEFAULTS),
    [data],
  );

  const value = useMemo<PrefsContextValue>(
    () => ({
      prefs,
      isLoading,
      setPrefs: (update: AnalystPreferencesUpdate) => mutate(update),
    }),
    [prefs, isLoading, mutate],
  );

  return (
    <PrefsContext.Provider value={value}>
      {/* Redirect to default landing page on first load; no-op if already there. */}
      {!isLoading && <PrefsNavigator landingPage={prefs.default_landing_page} />}
      {children}
    </PrefsContext.Provider>
  );
}

export function usePrefsContext(): PrefsContextValue {
  const ctx = useContext(PrefsContext);
  if (!ctx) {
    throw new Error('usePrefsContext must be used inside PrefsProvider');
  }
  return ctx;
}
