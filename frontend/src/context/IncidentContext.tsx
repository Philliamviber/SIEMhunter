/**
 * IncidentContext.tsx — Global context for the currently active incident.
 *
 * Why global context? Three disconnected UI surfaces need the active incident ID
 * simultaneously:
 *   1. UploadZone — scopes file uploads to the incident (incident_id in FormData)
 *   2. GlobalSearchBar — scopes search results to the incident (incident_id in request)
 *   3. Navigation bar — shows the active incident name label
 *
 * Prop-drilling would require threading the ID through PageLayout → NavBar and
 * through every page that hosts UploadZone or GlobalSearchBar. Context avoids that.
 *
 * The active incident ID is also persisted to sessionStorage so that refreshing
 * the page (or navigating away and back) does not lose the analyst's incident scope.
 * It clears automatically when the tab closes (sessionStorage, not localStorage).
 *
 * Two-component pattern: IncidentProvider (manages state + sessionStorage) wraps
 * IncidentFetcher (calls useIncident unconditionally). This is required because
 * React hooks must not be called conditionally — if we only called useIncident when
 * activeIncidentId was non-null, the hook call count would change across renders.
 */
import { createContext, useContext, useState, useMemo, type ReactNode } from 'react';
import { useIncident } from '../hooks/useApi';
import type { Incident } from '../types/api';

const STORAGE_KEY = 'siemhunter.incident.active';

interface IncidentContextValue {
  activeIncidentId: string | null;
  setActiveIncidentId: (id: string | null) => void;
  activeIncident: Incident | null;
}

const IncidentContext = createContext<IncidentContextValue | null>(null);

// Inner component so we can always call useIncident (hook must not be conditional)
function IncidentFetcher({
  activeIncidentId,
  setActiveIncidentId,
  children,
}: {
  activeIncidentId: string | null;
  setActiveIncidentId: (id: string | null) => void;
  children: ReactNode;
}) {
  const { data: activeIncident = null } = useIncident(activeIncidentId ?? '');

  const value = useMemo<IncidentContextValue>(
    () => ({
      activeIncidentId,
      setActiveIncidentId,
      // Guard: if no ID is set, never expose a stale activeIncident from a prior
      // selection. useIncident returns the last-fetched data even after the ID
      // changes if the new fetch hasn't resolved yet.
      activeIncident: activeIncidentId ? (activeIncident ?? null) : null,
    }),
    [activeIncidentId, setActiveIncidentId, activeIncident],
  );

  return (
    <IncidentContext.Provider value={value}>
      {children}
    </IncidentContext.Provider>
  );
}

export function IncidentProvider({ children }: { children: ReactNode }) {
  const [activeIncidentId, setActiveIncidentIdState] = useState<string | null>(
    () => sessionStorage.getItem(STORAGE_KEY),
  );

  function setActiveIncidentId(id: string | null) {
    setActiveIncidentIdState(id);
    if (id) {
      sessionStorage.setItem(STORAGE_KEY, id);
    } else {
      sessionStorage.removeItem(STORAGE_KEY);
    }
  }

  return (
    <IncidentFetcher
      activeIncidentId={activeIncidentId}
      setActiveIncidentId={setActiveIncidentId}
    >
      {children}
    </IncidentFetcher>
  );
}

// Named useIncidentContext to avoid clash with useIncident hook from useApi
export function useIncidentContext(): IncidentContextValue {
  const ctx = useContext(IncidentContext);
  if (!ctx) {
    throw new Error('useIncidentContext must be used inside IncidentProvider');
  }
  return ctx;
}
