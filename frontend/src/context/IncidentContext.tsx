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
