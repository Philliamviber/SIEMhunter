import { useState, useRef, useEffect } from 'react';
import clsx from 'clsx';
import { useIncidents } from '../hooks/useApi';
import { useIncidentContext } from '../context/IncidentContext';
import { SeverityBadge } from './SeverityBadge';
import type { Incident } from '../types/api';

function IncidentOption({
  incident,
  isActive,
  onSelect,
}: {
  incident: Incident;
  isActive: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      onClick={onSelect}
      className={clsx(
        'w-full flex items-center gap-2 px-3 py-2 text-left text-sm hover:bg-gray-700 transition-colors',
        isActive && 'bg-gray-700/60',
      )}
    >
      <SeverityBadge severity={incident.severity} className="flex-shrink-0" />
      <span className="truncate text-gray-200">{incident.name}</span>
    </button>
  );
}

export function IncidentSelector() {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const { activeIncidentId, activeIncident, setActiveIncidentId } = useIncidentContext();
  const { data } = useIncidents();

  const openIncidents = (data?.incidents ?? []).filter((i) => i.status === 'open');

  // Close on outside click
  useEffect(() => {
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) {
      document.addEventListener('mousedown', handler);
    }
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  return (
    <div ref={ref} className="relative">
      {/* Trigger bar */}
      <div
        className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-gray-800 border border-gray-700 cursor-pointer hover:border-gray-600 transition-colors select-none"
        onClick={() => setOpen((o) => !o)}
      >
        <svg
          className="w-3.5 h-3.5 text-gray-400 flex-shrink-0"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"
          />
        </svg>

        {activeIncident ? (
          <>
            <SeverityBadge severity={activeIncident.severity} className="text-xs" />
            <span className="text-white text-xs font-medium max-w-[140px] truncate">
              {activeIncident.name}
            </span>
          </>
        ) : (
          <span className="text-gray-400 text-xs">No incident scope</span>
        )}

        <svg
          className={clsx('w-3 h-3 text-gray-500 ml-0.5 flex-shrink-0 transition-transform', open && 'rotate-180')}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>

        {/* Clear button */}
        {activeIncidentId && (
          <button
            className="ml-0.5 text-gray-500 hover:text-gray-300 transition-colors"
            onClick={(e) => {
              e.stopPropagation();
              setActiveIncidentId(null);
            }}
            title="Clear active incident"
          >
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>

      {/* Dropdown */}
      {open && (
        <div className="absolute right-0 top-full mt-1 w-72 bg-gray-800 border border-gray-700 rounded-lg shadow-xl z-50 py-1 overflow-hidden">
          <div className="px-3 py-2 border-b border-gray-700">
            <p className="text-xs font-medium text-gray-400 uppercase tracking-wide">Open Incidents</p>
          </div>
          {openIncidents.length === 0 ? (
            <p className="px-3 py-3 text-xs text-gray-500 text-center">No open incidents</p>
          ) : (
            openIncidents.map((incident) => (
              <IncidentOption
                key={incident.id}
                incident={incident}
                isActive={incident.id === activeIncidentId}
                onSelect={() => {
                  setActiveIncidentId(incident.id);
                  setOpen(false);
                }}
              />
            ))
          )}
        </div>
      )}
    </div>
  );
}
