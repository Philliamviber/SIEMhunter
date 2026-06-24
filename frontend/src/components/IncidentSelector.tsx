import { useState, useRef, useEffect } from 'react';
import clsx from 'clsx';
import { useIncidents } from '../hooks/useApi';
import { useIncidentContext } from '../context/IncidentContext';
import { SeverityBadge } from './SeverityBadge';
import type { Incident } from '../types/api';

const LISTBOX_ID = 'incident-listbox';
const optionId = (id: string) => `incident-option-${id}`;

function IncidentOption({
  incident,
  isHighlighted,
  isSelected,
  onSelect,
}: {
  incident: Incident;
  isHighlighted: boolean;
  isSelected: boolean;
  onSelect: () => void;
}) {
  return (
    <div
      id={optionId(incident.id)}
      role="option"
      aria-selected={isSelected}
      onClick={onSelect}
      className={clsx(
        'w-full flex items-center gap-2 px-3 py-2 text-sm cursor-pointer transition-colors',
        isHighlighted ? 'bg-gray-700' : 'hover:bg-gray-700/60',
      )}
    >
      <SeverityBadge severity={incident.severity} className="flex-shrink-0" />
      <span className="truncate text-gray-200">{incident.name}</span>
    </div>
  );
}

export function IncidentSelector() {
  const [open, setOpen] = useState(false);
  const [focusedIndex, setFocusedIndex] = useState(-1);
  const ref = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const { activeIncidentId, activeIncident, setActiveIncidentId } = useIncidentContext();
  const { data } = useIncidents();

  const openIncidents = (data?.incidents ?? []).filter((i) => i.status === 'open');

  function openDropdown() {
    const selectedIdx = openIncidents.findIndex((i) => i.id === activeIncidentId);
    setFocusedIndex(selectedIdx >= 0 ? selectedIdx : openIncidents.length > 0 ? 0 : -1);
    setOpen(true);
  }

  function closeDropdown() {
    setOpen(false);
    setFocusedIndex(-1);
  }

  function selectOption(id: string) {
    setActiveIncidentId(id);
    closeDropdown();
    buttonRef.current?.focus();
  }

  // Close on outside click
  useEffect(() => {
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        closeDropdown();
      }
    }
    if (open) {
      document.addEventListener('mousedown', handler);
    }
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  function handleKeyDown(e: React.KeyboardEvent<HTMLButtonElement>) {
    if (!open) {
      if (e.key === 'Enter' || e.key === ' ' || e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        openDropdown();
      }
      return;
    }

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setFocusedIndex((i) => Math.min(i + 1, openIncidents.length - 1));
        break;
      case 'ArrowUp':
        e.preventDefault();
        setFocusedIndex((i) => Math.max(i - 1, 0));
        break;
      case 'Home':
        e.preventDefault();
        setFocusedIndex(0);
        break;
      case 'End':
        e.preventDefault();
        setFocusedIndex(openIncidents.length - 1);
        break;
      case 'Enter':
        e.preventDefault();
        if (focusedIndex >= 0 && focusedIndex < openIncidents.length) {
          selectOption(openIncidents[focusedIndex].id);
        }
        break;
      case 'Escape':
        e.preventDefault();
        closeDropdown();
        buttonRef.current?.focus();
        break;
    }
  }

  const focusedOption = focusedIndex >= 0 ? openIncidents[focusedIndex] : null;

  return (
    <div ref={ref} className="relative">
      {/* Trigger — select-only combobox pattern */}
      {/* Combobox trigger — clear button is a sibling (not child) to avoid button-in-button */}
      <div className="relative flex">
        <button
          ref={buttonRef}
          type="button"
          role="combobox"
          aria-haspopup="listbox"
          aria-expanded={open}
          aria-controls={LISTBOX_ID}
          aria-activedescendant={open && focusedOption ? optionId(focusedOption.id) : undefined}
          aria-label={
            activeIncident ? `Incident scope: ${activeIncident.name}` : 'Select incident scope'
          }
          className={clsx(
            'flex items-center gap-2 py-1.5 rounded-md bg-gray-800 border border-gray-700 cursor-pointer hover:border-gray-600 transition-colors select-none',
            activeIncidentId ? 'pl-3 pr-6' : 'px-3',
          )}
          onClick={() => (open ? closeDropdown() : openDropdown())}
          onKeyDown={handleKeyDown}
        >
          <svg
            className="w-3.5 h-3.5 text-gray-400 flex-shrink-0"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
            aria-hidden="true"
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
            className={clsx(
              'w-3 h-3 text-gray-500 ml-0.5 flex-shrink-0 transition-transform',
              open && 'rotate-180',
            )}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
            aria-hidden="true"
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </button>

        {/* Clear button — absolutely positioned sibling to avoid button-in-button nesting */}
        {activeIncidentId && (
          <button
            type="button"
            aria-label="Clear active incident"
            className="absolute right-1 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
            onClick={() => setActiveIncidentId(null)}
          >
            <svg
              className="w-3 h-3"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
              aria-hidden="true"
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>

      {/* Listbox popup */}
      {open && (
        <div
          id={LISTBOX_ID}
          role="listbox"
          aria-label="Open incidents"
          className="absolute right-0 top-full mt-1 w-72 bg-gray-800 border border-gray-700 rounded-lg shadow-xl z-50 py-1 overflow-hidden"
        >
          <div className="px-3 py-2 border-b border-gray-700">
            <p className="text-xs font-medium text-gray-400 uppercase tracking-wide">
              Open Incidents
            </p>
          </div>
          {openIncidents.length === 0 ? (
            <p className="px-3 py-3 text-xs text-gray-500 text-center">No open incidents</p>
          ) : (
            openIncidents.map((incident, idx) => (
              <IncidentOption
                key={incident.id}
                incident={incident}
                isHighlighted={idx === focusedIndex}
                isSelected={incident.id === activeIncidentId}
                onSelect={() => selectOption(incident.id)}
              />
            ))
          )}
        </div>
      )}
    </div>
  );
}
