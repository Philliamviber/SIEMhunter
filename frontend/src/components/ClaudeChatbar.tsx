/**
 * ClaudeChatbar.tsx — Floating AI Analysis panel, accessible from any page.
 *
 * Data source: GET /v1/ai/summary returns aggregated statistics only (event counts,
 * detection counts, top rule IDs). Raw event fields (CommandLine, hostnames, IPs,
 * usernames) are never sent to the Claude API. This is a hard constraint from the
 * privacy design: see ARCHITECTURE.md §AI and docker-compose.yml (egress network).
 *
 * The panel is fixed-positioned at bottom-right (z-50) so it is always visible
 * regardless of scroll position or which page is active. This lets analysts keep
 * the AI summary open while scrolling through event tables.
 *
 * Open/closed state is persisted to sessionStorage so navigating between pages
 * (which unmounts and remounts this component) does not collapse the panel. The
 * try/catch around sessionStorage guards against browsers with storage disabled.
 */
import { useState, useEffect } from 'react';
import { useAiSummary } from '../hooks/useApi';
import { formatTimestamp } from '../utils/formatTimestamp';

const STORAGE_KEY = 'siemhunter.chatbar.open';

function BrainIcon() {
  return (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"
      />
    </svg>
  );
}

function SpinnerIcon() {
  return (
    <svg className="w-4 h-4 animate-spin text-purple-400" fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  );
}

export function ClaudeChatbar() {
  const [isOpen, setIsOpen] = useState<boolean>(() => {
    try {
      return sessionStorage.getItem(STORAGE_KEY) === 'true';
    } catch {
      return false;
    }
  });

  const { data, isLoading, isError } = useAiSummary();

  useEffect(() => {
    try {
      sessionStorage.setItem(STORAGE_KEY, String(isOpen));
    } catch {
      // sessionStorage may be unavailable; silently continue
    }
  }, [isOpen]);

  return (
    // fixed bottom-right: always reachable regardless of page scroll position.
    // z-50 places it above page content but below any modal (z-50+ or z-[60]).
    <div className="fixed bottom-0 right-6 z-50 flex flex-col items-end">
      {/* Expanded panel */}
      {isOpen && (
        <div className="mb-0 w-96 max-h-[420px] bg-gray-900 border border-gray-700 rounded-t-lg shadow-2xl flex flex-col overflow-hidden">
          {/* Panel header */}
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-gray-800 bg-gray-900 shrink-0">
            <div className="flex items-center gap-2 text-purple-400">
              <BrainIcon />
              <span className="text-sm font-semibold text-white">AI Analysis</span>
            </div>
            <button
              onClick={() => setIsOpen(false)}
              className="text-gray-500 hover:text-gray-300 transition-colors"
              aria-label="Close AI Analysis panel"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
              </svg>
            </button>
          </div>

          {/* Panel body */}
          <div className="overflow-y-auto flex-1 px-4 py-3 flex flex-col gap-3">
            {isLoading && (
              <div className="flex items-center gap-2 text-gray-400 text-sm py-4 justify-center">
                <SpinnerIcon />
                <span>Loading analysis...</span>
              </div>
            )}

            {isError && (
              <p className="text-gray-500 text-sm py-4 text-center">
                AI analysis unavailable — API key not configured or service unreachable.
              </p>
            )}

            {data && (
              <>
                <p className="text-gray-300 text-sm leading-relaxed">{data.narrative}</p>

                {data.notable_items.length > 0 && (
                  <ul className="space-y-1">
                    {data.notable_items.map((item, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-gray-400">
                        <span className="text-purple-400 mt-0.5 shrink-0">•</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                )}

                <div className="pt-2 border-t border-gray-800 flex flex-col gap-0.5 mt-auto shrink-0">
                  <p className="text-xs text-gray-600">{data.disclaimer}</p>
                  <p className="text-xs text-gray-600">
                    Generated {formatTimestamp(data.generated_at)} · {data.source_window}
                  </p>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* Toggle button bar */}
      <button
        onClick={() => setIsOpen((prev) => !prev)}
        className="flex items-center gap-2 px-4 py-2 bg-gray-800 border border-gray-700 rounded-t-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-750 hover:border-gray-600 transition-colors shadow-lg"
        aria-expanded={isOpen}
        aria-label="Toggle AI Analysis panel"
      >
        <span className="text-purple-400">
          <BrainIcon />
        </span>
        <span>AI Analysis</span>
        <svg
          className={`w-3 h-3 text-gray-500 transition-transform duration-150 ${isOpen ? 'rotate-180' : ''}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M5 15l7-7 7 7" />
        </svg>
      </button>
    </div>
  );
}
