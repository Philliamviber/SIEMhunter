import { useEffect } from 'react';
import { Link } from 'react-router-dom';
import type { SecurityEvent } from '../types/api';
import { formatTimestamp } from '../utils/formatTimestamp';
import { getEventIdDescription } from '../utils/eventIdDescriptions';

/**
 * EventDetailPanel.tsx — Slide-in panel showing all fields for a single SecurityEvent.
 *
 * Slide-in pattern: the panel is fixed to the right edge (inset-y-0 right-0) at z-50.
 * A full-screen transparent backdrop at z-40 catches outside clicks and calls onClose,
 * matching the UX convention for slide-in drawers (click outside to dismiss).
 * Escape key also closes the panel (keyboard navigation, see useEffect below).
 *
 * UnmappedFields is shown as pretty-printed JSON even though most canonical fields
 * are displayed above it. Forensic value: fields that the normalizer couldn't map to
 * a schema column (tool-specific, source-specific, or future fields) may still be the
 * most important data point for an analyst. Displaying the raw JSON preserves that.
 *
 * Pivot links at the bottom generate pre-filtered URLs into the Events page, enabling
 * one-click pivots from a single event to all events from the same host, user, or IP.
 * These use React Router <Link> (client-side navigation, no page reload).
 *
 * AnomalyScore is not shown here because it lives on detection_hits rows, not on
 * security_events rows. The governance note at the bottom of the panel makes this
 * explicit to analysts who expect to see it.
 */
// ── EventDetailPanel ──────────────────────────────────────────────────────────

export function EventDetailPanel({ event, onClose }: { event: SecurityEvent; onClose: () => void }) {
  // Close on Escape key
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        onClose();
      }
    }
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  // UnmappedFields is stored as a JSON string in ClickHouse. Parse it for pretty-printing.
  // The empty-string and "{}" checks skip the JSON.parse call for events with no unmapped
  // data (the common case), avoiding unnecessary parse overhead in large event lists.
  let unmappedParsed: unknown = null;
  try {
    if (event.UnmappedFields && event.UnmappedFields !== '{}' && event.UnmappedFields !== '') {
      unmappedParsed = JSON.parse(event.UnmappedFields);
    }
  } catch {
    // show raw
  }

  const eventDescription = getEventIdDescription(event.EventID);

  const fields: [string, string][] = [
    ['TimeGenerated', formatTimestamp(event.TimeGenerated)],
    ['HostName', event.HostName],
    ['EventID', String(event.EventID)],
    ['ChannelName', event.ChannelName],
    ['ProviderName', event.ProviderName],
    ['SubjectUserName', event.SubjectUserName],
    ['SubjectUserSid', event.SubjectUserSid],
    ['SubjectDomainName', event.SubjectDomainName],
    ['TargetUserName', event.TargetUserName],
    ['TargetUserSid', event.TargetUserSid],
    ['TargetDomainName', event.TargetDomainName],
    ['LogonType', String(event.LogonType)],
    ['ServiceName', event.ServiceName],
    ['ProcessImagePath', event.ProcessImagePath],
    ['CommandLine', event.CommandLine],
    ['ParentProcessImagePath', event.ParentProcessImagePath],
    ['ParentCommandLine', event.ParentCommandLine],
    ['GrantedAccess', event.GrantedAccess],
    ['ObjectName', event.ObjectName],
    ['FileMD5', event.FileMD5],
    ['FileSHA256', event.FileSHA256],
    ['RegistryKey', event.RegistryKey],
    ['SrcIpAddr', event.SrcIpAddr],
    ['SrcPort', String(event.SrcPort)],
    ['DstIpAddr', event.DstIpAddr],
    ['DstPort', String(event.DstPort)],
    ['NetworkProtocol', event.NetworkProtocol],
    ['ProvenanceTag', event.ProvenanceTag],
    ['EventRecordID', event.EventRecordID],
    ['IngestTimestamp', formatTimestamp(event.IngestTimestamp)],
  ];

  return (
    <>
    {/* Backdrop — closes panel on outside click; hidden from assistive tech */}
    <div className="fixed inset-0 z-40" onClick={onClose} aria-hidden="true" />
    <div className="fixed inset-y-0 right-0 w-[480px] bg-gray-900 border-l border-gray-800 overflow-y-auto z-50 shadow-2xl">
      <div className="px-5 py-4 border-b border-gray-800 flex items-center justify-between sticky top-0 bg-gray-900">
        <div>
          <h3 className="text-white font-semibold text-sm">Event Detail</h3>
          <p className="text-gray-500 text-xs font-mono mt-0.5">EID {event.EventID} · {event.HostName}</p>
        </div>
        <button
          onClick={onClose}
          aria-label="Close event detail"
          className="text-gray-500 hover:text-gray-300 p-1"
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <div className="p-5 space-y-1">
        {fields.map(([key, val]) => (
          val ? (
            <div key={key} className="flex gap-2 text-sm py-1.5 border-b border-gray-800/40">
              <span className="text-gray-500 w-44 flex-shrink-0 font-medium text-xs uppercase tracking-wide pt-0.5">
                {key}
              </span>
              <span className="text-gray-200 font-mono text-xs break-all">{val}</span>
            </div>
          ) : null
        ))}

        {/* Event ID description row — inserted after EventID data */}
        {eventDescription && (
          <div className="flex gap-2 text-sm py-1.5 border-b border-gray-800/40">
            <span className="text-gray-500 w-44 flex-shrink-0 font-medium text-xs uppercase tracking-wide pt-0.5">
              Event Description
            </span>
            <span className="text-gray-200 font-mono text-xs break-all">{eventDescription}</span>
          </div>
        )}

        {/* UnmappedFields */}
        <div className="pt-2">
          <div className="text-gray-500 font-medium text-xs uppercase tracking-wide mb-2">UnmappedFields</div>
          {unmappedParsed ? (
            <pre className="bg-gray-800 rounded p-3 text-xs text-gray-300 overflow-x-auto whitespace-pre-wrap break-all">
              {JSON.stringify(unmappedParsed, null, 2)}
            </pre>
          ) : (
            <span className="text-gray-600 text-xs">empty</span>
          )}
        </div>

        {/* Pivot Links */}
        <div className="pt-3">
          <div className="text-gray-500 font-medium text-xs uppercase tracking-wide mb-2">Pivot Links</div>
          <div className="flex flex-col gap-1.5">
            <Link
              to={`/events?hostname=${encodeURIComponent(event.HostName)}`}
              className="inline-block px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-cyan-400 hover:text-cyan-300 rounded text-xs font-mono border border-gray-700 hover:border-gray-600 transition-colors"
            >
              All events from this host
            </Link>
            {event.SubjectUserName && (
              <Link
                to={`/events?user=${encodeURIComponent(event.SubjectUserName)}`}
                className="inline-block px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-cyan-400 hover:text-cyan-300 rounded text-xs font-mono border border-gray-700 hover:border-gray-600 transition-colors"
              >
                All events by this user
              </Link>
            )}
            {event.SrcIpAddr && (
              <Link
                to={`/events?src_ip=${encodeURIComponent(event.SrcIpAddr)}`}
                className="inline-block px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-cyan-400 hover:text-cyan-300 rounded text-xs font-mono border border-gray-700 hover:border-gray-600 transition-colors"
              >
                All events from this IP
              </Link>
            )}
            <Link
              to={`/events?event_id=${event.EventID}`}
              className="inline-block px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-cyan-400 hover:text-cyan-300 rounded text-xs font-mono border border-gray-700 hover:border-gray-600 transition-colors"
            >
              All events with this EventID
            </Link>
          </div>
        </div>

        {/* Governance note — no AnomalyScore per event */}
        <div className="mt-4 bg-gray-800/50 rounded p-3 text-xs text-gray-500">
          AnomalyScore is not available on security events — it lives on detection hits only.
        </div>
      </div>
    </div>
    </>
  );
}
