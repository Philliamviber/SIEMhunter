import { Link, useParams } from 'react-router-dom';
import clsx from 'clsx';
import { useIncident, useUpdateIncidentStatus } from '../hooks/useApi';
import { SeverityBadge } from '../components/SeverityBadge';
import { formatTimestamp } from '../utils/formatTimestamp';
import type { IncidentStatus } from '../types/api';
import { ClaudeChatbar } from '../components/ClaudeChatbar';

// ── Status badge ──────────────────────────────────────────────────────────────

const STATUS_CLASSES: Record<string, string> = {
  open: 'bg-green-500/20 text-green-400 border border-green-500/40',
  closed: 'bg-gray-600/20 text-gray-400 border border-gray-600/40',
  archived: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40',
};

function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center px-2.5 py-1 rounded text-xs font-medium uppercase tracking-wide',
        STATUS_CLASSES[status] ?? 'bg-gray-600/20 text-gray-400 border border-gray-600/40',
      )}
    >
      {status}
    </span>
  );
}

// ── Detail field ──────────────────────────────────────────────────────────────

function DetailField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">{label}</div>
      <div className="text-gray-200 text-sm">{children}</div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: incident, isLoading, isError } = useIncident(id ?? '');
  const { mutate: updateStatus, isPending } = useUpdateIncidentStatus();

  function changeStatus(newStatus: IncidentStatus) {
    if (!id) return;
    updateStatus({ id, newStatus });
  }

  if (isLoading) {
    return (
      <div className="p-6 flex flex-col gap-4">
        <div className="h-6 w-40 bg-gray-800 rounded animate-pulse" />
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-4 bg-gray-800 rounded animate-pulse w-3/4" />
          ))}
        </div>
      </div>
    );
  }

  if (isError || !incident) {
    return (
      <div className="p-6">
        <Link
          to="/incidents"
          className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-gray-200 mb-4 transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
          </svg>
          Incidents
        </Link>
        <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-4 text-red-400 text-sm">
          Failed to load incident.
        </div>
      </div>
    );
  }

  const isOpen = incident.status === 'open';
  const provenancePrefix = `manual-upload:incident:${incident.id}:*`;

  return (
    <div className="p-6 flex flex-col gap-5 max-w-3xl">
      {/* Back link */}
      <Link
        to="/incidents"
        className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-gray-200 transition-colors self-start"
      >
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
        </svg>
        Incidents
      </Link>

      {/* Header */}
      <div className="flex items-start gap-3 flex-wrap">
        <div className="flex-1 min-w-0">
          <h1 className="text-xl font-bold text-white truncate">{incident.name}</h1>
          <div className="flex items-center gap-2 mt-1.5 flex-wrap">
            <StatusBadge status={incident.status} />
            <SeverityBadge severity={incident.severity} />
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-2 flex-shrink-0">
          {isOpen ? (
            <>
              <button
                disabled={isPending}
                onClick={() => changeStatus('closed')}
                className="px-3 py-1.5 text-sm bg-gray-700 hover:bg-gray-600 text-white rounded-md font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Close
              </button>
              <button
                disabled={isPending}
                onClick={() => changeStatus('archived')}
                className="px-3 py-1.5 text-sm bg-yellow-600/20 hover:bg-yellow-600/30 text-yellow-400 border border-yellow-600/40 rounded-md font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Archive
              </button>
            </>
          ) : (
            <button
              disabled={isPending}
              onClick={() => changeStatus('open')}
              className="px-3 py-1.5 text-sm bg-green-600/20 hover:bg-green-600/30 text-green-400 border border-green-600/40 rounded-md font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Reopen
            </button>
          )}
        </div>
      </div>

      {/* Details card */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 grid grid-cols-1 sm:grid-cols-2 gap-5">
        <DetailField label="Description">
          {incident.description ? (
            <span>{incident.description}</span>
          ) : (
            <span className="text-gray-500 italic">No description provided</span>
          )}
        </DetailField>

        <DetailField label="Event Count">
          <span className="font-mono text-white font-medium">{incident.event_count}</span>
        </DetailField>

        <DetailField label="Created">
          <span className="whitespace-nowrap">{formatTimestamp(incident.created_at)}</span>
        </DetailField>

        <DetailField label="Last Updated">
          <span className="whitespace-nowrap">{formatTimestamp(incident.updated_at)}</span>
        </DetailField>

        <DetailField label="Incident ID">
          <span className="font-mono text-xs text-gray-400 break-all">{incident.id}</span>
        </DetailField>
      </div>

      {/* Notes (read-only in Wave 2C) */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-white">Notes</h2>
          <span className="text-xs text-gray-600">Read-only in this release</span>
        </div>
        <div className="bg-gray-800/50 border border-gray-700 rounded-lg px-4 py-3 text-gray-500 text-sm italic min-h-[72px]">
          Notes editor coming in a future release.
        </div>
      </div>

      {/* ProvenanceTag hint */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <h2 className="text-sm font-semibold text-white mb-2">ProvenanceTag Filter</h2>
        <p className="text-xs text-gray-400 mb-2">
          Use this prefix in the Query Console to scope events to this incident:
        </p>
        <code className="block bg-gray-800 border border-gray-700 rounded px-3 py-2 text-xs text-blue-300 font-mono break-all">
          {provenancePrefix}
        </code>
      </div>

      <ClaudeChatbar />
    </div>
  );
}
