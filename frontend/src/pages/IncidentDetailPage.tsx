import { useState, useRef, useEffect } from 'react';
import { Link, useParams } from 'react-router-dom';
import clsx from 'clsx';
import { useIncident, useUpdateIncidentStatus, useIncidentNotes, useAddIncidentNote } from '../hooks/useApi';
import { useToast } from '../hooks/useToast';
import { SeverityBadge } from '../components/SeverityBadge';
import { formatTimestamp } from '../utils/formatTimestamp';
import { downloadIncidentReport } from '../utils/incidentReportUtils';
import { api } from '../api/client';
import type { IncidentStatus, Incident, IncidentNote } from '../types/api';

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

// ── Confirm dialog ────────────────────────────────────────────────────────────

interface ConfirmDialogProps {
  message: string;
  onConfirm: () => void;
  onCancel: () => void;
}

function ConfirmDialog({ message, onConfirm, onCancel }: ConfirmDialogProps) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      role="dialog"
      aria-modal="true"
      aria-label="Confirm action"
    >
      <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-sm shadow-2xl p-6">
        <h2 className="text-white font-semibold text-base mb-3">Confirm</h2>
        <p className="text-gray-300 text-sm mb-5">{message}</p>
        <div className="flex gap-3 justify-end">
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 text-sm text-gray-400 hover:text-gray-200 transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className="px-4 py-2 text-sm bg-red-600 hover:bg-red-500 text-white rounded-md font-medium transition-colors"
          >
            Confirm
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Export button ─────────────────────────────────────────────────────────────

type ExportFormat = 'markdown' | 'json' | 'pdf';

const FORMAT_LABELS: Record<ExportFormat, string> = {
  markdown: 'Markdown (.md)',
  json: 'JSON (.json)',
  pdf: 'PDF (print)',
};

function ExportIncidentButton({
  incident,
  notes,
}: {
  incident: Incident;
  notes: IncidentNote[];
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function handleOutside(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', handleOutside);
    return () => document.removeEventListener('mousedown', handleOutside);
  }, [open]);

  async function handleExport(format: ExportFormat) {
    setOpen(false);
    setBusy(true);
    try {
      const provenancePrefix = `manual-upload:incident:${incident.id}:%`;
      const result = await api.query({
        sql: `SELECT TimeGenerated, HostName, EventID, EventRecordID, SubjectUserName, TargetUserName, CommandLine, ProcessImagePath, SrcIpAddr, DstIpAddr FROM siemhunter.security_events WHERE ProvenanceTag LIKE {prefix:String} ORDER BY TimeGenerated DESC LIMIT 1001`,
        params: { prefix: provenancePrefix },
      });

      const truncated = result.row_count > 1000 || result.truncated;
      const events = truncated ? result.rows.slice(0, 1000) : result.rows;

      downloadIncidentReport(
        {
          incident,
          notes,
          events,
          exportOptions: truncated
            ? { truncated: true, truncationNote: 'Results capped at 1,000 rows — only the first 1,000 events are included in this report' }
            : undefined,
        },
        format,
      );
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Export failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="relative" ref={menuRef}>
      <button
        type="button"
        disabled={busy}
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="true"
        aria-expanded={open}
        aria-label="Export incident report"
        className="px-3 py-1.5 text-sm bg-blue-700/20 hover:bg-blue-700/30 text-blue-400 border border-blue-600/40 rounded-md font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5"
      >
        {busy ? 'Exporting…' : 'Export'}
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {open && (
        <div
          role="menu"
          className="absolute right-0 top-full mt-1 z-30 w-44 bg-gray-900 border border-gray-700 rounded-lg shadow-xl py-1"
        >
          {(Object.keys(FORMAT_LABELS) as ExportFormat[]).map((fmt) => (
            <button
              key={fmt}
              role="menuitem"
              type="button"
              onClick={() => handleExport(fmt)}
              className="w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-gray-800 hover:text-white transition-colors"
            >
              {FORMAT_LABELS[fmt]}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Notes panel ───────────────────────────────────────────────────────────────

function NotesPanel({ incidentId }: { incidentId: string }) {
  const { data: notesData, isLoading } = useIncidentNotes(incidentId);
  const { mutate: addNote, isPending: isSubmitting } = useAddIncidentNote(incidentId);
  const [draft, setDraft] = useState('');

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = draft.trim();
    if (!trimmed) return;
    addNote({ content: trimmed }, { onSuccess: () => setDraft('') });
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 flex flex-col gap-4">
      <h2 className="text-sm font-semibold text-white">Notes</h2>

      {/* Note list — content rendered as text, never as HTML */}
      <div className="flex flex-col gap-3 max-h-80 overflow-y-auto">
        {isLoading && (
          <div className="text-gray-500 text-sm italic">Loading notes…</div>
        )}
        {!isLoading && notesData && notesData.notes.length === 0 && (
          <div className="text-gray-500 text-sm italic">No notes yet. Add the first one below.</div>
        )}
        {notesData?.notes.map((note) => (
          <div
            key={note.id}
            className="bg-gray-800/60 border border-gray-700 rounded-lg px-4 py-3 text-sm"
          >
            <div className="flex items-center gap-2 mb-1.5 text-xs text-gray-500">
              {/* Author and timestamp are server-set; rendered as text (no innerHTML) */}
              <span className="font-medium text-gray-400">{note.author}</span>
              <span>·</span>
              <span>{formatTimestamp(note.created_at)}</span>
            </div>
            {/* Content is plain text — React escapes it by default, preventing XSS */}
            <p className="text-gray-200 whitespace-pre-wrap break-words">{note.content}</p>
          </div>
        ))}
      </div>

      {/* Add note form */}
      <form onSubmit={handleSubmit} className="flex flex-col gap-2 pt-2 border-t border-gray-800">
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="Add a note…"
          rows={3}
          maxLength={10000}
          className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600 resize-y focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
        />
        <div className="flex justify-end">
          <button
            type="submit"
            disabled={isSubmitting || !draft.trim()}
            className="px-4 py-1.5 text-sm bg-blue-600 hover:bg-blue-500 text-white rounded-md font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isSubmitting ? 'Saving…' : 'Add Note'}
          </button>
        </div>
      </form>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: incident, isLoading, isError } = useIncident(id ?? '');
  const { mutate: updateStatus, isPending } = useUpdateIncidentStatus();
  const { data: notesData } = useIncidentNotes(id ?? '');
  const toast = useToast();
  const [pending, setPending] = useState<{ newStatus: IncidentStatus; label: string } | null>(null);

  function requestDestructive(newStatus: IncidentStatus, label: string) {
    setPending({ newStatus, label });
  }

  function confirmChange() {
    if (!id || !pending) return;
    const { newStatus } = pending;
    setPending(null);
    updateStatus(
      { id, newStatus },
      {
        onSuccess: () => toast.success(`Incident ${newStatus}.`),
        onError: (err) => toast.error(err instanceof Error ? err.message : 'Failed to update incident status.'),
      },
    );
  }

  function changeStatus(newStatus: IncidentStatus) {
    if (!id) return;
    updateStatus(
      { id, newStatus },
      {
        onSuccess: () => toast.success(`Incident ${newStatus}.`),
        onError: (err) => toast.error(err instanceof Error ? err.message : 'Failed to update incident status.'),
      },
    );
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
        <div className="flex items-center gap-2 flex-shrink-0 flex-wrap">
          {isOpen ? (
            <>
              <button
                disabled={isPending}
                onClick={() => requestDestructive('closed', 'close this incident')}
                className="px-3 py-1.5 text-sm bg-gray-700 hover:bg-gray-600 text-white rounded-md font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Close
              </button>
              <button
                disabled={isPending}
                onClick={() => requestDestructive('archived', 'archive this incident')}
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
          <ExportIncidentButton
            incident={incident}
            notes={notesData?.notes ?? []}
          />
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

      {/* Server-side notes (FR #19) */}
      <NotesPanel incidentId={incident.id} />

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

      {pending && (
        <ConfirmDialog
          message={`Are you sure you want to ${pending.label}?`}
          onConfirm={confirmChange}
          onCancel={() => setPending(null)}
        />
      )}
    </div>
  );
}
