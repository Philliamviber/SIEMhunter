import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import clsx from 'clsx';
import { useIncidents, useCreateIncident } from '../hooks/useApi';
import { useIncidentContext } from '../context/IncidentContext';
import { SeverityBadge } from '../components/SeverityBadge';
import { DataTable } from '../components/DataTable';
import type { ColumnDef } from '../components/DataTable';
import { formatTimestamp } from '../utils/formatTimestamp';
import type { Incident, IncidentSeverity } from '../types/api';
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
        'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium uppercase tracking-wide',
        STATUS_CLASSES[status] ?? 'bg-gray-600/20 text-gray-400 border border-gray-600/40',
      )}
    >
      {status}
    </span>
  );
}

// ── New Incident Form Modal ───────────────────────────────────────────────────

interface NewIncidentFormProps {
  onClose: () => void;
}

function NewIncidentForm({ onClose }: NewIncidentFormProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<IncidentSeverity>('medium');
  const [error, setError] = useState<string | null>(null);

  const { mutate: createIncident, isPending } = useCreateIncident();

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) {
      setError('Name is required.');
      return;
    }
    setError(null);
    createIncident(
      {
        name: name.trim(),
        description: description.trim() || undefined,
        severity,
      },
      {
        onSuccess: () => onClose(),
        onError: (err) => setError(err instanceof Error ? err.message : 'Failed to create incident.'),
      },
    );
  }

  return (
    /* Modal backdrop */
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-md shadow-2xl p-6">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-white font-semibold text-base">New Incident</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-200 transition-colors"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5">
              Name <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Incident name"
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-blue-500"
              autoFocus
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5">Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional description"
              rows={3}
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-blue-500 resize-none"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5">Severity</label>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as IncidentSeverity)}
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-blue-500"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>

          {error && (
            <p className="text-red-400 text-xs">{error}</p>
          )}

          <div className="flex gap-3 justify-end pt-1">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-gray-400 hover:text-gray-200 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isPending}
              className="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-md font-medium transition-colors"
            >
              {isPending ? 'Creating...' : 'Create Incident'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function IncidentsPage() {
  const navigate = useNavigate();
  const [showForm, setShowForm] = useState(false);
  const { activeIncidentId, setActiveIncidentId } = useIncidentContext();
  const { data, isLoading, isError } = useIncidents();

  const incidents = data?.incidents ?? [];

  const columns: ColumnDef<Incident>[] = [
    {
      key: 'name',
      header: 'Name',
      render: (row) => (
        <span className="text-white font-medium">{row.name}</span>
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      render: (row) => <SeverityBadge severity={row.severity} />,
    },
    {
      key: 'status',
      header: 'Status',
      render: (row) => <StatusBadge status={row.status} />,
    },
    {
      key: 'event_count',
      header: 'Events',
      render: (row) => (
        <span className="text-gray-300 font-mono text-xs">{row.event_count}</span>
      ),
    },
    {
      key: 'created_at',
      header: 'Created',
      render: (row) => (
        <span className="text-gray-400 text-xs whitespace-nowrap">{formatTimestamp(row.created_at)}</span>
      ),
    },
    {
      key: 'actions',
      header: '',
      render: (row) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            setActiveIncidentId(row.id === activeIncidentId ? null : row.id);
          }}
          className={clsx(
            'px-2.5 py-1 rounded text-xs font-medium transition-colors',
            row.id === activeIncidentId
              ? 'bg-blue-600/30 text-blue-400 border border-blue-600/40 hover:bg-blue-600/20'
              : 'bg-gray-800 text-gray-400 border border-gray-700 hover:bg-gray-700 hover:text-white',
          )}
        >
          {row.id === activeIncidentId ? 'Active' : 'Set Active'}
        </button>
      ),
    },
  ];

  return (
    <div className="p-6 flex flex-col gap-5">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Incidents</h1>
        <button
          onClick={() => setShowForm(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-md transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          New Incident
        </button>
      </div>

      {isError && (
        <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-4 text-red-400 text-sm">
          Failed to load incidents.
        </div>
      )}

      <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
        <DataTable
          columns={columns}
          rows={incidents}
          keyFn={(row) => row.id}
          loading={isLoading}
          emptyMessage="No incidents found. Create one to get started."
          onRowClick={(row) => navigate(`/incidents/${row.id}`)}
        />
      </div>

      {showForm && <NewIncidentForm onClose={() => setShowForm(false)} />}

      <ClaudeChatbar />
    </div>
  );
}
