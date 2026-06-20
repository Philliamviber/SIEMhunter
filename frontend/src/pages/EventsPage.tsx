import { useState } from 'react';
import { useEvents } from '../hooks/useApi';
import { DataTable, Pagination } from '../components/DataTable';
import type { ColumnDef } from '../components/DataTable';
import type { SecurityEvent, EventsFilter } from '../types/api';

const PAGE_SIZE = 50;

function formatTime(iso: string): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

// ── Drill-in panel ────────────────────────────────────────────────────────────

function EventDetailPanel({ event, onClose }: { event: SecurityEvent; onClose: () => void }) {
  let unmappedParsed: unknown = null;
  try {
    if (event.UnmappedFields && event.UnmappedFields !== '{}' && event.UnmappedFields !== '') {
      unmappedParsed = JSON.parse(event.UnmappedFields);
    }
  } catch {
    // show raw
  }

  const fields: [string, string][] = [
    ['TimeGenerated', formatTime(event.TimeGenerated)],
    ['HostName', event.HostName],
    ['EventID', String(event.EventID)],
    ['EventRecordID', event.EventRecordID],
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
    ['IngestTimestamp', formatTime(event.IngestTimestamp)],
  ];

  return (
    <div className="fixed inset-y-0 right-0 w-[480px] bg-gray-900 border-l border-gray-800 overflow-y-auto z-50 shadow-2xl">
      <div className="px-5 py-4 border-b border-gray-800 flex items-center justify-between sticky top-0 bg-gray-900">
        <div>
          <h3 className="text-white font-semibold text-sm">Event Detail</h3>
          <p className="text-gray-500 text-xs font-mono mt-0.5">EID {event.EventID} · {event.HostName}</p>
        </div>
        <button
          onClick={onClose}
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

        {/* Governance note — no AnomalyScore per event */}
        <div className="mt-4 bg-gray-800/50 rounded p-3 text-xs text-gray-500">
          AnomalyScore is not available on security events — it lives on detection hits only.
        </div>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

const TABLE_COLS: ColumnDef<SecurityEvent>[] = [
  {
    key: 'TimeGenerated',
    header: 'Time',
    render: (r) => (
      <span className="text-gray-300 text-xs whitespace-nowrap">{formatTime(r.TimeGenerated)}</span>
    ),
  },
  {
    key: 'HostName',
    header: 'Host',
    render: (r) => <span className="font-mono text-xs text-gray-200">{r.HostName || '—'}</span>,
  },
  {
    key: 'EventID',
    header: 'EID',
    render: (r) => <span className="font-mono text-xs text-cyan-400">{r.EventID}</span>,
  },
  {
    key: 'SubjectUserName',
    header: 'User',
    render: (r) => <span className="text-xs text-gray-300">{r.SubjectUserName || '—'}</span>,
  },
  {
    key: 'SrcIpAddr',
    header: 'Src IP',
    render: (r) => <span className="font-mono text-xs text-gray-300">{r.SrcIpAddr || '—'}</span>,
  },
  {
    key: 'ProvenanceTag',
    header: 'Source',
    render: (r) => (
      <span className="text-xs text-purple-400 font-mono">{r.ProvenanceTag || '—'}</span>
    ),
  },
];

export function EventsPage() {
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const [form, setForm] = useState<EventsFilter>({});
  const [applied, setApplied] = useState<EventsFilter>({});

  const filter: EventsFilter = { ...applied, limit: PAGE_SIZE, offset };
  const { data, isLoading, isError } = useEvents(filter);

  function applyFilters() {
    setOffset(0);
    setApplied({ ...form });
  }

  function clearFilters() {
    setForm({});
    setApplied({});
    setOffset(0);
  }

  return (
    <div className="p-6 flex flex-col gap-5">
      <h1 className="text-xl font-bold text-white">Security Events</h1>

      {/* Filters */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <div>
            <label className="block text-xs text-gray-400 mb-1">Start</label>
            <input
              type="datetime-local"
              value={form.start ?? ''}
              onChange={(e) => setForm((f) => ({ ...f, start: e.target.value || undefined }))}
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-white text-xs"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">End</label>
            <input
              type="datetime-local"
              value={form.end ?? ''}
              onChange={(e) => setForm((f) => ({ ...f, end: e.target.value || undefined }))}
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-white text-xs"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Hostname</label>
            <input
              type="text"
              value={form.hostname ?? ''}
              onChange={(e) => setForm((f) => ({ ...f, hostname: e.target.value || undefined }))}
              placeholder="dc01"
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-white text-xs"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Event ID</label>
            <input
              type="number"
              value={form.event_id ?? ''}
              onChange={(e) =>
                setForm((f) => ({ ...f, event_id: e.target.value ? Number(e.target.value) : undefined }))
              }
              placeholder="4624"
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-white text-xs"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Username</label>
            <input
              type="text"
              value={form.subject_user_name ?? ''}
              onChange={(e) =>
                setForm((f) => ({ ...f, subject_user_name: e.target.value || undefined }))
              }
              placeholder="SYSTEM"
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-white text-xs"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Src IP</label>
            <input
              type="text"
              value={form.src_ip_addr ?? ''}
              onChange={(e) =>
                setForm((f) => ({ ...f, src_ip_addr: e.target.value || undefined }))
              }
              placeholder="192.168.1.1"
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-white text-xs"
            />
          </div>
        </div>
        <div className="flex items-center gap-2 mt-3">
          <div className="flex-1">
            <label className="block text-xs text-gray-400 mb-1">Provenance Tag</label>
            <input
              type="text"
              value={form.provenance_tag ?? ''}
              onChange={(e) =>
                setForm((f) => ({ ...f, provenance_tag: e.target.value || undefined }))
              }
              placeholder="wef:security"
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-white text-xs"
            />
          </div>
          <div className="flex gap-2 mt-4">
            <button
              onClick={applyFilters}
              className="px-4 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-medium"
            >
              Apply
            </button>
            <button
              onClick={clearFilters}
              className="px-4 py-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded text-xs font-medium"
            >
              Clear
            </button>
          </div>
        </div>
      </div>

      {isError && (
        <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-4 text-red-400 text-sm">
          Failed to load events — check API connectivity and token validity.
        </div>
      )}

      {/* Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
        <DataTable
          columns={TABLE_COLS}
          rows={data?.events ?? []}
          keyFn={(r) => r.EventRecordID || `${r.TimeGenerated}-${r.EventID}`}
          loading={isLoading}
          emptyMessage="No events match the current filters"
          onRowClick={setSelected}
          selectedKey={selected ? (selected.EventRecordID || `${selected.TimeGenerated}-${selected.EventID}`) : undefined}
        />
        <Pagination
          offset={offset}
          limit={PAGE_SIZE}
          total={data?.total_count ?? 0}
          onPrev={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
          onNext={() => setOffset((o) => o + PAGE_SIZE)}
        />
      </div>

      {/* Detail panel */}
      {selected && (
        <EventDetailPanel event={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}
