import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import clsx from 'clsx';
import { api } from '../api/client';
import type { SecurityEvent } from '../types/api';
import { DataTable } from '../components/DataTable';
import type { ColumnDef } from '../components/DataTable';
import { EventDetailPanel } from '../components/EventDetailPanel';
import { formatTimestamp } from '../utils/formatTimestamp';

// ── Category definitions ──────────────────────────────────────────────────────

interface Category {
  id: string;
  name: string;
  description: string;
  color: 'blue' | 'green' | 'yellow' | 'orange' | 'red' | 'purple';
  filter: string;
}

const CATEGORIES: Category[] = [
  {
    id: 'active-directory',
    name: 'Active Directory',
    description: 'Account management, Kerberos, logon events',
    color: 'blue',
    filter: `EventID IN (4720,4722,4724,4725,4726,4728,4732,4756,4768,4769,4771,4776) OR ChannelName = 'Security'`,
  },
  {
    id: 'network',
    name: 'Network',
    description: 'Network connections and protocol events',
    color: 'green',
    filter: `NetworkProtocol != '' OR SrcIpAddr != ''`,
  },
  {
    id: 'dns',
    name: 'DNS',
    description: 'DNS query and resolution events',
    color: 'yellow',
    filter: `EventID IN (4,3008) OR ServiceName LIKE '%dns%'`,
  },
  {
    id: 'network-analysis',
    name: 'Network Analysis',
    description: 'HTTP/HTTPS traffic with source IPs',
    color: 'orange',
    filter: `DstPort IN (80,443,8080,8443) AND SrcIpAddr != ''`,
  },
  {
    id: 'malware-analysis',
    name: 'Malware Analysis',
    description: 'File hashes, suspicious commands, scripting',
    color: 'red',
    filter: `FileSHA256 != '' OR FileMD5 != '' OR CommandLine LIKE '%powershell%' OR CommandLine LIKE '%cmd.exe%'`,
  },
  {
    id: 'log-analysis',
    name: 'Log Analysis',
    description: 'All manually uploaded evidence',
    color: 'purple',
    filter: `ProvenanceTag != ''`,
  },
];

// ── Color maps ────────────────────────────────────────────────────────────────

const BORDER_COLOR: Record<Category['color'], string> = {
  blue: 'border-blue-500',
  green: 'border-green-500',
  yellow: 'border-yellow-400',
  orange: 'border-orange-500',
  red: 'border-red-500',
  purple: 'border-purple-500',
};

const TEXT_COLOR: Record<Category['color'], string> = {
  blue: 'text-blue-400',
  green: 'text-green-400',
  yellow: 'text-yellow-400',
  orange: 'text-orange-400',
  red: 'text-red-400',
  purple: 'text-purple-400',
};

const BADGE_COLOR: Record<Category['color'], string> = {
  blue: 'bg-blue-900/40 text-blue-300',
  green: 'bg-green-900/40 text-green-300',
  yellow: 'bg-yellow-900/40 text-yellow-300',
  orange: 'bg-orange-900/40 text-orange-300',
  red: 'bg-red-900/40 text-red-300',
  purple: 'bg-purple-900/40 text-purple-300',
};

// ── CategoryCard ──────────────────────────────────────────────────────────────

interface CategoryCardProps {
  category: Category;
  count: number | null;
  countLoading: boolean;
  isSelected: boolean;
  onClick: () => void;
}

function CategoryCard({ category, count, countLoading, isSelected, onClick }: CategoryCardProps) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        'text-left w-full rounded-lg bg-gray-900 border-l-4 border border-gray-800 p-4 transition-all',
        BORDER_COLOR[category.color],
        isSelected
          ? 'ring-1 ring-gray-600 bg-gray-800/60'
          : 'hover:bg-gray-800/40 hover:border-gray-700',
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className={clsx('text-sm font-semibold truncate', TEXT_COLOR[category.color])}>
            {category.name}
          </h3>
          <p className="text-gray-400 text-xs mt-0.5 leading-snug">{category.description}</p>
        </div>
        <div
          className={clsx(
            'flex-shrink-0 rounded px-2 py-0.5 text-xs font-mono font-medium min-w-[3rem] text-right',
            BADGE_COLOR[category.color],
          )}
        >
          {countLoading ? (
            <span className="inline-block h-3 w-8 bg-gray-700 rounded animate-pulse" />
          ) : count === null ? (
            '—'
          ) : (
            count.toLocaleString()
          )}
        </div>
      </div>
      <div className={clsx('mt-3 text-xs font-medium', TEXT_COLOR[category.color])}>
        View Events &rarr;
      </div>
    </button>
  );
}

// ── Drill-down table columns ──────────────────────────────────────────────────

const COLUMNS: ColumnDef<SecurityEvent>[] = [
  {
    key: 'TimeGenerated',
    header: 'Time',
    render: (row) => (
      <span className="font-mono text-xs whitespace-nowrap">{formatTimestamp(row.TimeGenerated)}</span>
    ),
    className: 'min-w-[200px]',
  },
  {
    key: 'HostName',
    header: 'Host',
    render: (row) => <span className="font-mono text-xs">{row.HostName || '—'}</span>,
  },
  {
    key: 'EventID',
    header: 'EID',
    render: (row) => <span className="font-mono text-xs">{row.EventID || '—'}</span>,
    className: 'w-16',
  },
  {
    key: 'SubjectUserName',
    header: 'User',
    render: (row) => <span className="font-mono text-xs">{row.SubjectUserName || '—'}</span>,
  },
  {
    key: 'SrcIpAddr',
    header: 'Src IP',
    render: (row) => <span className="font-mono text-xs">{row.SrcIpAddr || '—'}</span>,
  },
  {
    key: 'ProvenanceTag',
    header: 'Source',
    render: (row) => (
      <span className="font-mono text-xs text-gray-400">{row.ProvenanceTag || '—'}</span>
    ),
  },
];

// ── Category event query SQL ──────────────────────────────────────────────────

function buildCountSql(filter: string): string {
  return `SELECT COUNT(*) AS cnt FROM siemhunter.security_events WHERE ${filter}`;
}

function buildEventsSql(filter: string): string {
  return (
    `SELECT TimeGenerated, HostName, EventID, EventRecordID, ChannelName, SubjectUserName, ` +
    `SrcIpAddr, DstIpAddr, CommandLine, ProvenanceTag, UnmappedFields, IngestTimestamp, ` +
    `EventRecordID, ProviderName, SubjectUserSid, SubjectDomainName, TargetUserName, ` +
    `TargetUserSid, TargetDomainName, LogonType, ServiceName, ProcessImagePath, ` +
    `ParentProcessImagePath, ParentCommandLine, GrantedAccess, ObjectName, FileMD5, ` +
    `FileSHA256, RegistryKey, SrcPort, DstPort, NetworkProtocol ` +
    `FROM siemhunter.security_events WHERE ${filter} ORDER BY TimeGenerated DESC LIMIT 500`
  );
}

// ── CategoryDashboardPage ─────────────────────────────────────────────────────

export function CategoryDashboardPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [counts, setCounts] = useState<Record<string, number | null>>({});
  const [countsLoading, setCountsLoading] = useState<Record<string, boolean>>({});
  const [drillEvents, setDrillEvents] = useState<SecurityEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  // useMutation for drill-down events fetch
  const drillMutation = useMutation({
    mutationFn: (sql: string) => api.query({ sql }),
    onSuccess: (data) => {
      const rows = (data.rows ?? []).map(
        (r) => r as unknown as SecurityEvent,
      );
      setDrillEvents(rows);
    },
  });

  // useMutation for count fetch (called per category on mount via handleCountFetch)
  const countMutation = useMutation({
    mutationFn: ({ categoryId, sql }: { categoryId: string; sql: string }) =>
      api.query({ sql }).then((res) => ({ categoryId, res })),
    onSuccess: ({ categoryId, res }) => {
      const row = res.rows[0];
      const cnt = row ? Number(row['cnt'] ?? row['COUNT(*)'] ?? 0) : 0;
      setCounts((prev) => ({ ...prev, [categoryId]: cnt }));
      setCountsLoading((prev) => ({ ...prev, [categoryId]: false }));
    },
    onError: (_err, { categoryId }) => {
      setCounts((prev) => ({ ...prev, [categoryId]: null }));
      setCountsLoading((prev) => ({ ...prev, [categoryId]: false }));
    },
  });

  // Fetch all category counts on first render (tracked to avoid re-fires)
  const [countsFetched, setCountsFetched] = useState(false);
  if (!countsFetched) {
    setCountsFetched(true);
    for (const cat of CATEGORIES) {
      setCountsLoading((prev) => ({ ...prev, [cat.id]: true }));
      countMutation.mutate({ categoryId: cat.id, sql: buildCountSql(cat.filter) });
    }
  }

  function handleCardClick(cat: Category) {
    if (selectedId === cat.id) {
      // Collapse
      setSelectedId(null);
      setDrillEvents([]);
      setSelectedEvent(null);
      return;
    }
    setSelectedId(cat.id);
    setSelectedEvent(null);
    setDrillEvents([]);
    drillMutation.mutate(buildEventsSql(cat.filter));
  }

  const selectedCategory = CATEGORIES.find((c) => c.id === selectedId) ?? null;

  return (
    <div className="p-6 space-y-6">
      {/* Page header */}
      <div>
        <h1 className="text-white text-xl font-bold tracking-tight">Category Dashboard</h1>
        <p className="text-gray-400 text-sm mt-0.5">
          Browse security events by category. Click a card to drill down.
        </p>
      </div>

      {/* 2x3 grid */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
        {CATEGORIES.map((cat) => (
          <CategoryCard
            key={cat.id}
            category={cat}
            count={counts[cat.id] ?? null}
            countLoading={countsLoading[cat.id] ?? false}
            isSelected={selectedId === cat.id}
            onClick={() => handleCardClick(cat)}
          />
        ))}
      </div>

      {/* Drill-down section */}
      {selectedId && selectedCategory && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          {/* Section header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
            <h2 className={clsx('text-sm font-semibold', TEXT_COLOR[selectedCategory.color])}>
              {selectedCategory.name} Events
            </h2>
            <div className="flex items-center gap-3">
              {drillMutation.isPending && (
                <span className="text-xs text-gray-500 animate-pulse">Loading...</span>
              )}
              {!drillMutation.isPending && drillMutation.isSuccess && (
                <span className="text-xs text-gray-500">
                  {drillEvents.length} row{drillEvents.length !== 1 ? 's' : ''}
                  {drillEvents.length === 500 ? ' (limit reached)' : ''}
                </span>
              )}
              <button
                onClick={() => {
                  setSelectedId(null);
                  setDrillEvents([]);
                  setSelectedEvent(null);
                }}
                className="text-gray-500 hover:text-gray-300 p-1 rounded"
                aria-label="Collapse"
              >
                <svg
                  className="w-4 h-4"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  strokeWidth={2}
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </div>

          {/* Error state */}
          {drillMutation.isError && (
            <div className="px-4 py-6 text-center text-red-400 text-sm">
              Failed to load events. Please try again.
            </div>
          )}

          {/* Table */}
          {!drillMutation.isError && (
            <DataTable<SecurityEvent>
              columns={COLUMNS}
              rows={drillEvents}
              keyFn={(row) =>
                `${row.EventRecordID}-${row.TimeGenerated}-${row.HostName}`
              }
              loading={drillMutation.isPending}
              emptyMessage={
                drillMutation.isSuccess
                  ? 'No events match this category filter.'
                  : 'Select a category to view events.'
              }
              onRowClick={(row) => setSelectedEvent(row)}
              selectedKey={
                selectedEvent
                  ? `${selectedEvent.EventRecordID}-${selectedEvent.TimeGenerated}-${selectedEvent.HostName}`
                  : undefined
              }
            />
          )}
        </div>
      )}

      {/* Event detail panel */}
      {selectedEvent && (
        <EventDetailPanel
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}

    </div>
  );
}
