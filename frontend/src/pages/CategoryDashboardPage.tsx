import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
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

const DRILL_LIMIT = 500;

function buildCountSql(filter: string): string {
  return `SELECT COUNT(*) AS cnt FROM siemhunter.security_events WHERE ${filter}`;
}

function buildEventsSql(filter: string, offset = 0): string {
  const base =
    `SELECT TimeGenerated, HostName, EventID, EventRecordID, ChannelName, SubjectUserName, ` +
    `SrcIpAddr, DstIpAddr, CommandLine, ProvenanceTag, UnmappedFields, IngestTimestamp, ` +
    `EventRecordID, ProviderName, SubjectUserSid, SubjectDomainName, TargetUserName, ` +
    `TargetUserSid, TargetDomainName, LogonType, ServiceName, ProcessImagePath, ` +
    `ParentProcessImagePath, ParentCommandLine, GrantedAccess, ObjectName, FileMD5, ` +
    `FileSHA256, RegistryKey, SrcPort, DstPort, NetworkProtocol ` +
    `FROM siemhunter.security_events WHERE ${filter} ORDER BY TimeGenerated DESC LIMIT ${DRILL_LIMIT}`;
  return offset > 0 ? `${base} OFFSET ${offset}` : base;
}

// ── CategoryDashboardPage ─────────────────────────────────────────────────────

export function CategoryDashboardPage() {
  const navigate = useNavigate();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [counts, setCounts] = useState<Record<string, number | null>>({});
  const [countsLoading, setCountsLoading] = useState<Record<string, boolean>>({});
  const [drillEvents, setDrillEvents] = useState<SecurityEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  // True when the last page fetch returned exactly DRILL_LIMIT rows (more may exist)
  const [hasMore, setHasMore] = useState(false);

  // useMutation for drill-down events fetch (initial load — replaces drillEvents)
  const drillMutation = useMutation({
    mutationFn: (sql: string) => api.query({ sql }),
    onSuccess: (data) => {
      const rows = (data.rows ?? []).map(
        (r) => r as unknown as SecurityEvent,
      );
      setDrillEvents(rows);
      setHasMore(rows.length === DRILL_LIMIT);
    },
  });

  // useMutation for load-more (appends to drillEvents)
  const loadMoreMutation = useMutation({
    mutationFn: (sql: string) => api.query({ sql }),
    onSuccess: (data) => {
      const rows = (data.rows ?? []).map(
        (r) => r as unknown as SecurityEvent,
      );
      setDrillEvents((prev) => [...prev, ...rows]);
      setHasMore(rows.length === DRILL_LIMIT);
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
      setHasMore(false);
      return;
    }
    setSelectedId(cat.id);
    setSelectedEvent(null);
    setDrillEvents([]);
    setHasMore(false);
    drillMutation.mutate(buildEventsSql(cat.filter));
  }

  function handleLoadMore() {
    if (!selectedCategory) return;
    loadMoreMutation.mutate(buildEventsSql(selectedCategory.filter, drillEvents.length));
  }

  function handleRefine() {
    if (!selectedCategory) return;
    const sql = buildEventsSql(selectedCategory.filter);
    navigate(`/query?sql=${encodeURIComponent(sql)}`);
  }

  function handleRetry() {
    if (!selectedCategory) return;
    setDrillEvents([]);
    setHasMore(false);
    drillMutation.mutate(buildEventsSql(selectedCategory.filter));
  }

  const selectedCategory = CATEGORIES.find((c) => c.id === selectedId) ?? null;
  const totalCount = selectedId != null ? (counts[selectedId] ?? null) : null;
  const isLoading = drillMutation.isPending;
  const isError = drillMutation.isError && !loadMoreMutation.isPending;
  const isEmpty = drillMutation.isSuccess && drillEvents.length === 0;

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
              {isLoading && (
                <span className="text-xs text-gray-500 animate-pulse">Loading...</span>
              )}
              {!isLoading && drillMutation.isSuccess && drillEvents.length > 0 && (
                <span className="text-xs text-gray-500" data-testid="drill-row-count">
                  {drillEvents.length.toLocaleString()} row{drillEvents.length !== 1 ? 's' : ''}
                </span>
              )}
              <button
                onClick={() => {
                  setSelectedId(null);
                  setDrillEvents([]);
                  setSelectedEvent(null);
                  setHasMore(false);
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

          {/* Truncation banner — shown when the result set is truncated */}
          {!isLoading && hasMore && (
            <div
              className="flex items-center justify-between gap-4 px-4 py-2.5 bg-amber-900/20 border-b border-amber-700/30"
              data-testid="truncation-banner"
            >
              <p className="text-amber-300 text-xs">
                Showing{' '}
                <span className="font-semibold font-mono">{drillEvents.length.toLocaleString()}</span>
                {totalCount != null && totalCount > drillEvents.length ? (
                  <>
                    {' '}of{' '}
                    <span className="font-semibold font-mono">{totalCount.toLocaleString()}</span>
                  </>
                ) : null}{' '}
                events — results are truncated.
              </p>
              <div className="flex items-center gap-2 flex-shrink-0">
                <button
                  onClick={handleRefine}
                  className="px-2.5 py-1 text-xs rounded border border-amber-700/50 text-amber-300 hover:bg-amber-900/40 transition-colors"
                  aria-label="Refine in Query Builder"
                >
                  Refine in Query Builder
                </button>
                <button
                  onClick={handleLoadMore}
                  disabled={loadMoreMutation.isPending}
                  className="px-2.5 py-1 text-xs rounded bg-amber-700/30 hover:bg-amber-700/50 text-amber-200 font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-1"
                  aria-label="Load more events"
                >
                  {loadMoreMutation.isPending && (
                    <svg className="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  )}
                  Load More
                </button>
              </div>
            </div>
          )}

          {/* Error state */}
          {isError && (
            <div
              className="flex flex-col items-center gap-3 px-4 py-10 text-center"
              data-testid="drill-error-state"
              role="alert"
            >
              <svg className="w-8 h-8 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
              </svg>
              <div>
                <p className="text-red-400 text-sm font-medium">Failed to load events</p>
                <p className="text-gray-500 text-xs mt-1">Check API connectivity and try again.</p>
              </div>
              <button
                onClick={handleRetry}
                className="mt-1 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-xs border border-gray-700"
              >
                Retry
              </button>
            </div>
          )}

          {/* Empty state */}
          {isEmpty && (
            <div
              className="flex flex-col items-center gap-3 px-4 py-10 text-center"
              data-testid="drill-empty-state"
            >
              <svg className="w-8 h-8 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 9.776c.112-.017.227-.026.344-.026h15.812c.117 0 .232.009.344.026m-16.5 0a2.25 2.25 0 00-1.883 2.542l.857 6a2.25 2.25 0 002.227 1.932H19.05a2.25 2.25 0 002.227-1.932l.857-6a2.25 2.25 0 00-1.883-2.542m-16.5 0V6A2.25 2.25 0 016 3.75h3.879a1.5 1.5 0 011.06.44l2.122 2.12a1.5 1.5 0 001.06.44H18A2.25 2.25 0 0120.25 9v.776" />
              </svg>
              <div>
                <p className="text-gray-400 text-sm font-medium">No events found</p>
                <p className="text-gray-600 text-xs mt-1">
                  No events match the <span className={clsx('font-medium', TEXT_COLOR[selectedCategory.color])}>{selectedCategory.name}</span> filter.
                </p>
              </div>
            </div>
          )}

          {/* Table — shown when not in error or empty state */}
          {!isError && !isEmpty && (
            <DataTable<SecurityEvent>
              columns={COLUMNS}
              rows={drillEvents}
              keyFn={(row) =>
                `${row.EventRecordID}-${row.TimeGenerated}-${row.HostName}`
              }
              loading={isLoading}
              emptyMessage="Select a category to view events."
              onRowClick={(row) => setSelectedEvent(row)}
              selectedKey={
                selectedEvent
                  ? `${selectedEvent.EventRecordID}-${selectedEvent.TimeGenerated}-${selectedEvent.HostName}`
                  : undefined
              }
            />
          )}

          {/* Load-more error inline */}
          {loadMoreMutation.isError && (
            <div
              className="px-4 py-3 border-t border-gray-800 text-center text-xs text-red-400"
              role="alert"
            >
              Failed to load more events. Please try again.
            </div>
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
