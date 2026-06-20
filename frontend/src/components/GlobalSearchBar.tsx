import { useState, useCallback } from 'react';
import clsx from 'clsx';
import { useSearch } from '../hooks/useApi';
import { useIncidentContext } from '../context/IncidentContext';
import { DataTable } from './DataTable';
import { EventDetailPanel } from './EventDetailPanel';
import type { SearchFieldType, SecurityEvent } from '../types/api';
import { formatTimestamp } from '../utils/formatTimestamp';
import { ApiClientError } from '../api/client';

// ── Field type options ────────────────────────────────────────────────────────

interface FieldOption {
  label: string;
  value: SearchFieldType;
  placeholder: string;
}

const FIELD_OPTIONS: FieldOption[] = [
  { label: 'IP Address',    value: 'IP',          placeholder: 'e.g. 192.168.1.1' },
  { label: 'Hostname',      value: 'Hostname',    placeholder: 'e.g. WORKSTATION01' },
  { label: 'Username',      value: 'Username',    placeholder: 'e.g. jsmith' },
  { label: 'TCP Port',      value: 'Port',        placeholder: 'e.g. 443' },
  { label: 'Event ID',      value: 'EventID',     placeholder: 'e.g. 4624' },
  { label: 'File Hash',     value: 'FileHash',    placeholder: 'MD5 (32 hex) or SHA-256 (64 hex)' },
  { label: 'Process Name',  value: 'ProcessName', placeholder: 'e.g. cmd.exe (prefix match)' },
];

// ── Error code → plain-English message ────────────────────────────────────────
// Raw ClickHouse errors are never shown to the user (AC#9).

const ERROR_MESSAGES: Record<string, string> = {
  UNKNOWN_FIELD_TYPE:   'The selected field type is not supported.',
  EMPTY_SEARCH_VALUE:   'Search value cannot be empty.',
  INVALID_DATETIME:     'The time range contains an invalid date.',
  INVALID_TIME_RANGE:   'Start time must be before end time.',
  TIME_RANGE_TOO_LARGE: 'Time range cannot exceed 30 days.',
  INVALID_PORT:         'Port must be an integer between 1 and 65535.',
  INVALID_EVENT_ID:     'Event ID must be a non-negative integer.',
  INVALID_HASH:         'File hash must contain only hexadecimal characters.',
  INVALID_HASH_LENGTH:  'File hash must be 32 characters (MD5) or 64 characters (SHA-256).',
  INVALID_INCIDENT_ID:  'Invalid incident ID format.',
  QUERY_TIMEOUT:        'Search timed out. Try narrowing your time range.',
  QUERY_ERROR:          'The search could not be completed. Please try again.',
  AUTH_REQUIRED:        'Authentication required. Please log in again.',
};

function friendlyError(err: unknown): string {
  if (err instanceof ApiClientError) {
    return ERROR_MESSAGES[err.code] ?? 'An unexpected error occurred. Please try again.';
  }
  if (err instanceof Error) {
    return 'An unexpected error occurred. Please try again.';
  }
  return 'An unexpected error occurred.';
}

// ── Result table columns ───────────────────────────────────────────────────────

function toSecurityEvent(row: Record<string, unknown>): SecurityEvent {
  // Cast raw ClickHouse row to SecurityEvent, supplying empty-string / zero defaults
  // for any fields that may be absent so EventDetailPanel never receives undefined.
  return {
    TimeGenerated:          String(row['TimeGenerated'] ?? ''),
    HostName:               String(row['HostName'] ?? ''),
    EventID:                Number(row['EventID'] ?? 0),
    EventRecordID:          String(row['EventRecordID'] ?? ''),
    ChannelName:            String(row['ChannelName'] ?? ''),
    ProviderName:           String(row['ProviderName'] ?? ''),
    SubjectUserName:        String(row['SubjectUserName'] ?? ''),
    SubjectUserSid:         String(row['SubjectUserSid'] ?? ''),
    SubjectDomainName:      String(row['SubjectDomainName'] ?? ''),
    TargetUserName:         String(row['TargetUserName'] ?? ''),
    TargetUserSid:          String(row['TargetUserSid'] ?? ''),
    TargetDomainName:       String(row['TargetDomainName'] ?? ''),
    LogonType:              Number(row['LogonType'] ?? 0),
    ServiceName:            String(row['ServiceName'] ?? ''),
    ProcessImagePath:       String(row['ProcessImagePath'] ?? ''),
    CommandLine:            String(row['CommandLine'] ?? ''),
    ParentProcessImagePath: String(row['ParentProcessImagePath'] ?? ''),
    ParentCommandLine:      String(row['ParentCommandLine'] ?? ''),
    GrantedAccess:          String(row['GrantedAccess'] ?? ''),
    ObjectName:             String(row['ObjectName'] ?? ''),
    FileMD5:                String(row['FileMD5'] ?? ''),
    FileSHA256:             String(row['FileSHA256'] ?? ''),
    RegistryKey:            String(row['RegistryKey'] ?? ''),
    SrcIpAddr:              String(row['SrcIpAddr'] ?? ''),
    SrcPort:                Number(row['SrcPort'] ?? 0),
    DstIpAddr:              String(row['DstIpAddr'] ?? ''),
    DstPort:                Number(row['DstPort'] ?? 0),
    NetworkProtocol:        String(row['NetworkProtocol'] ?? ''),
    ProvenanceTag:          String(row['ProvenanceTag'] ?? ''),
    IngestTimestamp:        String(row['IngestTimestamp'] ?? ''),
    UnmappedFields:         String(row['UnmappedFields'] ?? ''),
  };
}

// ── Component ─────────────────────────────────────────────────────────────────

export function GlobalSearchBar() {
  const [fieldType, setFieldType] = useState<SearchFieldType>('IP');
  const [value, setValue] = useState('');
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [panelOpen, setPanelOpen] = useState(false);
  const [searchAll, setSearchAll] = useState(false);

  const { activeIncidentId, activeIncident } = useIncidentContext();
  const search = useSearch();

  const currentOption = FIELD_OPTIONS.find((o) => o.value === fieldType) ?? FIELD_OPTIONS[0];
  const scopedIncidentId = !searchAll && activeIncidentId ? activeIncidentId : undefined;

  const handleSubmit = useCallback(() => {
    if (!value.trim()) return; // AC#8: never send when empty
    search.mutate({
      field_type: fieldType,
      value: value.trim(),
      ...(scopedIncidentId ? { incident_id: scopedIncidentId } : {}),
    });
  }, [fieldType, value, search, scopedIncidentId]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      handleSubmit();
    }
  };

  const handleClear = () => {
    setValue('');
    search.reset();
    setSelectedEvent(null);
    setPanelOpen(false);
    setSearchAll(false);
  };

  const handleRowClick = (event: SecurityEvent) => {
    setSelectedEvent(event);
    setPanelOpen(true);
  };

  const results = search.data;
  const hasResults = results !== undefined;
  const events = hasResults ? results.rows.map(toSecurityEvent) : [];
  const isEmpty = value.trim().length === 0;

  return (
    <>
      {/* ── Search bar ─────────────────────────────────────────────────────── */}
      <div className="border-b border-gray-800 bg-gray-900/80 px-4 py-2.5">
        <div className="flex items-center gap-2 max-w-5xl flex-wrap">
          {/* Incident scope chip */}
          {activeIncidentId && activeIncident && !searchAll && (
            <div className="flex items-center gap-1 flex-shrink-0 bg-cyan-900/40 border border-cyan-700/50 rounded px-2 py-1 text-xs text-cyan-300">
              <span>Scoped: {activeIncident.name}</span>
              <button
                onClick={() => setSearchAll(true)}
                className="ml-1 text-cyan-500 hover:text-cyan-200 font-medium underline underline-offset-2"
              >
                Search all
              </button>
            </div>
          )}
          {activeIncidentId && searchAll && (
            <div className="flex items-center gap-1 flex-shrink-0 bg-gray-800/60 border border-gray-700 rounded px-2 py-1 text-xs text-gray-400">
              <span>Global search</span>
              <button
                onClick={() => setSearchAll(false)}
                className="ml-1 text-gray-500 hover:text-gray-200 font-medium underline underline-offset-2"
              >
                Restore scope
              </button>
            </div>
          )}
          {/* Field type dropdown */}
          <select
            value={fieldType}
            onChange={(e) => {
              setFieldType(e.target.value as SearchFieldType);
              // Reset results when field type changes
              search.reset();
            }}
            aria-label="Search field type"
            className="bg-gray-800 border border-gray-700 text-gray-200 text-xs rounded px-2 py-1.5 h-8 focus:outline-none focus:ring-1 focus:ring-cyan-500 flex-shrink-0"
          >
            {FIELD_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>

          {/* Value input */}
          <input
            type="text"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={currentOption.placeholder}
            aria-label="Search value"
            className="flex-1 bg-gray-800 border border-gray-700 text-gray-200 text-xs rounded px-3 py-1.5 h-8 focus:outline-none focus:ring-1 focus:ring-cyan-500 placeholder-gray-600 font-mono min-w-0"
          />

          {/* Search button — AC#8: disabled when value is empty */}
          <button
            onClick={handleSubmit}
            disabled={isEmpty || search.isPending}
            className={clsx(
              'flex-shrink-0 px-3 py-1.5 h-8 rounded text-xs font-medium transition-colors',
              isEmpty || search.isPending
                ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                : 'bg-cyan-600 hover:bg-cyan-500 text-white',
            )}
          >
            {search.isPending ? 'Searching…' : 'Search'}
          </button>

          {/* Clear button */}
          {(value || hasResults) && (
            <button
              onClick={handleClear}
              className="flex-shrink-0 px-2 py-1.5 h-8 rounded text-xs text-gray-400 hover:text-gray-200 hover:bg-gray-800 transition-colors"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* ── Results panel ──────────────────────────────────────────────────── */}
      {(hasResults || search.isError) && (
        <div className="border-b border-gray-800 bg-gray-950">
          {/* Error state — AC#9: plain-English only, no raw ClickHouse errors */}
          {search.isError && (
            <div className="flex items-center gap-2 px-4 py-3 text-sm">
              <svg className="w-4 h-4 text-red-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <span className="text-red-300">
                {friendlyError(search.error)}
              </span>
              {search.error instanceof ApiClientError && (
                <span className="text-gray-600 text-xs font-mono">
                  [{search.error.code}]
                </span>
              )}
            </div>
          )}

          {/* Success state */}
          {hasResults && (
            <div>
              {/* Result summary bar */}
              <div className="flex items-center gap-3 px-4 py-2 border-b border-gray-800/60">
                <span className="text-xs text-gray-400">
                  {results.row_count === 0
                    ? 'No events matched'
                    : `${results.row_count.toLocaleString()} event${results.row_count === 1 ? '' : 's'}`}
                </span>
                <span className="text-xs text-gray-600">
                  {results.execution_time_ms.toFixed(0)} ms
                </span>
                <span className="text-xs text-gray-600">
                  searched: {results.columns_searched.join(', ')}
                </span>

                {/* Truncation warning — AC#10 (MUST 10) */}
                {results.truncated && (
                  <span className="text-xs text-amber-400 flex items-center gap-1">
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    Results capped at 10,000 rows — narrow your time range for completeness
                  </span>
                )}
              </div>

              {/* Results table */}
              {results.row_count > 0 && (
                <div className="max-h-72 overflow-y-auto">
                  <DataTable<SecurityEvent>
                    columns={[
                      {
                        key: 'TimeGenerated',
                        header: 'Time',
                        render: (row) => (
                          <span className="font-mono text-xs text-gray-300 whitespace-nowrap">
                            {formatTimestamp(row.TimeGenerated)}
                          </span>
                        ),
                      },
                      {
                        key: 'HostName',
                        header: 'Host',
                        render: (row) => (
                          <span className="font-mono text-xs text-gray-300">{row.HostName}</span>
                        ),
                      },
                      {
                        key: 'EventID',
                        header: 'EID',
                        className: 'w-16',
                        render: (row) => (
                          <span className="font-mono text-xs text-cyan-400">{row.EventID}</span>
                        ),
                      },
                      {
                        key: 'SubjectUserName',
                        header: 'User',
                        render: (row) => (
                          <span className="font-mono text-xs text-gray-300">
                            {row.SubjectUserName || row.TargetUserName || '—'}
                          </span>
                        ),
                      },
                      {
                        key: 'SrcIpAddr',
                        header: 'Src IP',
                        render: (row) => (
                          <span className="font-mono text-xs text-gray-300">
                            {row.SrcIpAddr || '—'}
                          </span>
                        ),
                      },
                      {
                        key: 'ProvenanceTag',
                        header: 'Source',
                        render: (row) => (
                          <span className="font-mono text-xs text-gray-500 truncate max-w-[12rem] block">
                            {row.ProvenanceTag || '—'}
                          </span>
                        ),
                      },
                    ]}
                    rows={events}
                    keyFn={(row) => row.EventRecordID || `${row.TimeGenerated}-${row.EventID}`}
                    emptyMessage="No events matched"
                    onRowClick={handleRowClick}
                    selectedKey={
                      selectedEvent
                        ? selectedEvent.EventRecordID || `${selectedEvent.TimeGenerated}-${selectedEvent.EventID}`
                        : undefined
                    }
                  />
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Event detail panel (slide-in) ──────────────────────────────────── */}
      {panelOpen && selectedEvent && (
        <EventDetailPanel
          event={selectedEvent}
          onClose={() => {
            setPanelOpen(false);
            setSelectedEvent(null);
          }}
        />
      )}
    </>
  );
}
