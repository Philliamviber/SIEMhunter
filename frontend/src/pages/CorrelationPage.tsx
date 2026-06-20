import { useState, useMemo, useCallback } from 'react';
import ReactECharts from 'echarts-for-react';
import type { ECharts } from 'echarts';
import { api, ApiClientError } from '../api/client';
import { EventDetailPanel } from '../components/EventDetailPanel';
import { ClaudeChatbar } from '../components/ClaudeChatbar';
import { formatTimestamp } from '../utils/formatTimestamp';
import type { SecurityEvent } from '../types/api';

// ── Types ─────────────────────────────────────────────────────────────────────

interface GraphNode {
  name: string;
  category: number;
  symbolSize: number;
  label: { show: boolean };
}

interface GraphEdge {
  source: string;
  target: string;
  label: { show: boolean; formatter: string };
}

type TimePreset = '1h' | '6h' | '24h' | '7d';

// ── SQL queries ───────────────────────────────────────────────────────────────

function buildEntityQuery(intervalExpr: string): string {
  return `SELECT DISTINCT
  HostName, SubjectUserName, SrcIpAddr, DstIpAddr, ProcessImagePath
FROM siemhunter.security_events
WHERE TimeGenerated >= now() - INTERVAL ${intervalExpr}
  AND (HostName != '' OR SubjectUserName != '' OR SrcIpAddr != '')
LIMIT 500`;
}

function buildRelationshipQuery(intervalExpr: string): string {
  return `SELECT
  HostName, SubjectUserName, SrcIpAddr, DstIpAddr, EventID, TimeGenerated, EventRecordID,
  ChannelName, ProviderName, TargetUserName, SubjectUserSid, SubjectDomainName,
  TargetUserSid, TargetDomainName, LogonType, ServiceName, ProcessImagePath,
  CommandLine, ParentProcessImagePath, ParentCommandLine, GrantedAccess, ObjectName,
  FileMD5, FileSHA256, RegistryKey, SrcPort, DstPort, NetworkProtocol, ProvenanceTag,
  IngestTimestamp, UnmappedFields
FROM siemhunter.security_events
WHERE TimeGenerated >= now() - INTERVAL ${intervalExpr}
  AND (HostName != '' OR SrcIpAddr != '')
ORDER BY TimeGenerated DESC
LIMIT 1000`;
}

const PRESET_INTERVALS: Record<TimePreset, string> = {
  '1h': '1 HOUR',
  '6h': '6 HOUR',
  '24h': '1 DAY',
  '7d': '7 DAY',
};

const PRESET_LABELS: Record<TimePreset, string> = {
  '1h': 'Last 1h',
  '6h': 'Last 6h',
  '24h': 'Last 24h',
  '7d': 'Last 7d',
};

const NODE_CAP = 200;

// ── Graph data builder ────────────────────────────────────────────────────────

function buildGraphData(rows: Record<string, unknown>[]): {
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
} {
  if (!rows || rows.length === 0) {
    return { nodes: [], edges: [], truncated: false };
  }

  // Collect unique nodes keyed by name
  const nodeMap = new Map<string, number>(); // name → category

  function addNode(value: unknown, category: number) {
    const v = typeof value === 'string' ? value.trim() : '';
    if (v && !nodeMap.has(v)) {
      nodeMap.set(v, category);
    }
  }

  for (const row of rows) {
    addNode(row['HostName'], 0);
    addNode(row['SubjectUserName'], 1);
    addNode(row['TargetUserName'], 1);
    addNode(row['SrcIpAddr'], 2);
    addNode(row['DstIpAddr'], 2);
    addNode(row['ProcessImagePath'], 3);
  }

  const truncated = nodeMap.size > NODE_CAP;

  // Cap nodes to NODE_CAP
  const allowedNodes = new Set<string>();
  let count = 0;
  for (const [name] of nodeMap) {
    if (count >= NODE_CAP) break;
    allowedNodes.add(name);
    count++;
  }

  const nodes: GraphNode[] = [];
  for (const name of allowedNodes) {
    const category = nodeMap.get(name) ?? 0;
    nodes.push({
      name,
      category,
      // hosts and IPs slightly larger
      symbolSize: category === 0 ? 18 : category === 2 ? 16 : 12,
      label: { show: true },
    });
  }

  // Build edges only between allowed nodes
  const edgeSet = new Set<string>();
  const edges: GraphEdge[] = [];

  function addEdge(src: unknown, tgt: unknown, eventId: unknown) {
    const s = typeof src === 'string' ? src.trim() : '';
    const t = typeof tgt === 'string' ? tgt.trim() : '';
    if (!s || !t || s === t) return;
    if (!allowedNodes.has(s) || !allowedNodes.has(t)) return;
    const key = `${s}||${t}`;
    if (edgeSet.has(key)) return;
    edgeSet.add(key);
    const eid = eventId !== null && eventId !== undefined ? String(eventId) : '';
    edges.push({
      source: s,
      target: t,
      label: { show: Boolean(eid), formatter: eid },
    });
  }

  for (const row of rows) {
    const eid = row['EventID'];
    addEdge(row['HostName'], row['SubjectUserName'], eid);
    addEdge(row['HostName'], row['SrcIpAddr'], eid);
    addEdge(row['SrcIpAddr'], row['DstIpAddr'], eid);
    addEdge(row['HostName'], row['ProcessImagePath'], eid);
  }

  return { nodes, edges, truncated };
}

// ── Row → SecurityEvent coercion ──────────────────────────────────────────────

function rowToEvent(row: Record<string, unknown>): SecurityEvent {
  return {
    TimeGenerated: String(row['TimeGenerated'] ?? ''),
    HostName: String(row['HostName'] ?? ''),
    EventID: Number(row['EventID'] ?? 0),
    EventRecordID: String(row['EventRecordID'] ?? ''),
    ChannelName: String(row['ChannelName'] ?? ''),
    ProviderName: String(row['ProviderName'] ?? ''),
    SubjectUserName: String(row['SubjectUserName'] ?? ''),
    SubjectUserSid: String(row['SubjectUserSid'] ?? ''),
    SubjectDomainName: String(row['SubjectDomainName'] ?? ''),
    TargetUserName: String(row['TargetUserName'] ?? ''),
    TargetUserSid: String(row['TargetUserSid'] ?? ''),
    TargetDomainName: String(row['TargetDomainName'] ?? ''),
    LogonType: Number(row['LogonType'] ?? 0),
    ServiceName: String(row['ServiceName'] ?? ''),
    ProcessImagePath: String(row['ProcessImagePath'] ?? ''),
    CommandLine: String(row['CommandLine'] ?? ''),
    ParentProcessImagePath: String(row['ParentProcessImagePath'] ?? ''),
    ParentCommandLine: String(row['ParentCommandLine'] ?? ''),
    GrantedAccess: String(row['GrantedAccess'] ?? ''),
    ObjectName: String(row['ObjectName'] ?? ''),
    FileMD5: String(row['FileMD5'] ?? ''),
    FileSHA256: String(row['FileSHA256'] ?? ''),
    RegistryKey: String(row['RegistryKey'] ?? ''),
    SrcIpAddr: String(row['SrcIpAddr'] ?? ''),
    SrcPort: Number(row['SrcPort'] ?? 0),
    DstIpAddr: String(row['DstIpAddr'] ?? ''),
    DstPort: Number(row['DstPort'] ?? 0),
    NetworkProtocol: String(row['NetworkProtocol'] ?? ''),
    ProvenanceTag: String(row['ProvenanceTag'] ?? ''),
    IngestTimestamp: String(row['IngestTimestamp'] ?? ''),
    UnmappedFields: String(row['UnmappedFields'] ?? ''),
  };
}

// ── Entity side panel ─────────────────────────────────────────────────────────

interface EntityPanelProps {
  entityName: string;
  rows: Record<string, unknown>[];
  onClose: () => void;
  onOpenEvent: (event: SecurityEvent) => void;
}

function EntityPanel({ entityName, rows, onClose, onOpenEvent }: EntityPanelProps) {
  // Find all rows that involve this entity
  const relatedRows = useMemo(() => {
    return rows.filter((row) =>
      Object.values(row).some(
        (v) => typeof v === 'string' && v.trim() === entityName,
      ),
    );
  }, [rows, entityName]);

  return (
    <div className="fixed inset-y-0 right-0 w-[440px] bg-gray-900 border-l border-gray-800 overflow-y-auto z-50 shadow-2xl">
      <div className="px-5 py-4 border-b border-gray-800 flex items-center justify-between sticky top-0 bg-gray-900">
        <div>
          <h3 className="text-white font-semibold text-sm">Entity Events</h3>
          <p className="text-gray-400 text-xs font-mono mt-0.5 break-all">{entityName}</p>
        </div>
        <button onClick={onClose} aria-label="Close entity panel" className="text-gray-500 hover:text-gray-300 p-1">
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <div className="p-4">
        {relatedRows.length === 0 ? (
          <p className="text-gray-500 text-sm">No events found for this entity.</p>
        ) : (
          <div className="space-y-1">
            <p className="text-gray-500 text-xs mb-2">{relatedRows.length} event{relatedRows.length !== 1 ? 's' : ''} — click a row to view details</p>
            <table className="w-full text-xs border-collapse">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="text-left text-gray-500 pb-1.5 pr-2 font-medium">Time</th>
                  <th className="text-left text-gray-500 pb-1.5 pr-2 font-medium">EID</th>
                  <th className="text-left text-gray-500 pb-1.5 pr-2 font-medium">Host</th>
                  <th className="text-left text-gray-500 pb-1.5 font-medium">User</th>
                </tr>
              </thead>
              <tbody>
                {relatedRows.map((row, idx) => {
                  const event = rowToEvent(row);
                  return (
                    <tr
                      key={idx}
                      onClick={() => onOpenEvent(event)}
                      className="border-b border-gray-800/50 hover:bg-gray-800/50 cursor-pointer transition-colors"
                    >
                      <td className="py-1.5 pr-2 text-gray-400 whitespace-nowrap">
                        {formatTimestamp(event.TimeGenerated).slice(0, 19)}
                      </td>
                      <td className="py-1.5 pr-2 text-orange-400 font-mono">{event.EventID || '—'}</td>
                      <td className="py-1.5 pr-2 text-gray-300 font-mono truncate max-w-[100px]">{event.HostName || '—'}</td>
                      <td className="py-1.5 text-cyan-400 font-mono truncate max-w-[100px]">{event.SubjectUserName || '—'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function CorrelationPage() {
  const [preset, setPreset] = useState<TimePreset>('24h');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [relationshipRows, setRelationshipRows] = useState<Record<string, unknown>[]>([]);
  const [hasLoaded, setHasLoaded] = useState(false);

  // Panel state
  const [selectedEntity, setSelectedEntity] = useState<string | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  const { nodes, edges, truncated } = useMemo(
    () => buildGraphData(relationshipRows),
    [relationshipRows],
  );

  const runQueries = useCallback(async (p: TimePreset) => {
    setLoading(true);
    setError(null);
    setSelectedEntity(null);
    setSelectedEvent(null);
    try {
      const interval = PRESET_INTERVALS[p];
      // Run both queries in parallel
      const [, relResult] = await Promise.all([
        api.query({ sql: buildEntityQuery(interval) }),
        api.query({ sql: buildRelationshipQuery(interval) }),
      ]);
      setRelationshipRows(relResult.rows);
      setHasLoaded(true);
    } catch (e) {
      if (e instanceof ApiClientError) {
        setError(`[${e.code}] ${e.message}`);
      } else {
        setError('Unexpected error — check API connectivity.');
      }
    } finally {
      setLoading(false);
    }
  }, []);

  function handlePresetChange(p: TimePreset) {
    setPreset(p);
    void runQueries(p);
  }

  // ECharts option
  const option = useMemo(() => ({
    backgroundColor: 'transparent',
    tooltip: { trigger: 'item' as const },
    legend: [
      {
        data: ['Host', 'User', 'IP Address', 'Process'],
        textStyle: { color: '#9ca3af' },
        bottom: 0,
      },
    ],
    series: [
      {
        type: 'graph' as const,
        layout: 'force' as const,
        data: nodes,
        links: edges,
        categories: [
          { name: 'Host', itemStyle: { color: '#3b82f6' } },
          { name: 'User', itemStyle: { color: '#22c55e' } },
          { name: 'IP Address', itemStyle: { color: '#f97316' } },
          { name: 'Process', itemStyle: { color: '#a855f7' } },
        ],
        roam: true,
        label: {
          show: true,
          position: 'right' as const,
          fontSize: 10,
          color: '#d1d5db',
        },
        force: { repulsion: 100, edgeLength: 80 },
        lineStyle: { color: 'source' as const, curveness: 0.1, opacity: 0.6 },
        emphasis: { focus: 'adjacency' as const },
      },
    ],
  }), [nodes, edges]);

  // Handle node click from ECharts
  function handleChartEvents() {
    return {
      click: (params: { dataType?: string; name?: string }) => {
        if (params.dataType === 'node' && params.name) {
          setSelectedEvent(null);
          setSelectedEntity(params.name);
        }
      },
    };
  }

  const chartEvents = useMemo(() => handleChartEvents(), []);

  const onChartReady = useCallback((_chart: ECharts) => {
    // chart is ready; no action needed
  }, []);

  return (
    <div className="p-6 flex flex-col gap-5">
      <h1 className="text-xl font-bold text-white">Correlation Graph</h1>

      {/* Controls */}
      <div className="flex items-center gap-3 flex-wrap">
        <span className="text-xs text-gray-400 font-medium">Time range:</span>
        {(Object.keys(PRESET_LABELS) as TimePreset[]).map((p) => (
          <button
            key={p}
            onClick={() => handlePresetChange(p)}
            disabled={loading}
            className={`px-3 py-1.5 rounded text-xs font-medium border transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
              preset === p
                ? 'bg-red-600 border-red-500 text-white'
                : 'bg-gray-800 border-gray-700 text-gray-300 hover:bg-gray-700 hover:text-white hover:border-gray-600'
            }`}
          >
            {PRESET_LABELS[p]}
          </button>
        ))}
        {!hasLoaded && !loading && (
          <button
            onClick={() => handlePresetChange(preset)}
            className="px-4 py-1.5 rounded text-xs font-medium border bg-red-600 border-red-500 text-white hover:bg-red-700 transition-colors"
          >
            Load Graph
          </button>
        )}
        {loading && (
          <span className="flex items-center gap-1.5 text-xs text-gray-400">
            <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            Loading entity data…
          </span>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-4 text-red-400 text-sm font-mono">
          {error}
        </div>
      )}

      {/* Node cap warning */}
      {truncated && (
        <div className="bg-yellow-900/20 border border-yellow-700/40 rounded-lg px-4 py-2.5 text-yellow-300 text-xs">
          Graph too large — showing top {NODE_CAP} nodes. Narrow the time range to see all entities.
        </div>
      )}

      {/* Graph area */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
        {!hasLoaded && !loading ? (
          <div className="flex items-center justify-center h-[600px] text-gray-500 text-sm">
            Select a time range and click Load Graph to visualize entity relationships.
          </div>
        ) : loading ? (
          <div className="flex items-center justify-center h-[600px]">
            <div className="w-48 h-2 bg-gray-800 rounded-full overflow-hidden">
              <div className="h-full bg-red-600 rounded-full animate-pulse w-2/3" />
            </div>
          </div>
        ) : nodes.length === 0 ? (
          <div className="flex items-center justify-center h-[600px] text-center px-8">
            <p className="text-gray-500 text-sm">
              No entity data in the selected time window. Try adjusting the time range or checking that events are being ingested.
            </p>
          </div>
        ) : (
          <ReactECharts
            option={option}
            style={{ height: '600px' }}
            onEvents={chartEvents}
            onChartReady={onChartReady}
            notMerge={true}
          />
        )}
      </div>

      {/* Legend / help text */}
      {hasLoaded && nodes.length > 0 && (
        <div className="flex items-center gap-4 text-xs text-gray-500">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block" />
            Host
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-green-500 inline-block" />
            User
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-orange-500 inline-block" />
            IP Address
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-500 inline-block" />
            Process
          </span>
          <span className="ml-4 text-gray-600">Click a node to see related events. Scroll to zoom, drag to pan.</span>
        </div>
      )}

      {/* Entity side panel */}
      {selectedEntity && !selectedEvent && (
        <EntityPanel
          entityName={selectedEntity}
          rows={relationshipRows}
          onClose={() => setSelectedEntity(null)}
          onOpenEvent={(evt) => setSelectedEvent(evt)}
        />
      )}

      {/* Event detail panel */}
      {selectedEvent && (
        <EventDetailPanel
          event={selectedEvent}
          onClose={() => {
            setSelectedEvent(null);
            // Return to entity panel if entity is still selected
          }}
        />
      )}

      <ClaudeChatbar />
    </div>
  );
}
