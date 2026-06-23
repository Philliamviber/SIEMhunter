import { useState, useMemo } from 'react';
import { useDetections } from '../hooks/useApi';
import { SeverityBadge } from '../components/SeverityBadge';
import { DataTable, Pagination } from '../components/DataTable';
import type { ColumnDef } from '../components/DataTable';
import ReactECharts from 'echarts-for-react';
import type { DetectionHit, TimelineBucket, DetectionsFilter } from '../types/api';
import { formatTimestamp } from '../utils/formatTimestamp';

const PAGE_SIZE = 50;

const SEV_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#f97316',
  medium: '#eab308',
  low: '#60a5fa',
};

// ── Stacked area chart ────────────────────────────────────────────────────────

function TimelineChart({ timeline }: { timeline: TimelineBucket[] }) {
  const severities = ['low', 'medium', 'high', 'critical'];

  // Build hour → {sev: count} map
  const hourMap = new Map<string, Record<string, number>>();
  for (const b of timeline) {
    if (!hourMap.has(b.hour)) hourMap.set(b.hour, {});
    hourMap.get(b.hour)![b.severity] = b.hit_count;
  }

  const hours = [...hourMap.keys()].sort();
  const shortHours = hours.map((h) => {
    try { return new Date(h).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
    catch { return h; }
  });

  const series = severities.map((sev) => ({
    name: sev.toUpperCase(),
    type: 'line' as const,
    stack: 'total',
    areaStyle: { opacity: 0.6 },
    lineStyle: { width: 1 },
    showSymbol: false,
    color: SEV_COLORS[sev],
    data: hours.map((h) => hourMap.get(h)?.[sev] ?? 0),
  }));

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis' as const,
      axisPointer: { type: 'cross' as const },
      backgroundColor: '#111827',
      borderColor: '#374151',
      textStyle: { color: '#f3f4f6' },
    },
    legend: {
      data: severities.map((s) => s.toUpperCase()),
      textStyle: { color: '#9ca3af' },
      bottom: 0,
    },
    xAxis: {
      type: 'category' as const,
      data: shortHours,
      axisLabel: { color: '#6b7280', fontSize: 10 },
      axisLine: { lineStyle: { color: '#374151' } },
    },
    yAxis: {
      type: 'value' as const,
      axisLabel: { color: '#6b7280' },
      splitLine: { lineStyle: { color: '#1f2937' } },
    },
    series,
    grid: { left: 40, right: 20, top: 20, bottom: 50 },
  };

  if (hours.length === 0) {
    return <p className="text-gray-500 text-sm py-8 text-center">No timeline data</p>;
  }

  return <ReactECharts option={option} style={{ height: 260 }} />;
}

// ── Rule detail panel ─────────────────────────────────────────────────────────

function RuleDetailPanel({ ruleId, hits }: { ruleId: string; hits: DetectionHit[] }) {
  const ruleHits = hits.filter((h) => h.rule_id === ruleId);
  if (ruleHits.length === 0) return null;
  const latest = ruleHits[0];
  const totalCount = ruleHits.reduce((s, h) => s + h.hit_count, 0);

  return (
    <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4 text-sm space-y-2">
      <div className="flex items-center gap-2">
        <span className="font-mono text-white font-bold">{ruleId}</span>
        <SeverityBadge severity={latest.severity} />
      </div>
      <div className="grid grid-cols-3 gap-4 text-xs">
        <div>
          <div className="text-gray-500 mb-0.5">Total Hits (current view)</div>
          <div className="text-white font-bold">{totalCount}</div>
        </div>
        <div>
          <div className="text-gray-500 mb-0.5">MITRE</div>
          <div className="text-purple-400 font-mono">{latest.mitre_tag || '—'}</div>
        </div>
        <div>
          <div className="text-gray-500 mb-0.5">Last Fired</div>
          <div className="text-gray-300">{formatTimestamp(latest.created_at)}</div>
        </div>
      </div>
    </div>
  );
}

// ── Table columns ─────────────────────────────────────────────────────────────

const COLS: ColumnDef<DetectionHit>[] = [
  {
    key: 'rule_id',
    header: 'Rule',
    render: (r) => <span className="font-mono text-xs text-gray-200">{r.rule_id}</span>,
  },
  {
    key: 'severity',
    header: 'Severity',
    render: (r) => <SeverityBadge severity={r.severity} />,
  },
  {
    key: 'mitre_tag',
    header: 'MITRE',
    render: (r) => <span className="text-purple-400 text-xs font-mono">{r.mitre_tag || '—'}</span>,
  },
  {
    key: 'hit_count',
    header: 'Hits',
    render: (r) => <span className="text-white font-medium">{r.hit_count}</span>,
  },
  {
    key: 'anomaly_score',
    header: 'Anomaly',
    render: (r) => (
      <span className={`text-xs font-mono ${r.anomaly_score > 0.7 ? 'text-red-400' : r.anomaly_score > 0.4 ? 'text-yellow-400' : 'text-gray-400'}`}>
        {r.anomaly_score.toFixed(3)}
      </span>
    ),
  },
  {
    key: 'forwarded_at',
    header: 'Forwarded',
    render: (r) => (
      r.forwarded_at
        ? <span className="text-green-400 text-xs">Yes</span>
        : <span className="text-gray-500 text-xs">Pending</span>
    ),
  },
  {
    key: 'created_at',
    header: 'Time',
    render: (r) => <span className="text-gray-400 text-xs whitespace-nowrap">{formatTimestamp(r.created_at)}</span>,
  },
];

// ── Main page ─────────────────────────────────────────────────────────────────

export function DetectionsPage() {
  const [offset, setOffset] = useState(0);
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);

  // Facet filters
  const [severity, setSeverity] = useState('');
  const [ruleIdFilter, setRuleIdFilter] = useState('');
  const [forwarded, setForwarded] = useState<'' | 'yes' | 'no'>('');

  const filter: DetectionsFilter = {
    ...(severity ? { severity } : {}),
    ...(ruleIdFilter ? { rule_id: ruleIdFilter } : {}),
    ...(forwarded ? { forwarded } : {}),
    limit: PAGE_SIZE,
    offset,
  };

  const { data, isLoading, isError } = useDetections(filter);

  const allHits = data?.hits ?? [];
  const timeline = data?.timeline ?? [];

  // Unique rule IDs for facet
  const uniqueRules = useMemo(
    () => [...new Set(allHits.map((h) => h.rule_id))].sort(),
    [allHits],
  );

  return (
    <div className="p-6 flex flex-col gap-5">
      <h1 className="text-xl font-bold text-white">Detections</h1>

      {/* Timeline chart */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
        <h2 className="text-white font-semibold text-sm mb-3">Hit Timeline by Severity</h2>
        {isLoading ? (
          <div className="h-56 bg-gray-800 rounded animate-pulse" />
        ) : (
          <TimelineChart timeline={timeline} />
        )}
      </div>

      <div className="flex gap-5">
        {/* Facet sidebar */}
        <div className="w-52 flex-shrink-0 bg-gray-900 border border-gray-800 rounded-lg p-4 self-start space-y-4">
          <h2 className="text-white font-semibold text-sm">Filters</h2>

          <div>
            <label className="block text-xs text-gray-400 mb-1.5">Severity</label>
            <select
              value={severity}
              onChange={(e) => { setSeverity(e.target.value); setOffset(0); }}
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-white text-xs"
            >
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div>
            <label className="block text-xs text-gray-400 mb-1.5">Rule ID</label>
            <select
              value={ruleIdFilter}
              onChange={(e) => { setRuleIdFilter(e.target.value); setOffset(0); }}
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-white text-xs"
            >
              <option value="">All</option>
              {uniqueRules.map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs text-gray-400 mb-1.5">Forwarded</label>
            <select
              value={forwarded}
              onChange={(e) => { setForwarded(e.target.value as '' | 'yes' | 'no'); setOffset(0); }}
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-white text-xs"
            >
              <option value="">All</option>
              <option value="yes">Forwarded</option>
              <option value="no">Pending</option>
            </select>
          </div>

          <button
            onClick={() => { setSeverity(''); setRuleIdFilter(''); setForwarded(''); setOffset(0); }}
            className="w-full py-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded text-xs font-medium"
          >
            Clear
          </button>
        </div>

        {/* Table + detail */}
        <div className="flex-1 flex flex-col gap-3 min-w-0">
          {isError && (
            <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-4 text-red-400 text-sm">
              Failed to load detections.
            </div>
          )}

          {selectedRuleId && (
            <RuleDetailPanel ruleId={selectedRuleId} hits={allHits} />
          )}

          <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
            <DataTable
              columns={COLS}
              rows={allHits}
              keyFn={(r) => r.hit_id}
              loading={isLoading}
              emptyMessage="No detection hits match the current filters"
              onRowClick={(r) => setSelectedRuleId(r.rule_id === selectedRuleId ? null : r.rule_id)}
              selectedKey={allHits.find((h) => h.rule_id === selectedRuleId)?.hit_id}
            />
            <Pagination
              offset={offset}
              limit={PAGE_SIZE}
              total={data?.total_count ?? 0}
              onPrev={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
              onNext={() => setOffset((o) => o + PAGE_SIZE)}
            />
          </div>
        </div>
      </div>

    </div>
  );
}
