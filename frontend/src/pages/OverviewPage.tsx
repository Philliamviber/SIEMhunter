import { useMetrics, useStatus, useAiSummary, useDetections } from '../hooks/useApi';
import { KpiCard } from '../components/KpiCard';
import { StatusBanner } from '../components/StatusBanner';
import { SeverityBadge } from '../components/SeverityBadge';
import { DataTable } from '../components/DataTable';
import { SentinelUnavailable } from '../components/SentinelUnavailable';
import ReactECharts from 'echarts-for-react';
import type { DetectionHit } from '../types/api';

function formatTime(iso: string | null): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#f97316',
  medium: '#eab308',
  low: '#60a5fa',
};

function SeverityBarChart({ data }: { data: { severity: string; count: number }[] }) {
  const option = {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis' as const },
    xAxis: {
      type: 'category' as const,
      data: data.map((d) => d.severity.toUpperCase()),
      axisLabel: { color: '#9ca3af' },
      axisLine: { lineStyle: { color: '#374151' } },
    },
    yAxis: {
      type: 'value' as const,
      axisLabel: { color: '#9ca3af' },
      splitLine: { lineStyle: { color: '#1f2937' } },
    },
    series: [
      {
        type: 'bar' as const,
        data: data.map((d) => ({
          value: d.count,
          itemStyle: { color: SEVERITY_COLORS[d.severity.toLowerCase()] ?? '#6b7280' },
        })),
      },
    ],
    grid: { left: 40, right: 20, top: 20, bottom: 30 },
  };

  return <ReactECharts option={option} style={{ height: 200 }} />;
}

const RECENT_HITS_COLS = [
  {
    key: 'rule_id',
    header: 'Rule',
    render: (row: DetectionHit) => (
      <span className="font-mono text-xs text-gray-200">{row.rule_id}</span>
    ),
  },
  {
    key: 'severity',
    header: 'Severity',
    render: (row: DetectionHit) => <SeverityBadge severity={row.severity} />,
  },
  {
    key: 'mitre_tag',
    header: 'MITRE',
    render: (row: DetectionHit) => (
      <span className="text-purple-400 text-xs font-mono">{row.mitre_tag || '—'}</span>
    ),
  },
  {
    key: 'hit_count',
    header: 'Hits',
    render: (row: DetectionHit) => (
      <span className="text-white font-medium">{row.hit_count}</span>
    ),
  },
  {
    key: 'created_at',
    header: 'Time',
    render: (row: DetectionHit) => (
      <span className="text-gray-400 text-xs whitespace-nowrap">{formatTime(row.created_at)}</span>
    ),
  },
];

export function OverviewPage() {
  const metrics = useMetrics();
  const status = useStatus();
  const aiSummary = useAiSummary();
  const recentHits = useDetections({ severity: 'high', limit: 10 });

  // Derive severity counts from metrics
  const anomalyDist = metrics.data?.anomaly_score_distribution ?? [];
  const severityData = [
    { severity: 'critical', count: 0 },
    { severity: 'high', count: 0 },
    { severity: 'medium', count: 0 },
    { severity: 'low', count: 0 },
  ];
  // The metrics endpoint doesn't break down by severity directly — use detections timeline
  // We'll show anomaly distribution as a proxy visual
  const hasAnomalyData = anomalyDist.length > 0;

  const allHits = [
    ...(recentHits.data?.hits ?? []),
  ];

  // Derive forward status from status response
  const forwarderOk = status.data?.forwarder_alive;

  return (
    <div className="p-6 flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Overview</h1>
        <span className="text-gray-500 text-sm">
          Auto-refreshes every 30s
        </span>
      </div>

      {/* Status banner */}
      <StatusBanner
        status={status.data}
        loading={status.isLoading}
        error={status.isError}
      />

      {/* KPI cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <KpiCard
          title="Events (24h)"
          loading={metrics.isLoading}
          value={
            metrics.data
              ? metrics.data.events_by_source.reduce((s, x) => s + x.event_count, 0).toLocaleString()
              : '—'
          }
        />
        <KpiCard
          title="Detection Hits (24h)"
          loading={metrics.isLoading}
          value={metrics.data?.detection_hits_24h.toLocaleString() ?? '—'}
        />
        <KpiCard
          title="Active Rules"
          loading={false}
          value="—"
          trend="See Rules page"
        />
        <KpiCard
          title="Last Batch"
          loading={metrics.isLoading}
          value={metrics.data?.last_batch_run_at ? formatTime(metrics.data.last_batch_run_at) : '—'}
        />
        <KpiCard
          title="Sentinel Forward"
          loading={status.isLoading}
          value={forwarderOk === undefined ? '—' : forwarderOk ? 'Active' : 'Impaired'}
          badge={
            forwarderOk !== undefined && (
              <span
                className={`inline-block w-2 h-2 rounded-full ${forwarderOk ? 'bg-green-400' : 'bg-red-500'}`}
              />
            )
          }
        />
      </div>

      {/* Last Batch Duration — always Sentinel-side */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <div className="text-sm text-gray-400 mb-1 font-medium uppercase tracking-wide text-xs">Last Batch Duration</div>
        <SentinelUnavailable label="Not available locally (Sentinel-side)" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* AI Summary */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 flex flex-col gap-3">
          <div className="flex items-center gap-2">
            <span className="text-purple-400">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
              </svg>
            </span>
            <h2 className="text-white font-semibold text-sm">AI Security Summary</h2>
          </div>

          {aiSummary.isLoading && (
            <div className="space-y-2">
              <div className="h-4 bg-gray-800 rounded animate-pulse" />
              <div className="h-4 bg-gray-800 rounded animate-pulse w-4/5" />
              <div className="h-4 bg-gray-800 rounded animate-pulse w-3/5" />
            </div>
          )}
          {aiSummary.isError && (
            <p className="text-gray-500 text-sm">
              AI summary unavailable — Anthropic API key not configured or service unreachable.
            </p>
          )}
          {aiSummary.data && (
            <>
              <p className="text-gray-300 text-sm leading-relaxed">{aiSummary.data.narrative}</p>
              {aiSummary.data.notable_items.length > 0 && (
                <ul className="space-y-1">
                  {aiSummary.data.notable_items.map((item, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm text-gray-400">
                      <span className="text-purple-400 mt-0.5">•</span>
                      {item}
                    </li>
                  ))}
                </ul>
              )}
              <div className="pt-2 border-t border-gray-800 flex flex-col gap-0.5">
                <p className="text-xs text-gray-600">{aiSummary.data.disclaimer}</p>
                <p className="text-xs text-gray-600">
                  Generated {formatTime(aiSummary.data.generated_at)} · {aiSummary.data.source_window}
                </p>
              </div>
            </>
          )}
        </div>

        {/* Severity / Anomaly distribution */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 flex flex-col gap-3">
          <h2 className="text-white font-semibold text-sm">Anomaly Score Distribution (24h)</h2>
          {metrics.isLoading ? (
            <div className="h-48 bg-gray-800 rounded animate-pulse" />
          ) : hasAnomalyData ? (
            <SeverityBarChart
              data={anomalyDist.map((b) => ({
                severity: b.bucket_label,
                count: b.count,
              }))}
            />
          ) : (
            <p className="text-gray-500 text-sm py-8 text-center">No anomaly data for the last 24h</p>
          )}
          {/* Severity breakdown placeholder */}
          {severityData.map((s) => (
            <div key={s.severity} className="hidden" />
          ))}
        </div>
      </div>

      {/* Recent high/critical hits */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg">
        <div className="px-5 py-3 border-b border-gray-800 flex items-center justify-between">
          <h2 className="text-white font-semibold text-sm">Recent High Severity Hits</h2>
          <a href="/detections" className="text-xs text-gray-500 hover:text-gray-300">
            View all →
          </a>
        </div>
        <DataTable
          columns={RECENT_HITS_COLS}
          rows={allHits}
          keyFn={(r) => r.hit_id}
          loading={recentHits.isLoading}
          emptyMessage="No recent high severity hits"
        />
      </div>
    </div>
  );
}
