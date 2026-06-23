import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useIngestionSummary } from '../hooks/useApi';
import { useToast } from '../hooks/useToast';
import { SentinelUnavailable } from '../components/SentinelUnavailable';
import { UploadZone } from '../components/UploadZone';
import { UploadStatusCard } from '../components/UploadStatusCard';
import { useIncidentContext } from '../context/IncidentContext';
import ReactECharts from 'echarts-for-react';
import type { HourlyVolume, PerSourceStat, UploadResponse, UploadMode } from '../types/api';
import { formatTimestamp } from '../utils/formatTimestamp';

// ── Donut chart ───────────────────────────────────────────────────────────────

function ProvenanceDonut({ data }: { data: { name: string; value: number }[] }) {
  const option = {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'item' as const },
    legend: {
      orient: 'vertical' as const,
      right: 20,
      textStyle: { color: '#9ca3af' },
    },
    series: [
      {
        type: 'pie' as const,
        radius: ['40%', '70%'],
        center: ['40%', '50%'],
        data,
        label: { color: '#9ca3af', fontSize: 11 },
        itemStyle: { borderColor: '#111827', borderWidth: 2 },
      },
    ],
  };

  if (data.length === 0) {
    return <p className="text-gray-500 text-sm text-center py-8">No provenance data</p>;
  }

  return <ReactECharts option={option} style={{ height: 280 }} />;
}

// ── Stacked area: volume over time ────────────────────────────────────────────

function VolumeChart({ data }: { data: HourlyVolume[] }) {
  const sources = [...new Set(data.map((d) => d.provenance_tag))].sort();
  const hours = [...new Set(data.map((d) => d.hour))].sort();
  const shortHours = hours.map((h) => {
    try { return new Date(h).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
    catch { return h; }
  });

  const series = sources.map((src) => ({
    name: src,
    type: 'line' as const,
    stack: 'total',
    areaStyle: { opacity: 0.5 },
    showSymbol: false,
    data: hours.map((h) => {
      const row = data.find((d) => d.hour === h && d.provenance_tag === src);
      return row?.event_count ?? 0;
    }),
  }));

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis' as const,
      backgroundColor: '#111827',
      borderColor: '#374151',
      textStyle: { color: '#f3f4f6' },
    },
    legend: {
      data: sources,
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

  if (data.length === 0) {
    return <p className="text-gray-500 text-sm text-center py-8">No volume data</p>;
  }

  return <ReactECharts option={option} style={{ height: 260 }} />;
}

// ── Per-source cards ──────────────────────────────────────────────────────────

function SourceCard({ stat }: { stat: PerSourceStat }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-2">
      <div className="font-mono text-sm text-purple-400 font-medium">{stat.provenance_tag}</div>
      <div className="grid grid-cols-3 gap-3 text-xs">
        <div>
          <div className="text-gray-500 mb-0.5">Last Seen</div>
          <div className="text-gray-300">{formatTimestamp(stat.last_seen)}</div>
        </div>
        <div>
          <div className="text-gray-500 mb-0.5">Events/hr</div>
          <div className="text-white font-bold">{stat.events_per_hour.toFixed(1)}</div>
        </div>
        <div>
          <div className="text-gray-500 mb-0.5">Unmapped %</div>
          <div className={`font-bold ${stat.unmapped_nonempty_pct > 20 ? 'text-yellow-400' : 'text-green-400'}`}>
            {stat.unmapped_nonempty_pct.toFixed(1)}%
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function IngestionPage() {
  const { data, isLoading, isError } = useIngestionSummary();
  const { activeIncidentId } = useIncidentContext();
  const queryClient = useQueryClient();
  const toast = useToast();
  const [uploadResult, setUploadResult] = useState<UploadResponse | null>(null);
  const [uploadMode, setUploadMode] = useState<UploadMode>('global');

  const donutData = (data?.provenance_breakdown ?? []).map((p) => ({
    name: p.provenance_tag,
    value: p.event_count,
  }));

  return (
    <div className="p-6 flex flex-col gap-6">
      <h1 className="text-xl font-bold text-white">Ingestion Context</h1>

      {isError && (
        <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-4 text-red-400 text-sm">
          Failed to load ingestion summary.
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Donut */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
          <h2 className="text-white font-semibold text-sm mb-3">Source Breakdown (24h)</h2>
          {isLoading ? (
            <div className="h-64 bg-gray-800 rounded animate-pulse" />
          ) : (
            <ProvenanceDonut data={donutData} />
          )}
        </div>

        {/* Latency + Rate-limit panel */}
        <div className="flex flex-col gap-4">
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-3">
            <h2 className="text-white font-semibold text-sm">Pipeline Latency (24h)</h2>
            {isLoading ? (
              <div className="h-16 bg-gray-800 rounded animate-pulse" />
            ) : (
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-xs text-gray-500 mb-0.5">Avg latency</div>
                  <div className="text-white text-xl font-bold">
                    {data?.pipeline_latency.avg_seconds != null
                      ? `${data.pipeline_latency.avg_seconds.toFixed(2)}s`
                      : '—'}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-gray-500 mb-0.5">p95 latency</div>
                  <div className="text-white text-xl font-bold">
                    {data?.pipeline_latency.p95_seconds != null
                      ? `${data.pipeline_latency.p95_seconds.toFixed(2)}s`
                      : '—'}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Rate-limit / flood panel — governance check #1 */}
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-2">
            <h2 className="text-white font-semibold text-sm">Rate-Limit / Flood Panel</h2>
            <SentinelUnavailable />
            {data?.rate_limit_flood_note && (
              <p className="text-gray-600 text-xs leading-relaxed">{data.rate_limit_flood_note}</p>
            )}
          </div>
        </div>
      </div>

      {/* Volume over time */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
        <h2 className="text-white font-semibold text-sm mb-3">Event Volume Over Time (24h)</h2>
        {isLoading ? (
          <div className="h-56 bg-gray-800 rounded animate-pulse" />
        ) : (
          <VolumeChart data={data?.volume_over_time ?? []} />
        )}
      </div>

      {/* Per-source cards */}
      <div>
        <h2 className="text-white font-semibold text-sm mb-3">Per-Source Stats</h2>
        {isLoading ? (
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-28 bg-gray-800 rounded-lg animate-pulse" />
            ))}
          </div>
        ) : (data?.per_source ?? []).length === 0 ? (
          <p className="text-gray-500 text-sm">No source data available for the last 24h</p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {(data?.per_source ?? []).map((stat) => (
              <SourceCard key={stat.provenance_tag} stat={stat} />
            ))}
          </div>
        )}
      </div>

      {/* Manual File Upload */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
        <h2 className="text-white font-semibold text-sm">Manual File Upload</h2>

        {/* Mode selector */}
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => setUploadMode('global')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-colors duration-150 ${
              uploadMode === 'global'
                ? 'bg-purple-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-gray-200'
            }`}
          >
            Global Ingest
          </button>
          {activeIncidentId && (
            <button
              type="button"
              onClick={() => setUploadMode('incident')}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors duration-150 ${
                uploadMode === 'incident'
                  ? 'bg-purple-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-gray-200'
              }`}
            >
              Incident-Scoped
            </button>
          )}
          {uploadMode === 'incident' && activeIncidentId && (
            <span className="text-xs text-gray-500 font-mono">
              incident: {activeIncidentId}
            </span>
          )}
        </div>

        <UploadZone
          mode={uploadMode}
          incidentId={activeIncidentId ?? undefined}
          onUploadComplete={(result) => {
            setUploadResult(result);
            void queryClient.invalidateQueries({ queryKey: ['ingestion'] });
            void queryClient.invalidateQueries({ queryKey: ['metrics'] });
            toast.success(`${result.filename}: ${result.events_written} event${result.events_written !== 1 ? 's' : ''} written`);
          }}
        />

        {uploadResult && <UploadStatusCard result={uploadResult} />}
      </div>

    </div>
  );
}
