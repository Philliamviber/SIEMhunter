import { useStatus, useHealthService, useRules, useDetections } from '../hooks/useApi';
import { SentinelUnavailable } from '../components/SentinelUnavailable';
import { SeverityBadge } from '../components/SeverityBadge';
import clsx from 'clsx';

const SELF_RULE_IDS = ['SELF-001', 'SELF-002', 'SELF-003', 'SELF-004', 'SELF-005'];
const SERVICE_NAMES = ['vector', 'clickhouse', 'normalization', 'detection', 'forwarder'];

function StatusDot({ ok, unknown }: { ok: boolean; unknown?: boolean }) {
  return (
    <span
      className={clsx(
        'inline-block w-2.5 h-2.5 rounded-full flex-shrink-0',
        unknown ? 'bg-gray-500' : ok ? 'bg-green-400' : 'bg-red-500',
      )}
    />
  );
}

// ── Individual service status tile ────────────────────────────────────────────

function ServiceTile({ name }: { name: string }) {
  const { data, isLoading } = useHealthService(name);

  const statusText = data?.status ?? '…';
  const isOk = data?.status === 'ok';
  const isUnknown = data?.status === 'unknown';
  const isDegraded = data?.status === 'degraded' || data?.status === 'error';

  return (
    <div className={clsx(
      'bg-gray-900 border rounded-lg p-4 space-y-2',
      isOk ? 'border-green-800/50' : isUnknown ? 'border-gray-700' : isDegraded ? 'border-red-800/50' : 'border-gray-800',
    )}>
      <div className="flex items-center gap-2">
        {isLoading ? (
          <span className="inline-block w-2.5 h-2.5 rounded-full bg-gray-700 animate-pulse" />
        ) : (
          <StatusDot ok={isOk} unknown={isUnknown} />
        )}
        <span className="font-mono text-sm font-medium text-white">{name}</span>
        <span className={clsx(
          'ml-auto text-xs font-medium capitalize',
          isOk ? 'text-green-400' : isUnknown ? 'text-gray-500' : 'text-red-400',
        )}>
          {isLoading ? '…' : statusText}
        </span>
      </div>
      {data?.detail && (
        <p className="text-xs text-gray-500 leading-relaxed">{data.detail}</p>
      )}
      {data?.alive_file_age_seconds != null && (
        <p className="text-xs text-gray-600">Alive file: {data.alive_file_age_seconds}s ago</p>
      )}
    </div>
  );
}

// ── Self-detection rule board ─────────────────────────────────────────────────

function SelfRuleRow({ ruleId }: { ruleId: string }) {
  const rules = useRules();
  const detections = useDetections({ rule_id: ruleId, limit: 5 });

  const rule = rules.data?.find((r) => r.rule_id === ruleId);
  const hits = detections.data?.hits ?? [];
  const latestHit = hits[0];

  return (
    <div className="flex items-start gap-4 py-3 border-b border-gray-800/60 last:border-0">
      <span className="font-mono text-sm text-purple-400 w-24 flex-shrink-0">{ruleId}</span>
      <div className="flex-1 grid grid-cols-3 gap-4 text-xs">
        <div>
          <div className="text-gray-500 mb-0.5">Rule status</div>
          {rules.isLoading ? (
            <div className="h-4 bg-gray-800 rounded animate-pulse w-16" />
          ) : rule ? (
            <span className={clsx(
              'font-medium',
              rule.status === 'production' ? 'text-green-400' :
              rule.status === 'disabled' ? 'text-red-400' : 'text-yellow-400',
            )}>
              {rule.status}
            </span>
          ) : (
            <span className="text-gray-600">not in registry</span>
          )}
        </div>
        <div>
          <div className="text-gray-500 mb-0.5">Recent hits</div>
          {detections.isLoading ? (
            <div className="h-4 bg-gray-800 rounded animate-pulse w-8" />
          ) : (
            <span className={clsx('font-bold', hits.length > 0 ? 'text-red-400' : 'text-gray-400')}>
              {detections.data?.total_count ?? 0}
            </span>
          )}
        </div>
        <div>
          <div className="text-gray-500 mb-0.5">Last fired</div>
          {latestHit ? (
            <div className="flex items-center gap-1.5">
              <SeverityBadge severity={latestHit.severity} />
              <span className="text-gray-400">
                {(() => { try { return new Date(latestHit.created_at).toLocaleString(); } catch { return latestHit.created_at; } })()}
              </span>
            </div>
          ) : (
            <span className="text-gray-600">—</span>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Forward ledger ────────────────────────────────────────────────────────────

function ForwardLedger({ retryQueue }: { retryQueue: number }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-3">
      <h2 className="text-white font-semibold text-sm">Forward Ledger</h2>
      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <div className="text-gray-500 text-xs mb-0.5">Pending retry queue</div>
          <div className={clsx('font-bold text-lg', retryQueue > 0 ? 'text-yellow-400' : 'text-white')}>
            {retryQueue}
          </div>
        </div>
        <div>
          <div className="text-gray-500 text-xs mb-0.5">Sentinel-side count</div>
          <SentinelUnavailable />
        </div>
      </div>
      <div className="text-xs text-gray-600 leading-relaxed bg-gray-800/40 rounded p-2.5">
        SELF-005 ledger delta (local vs Sentinel) is Sentinel-side only.
        View in Log Analytics: <code className="text-purple-400">SIEMHunterHealth_CL | where EventType == "LedgerDelta"</code>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function HealthPage() {
  const status = useStatus();

  return (
    <div className="p-6 flex flex-col gap-6">
      <h1 className="text-xl font-bold text-white">Health</h1>

      {/* Service status grid */}
      <div>
        <h2 className="text-white font-semibold text-sm mb-3">Service Status</h2>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
          {SERVICE_NAMES.map((name) => (
            <ServiceTile key={name} name={name} />
          ))}
        </div>
      </div>

      {/* Overall status summary from /v1/status */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-2">
        <h2 className="text-white font-semibold text-sm">Pipeline Summary</h2>
        {status.isLoading ? (
          <div className="space-y-2">
            {[1,2,3,4,5].map(i => <div key={i} className="h-4 bg-gray-800 rounded animate-pulse" />)}
          </div>
        ) : status.data ? (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs">
            {[
              { label: 'ClickHouse', ok: status.data.clickhouse === 'ok', val: status.data.clickhouse },
              { label: 'Normalization', ok: status.data.normalization_alive, val: status.data.normalization_alive ? 'alive' : 'dead' },
              { label: 'Detection', ok: status.data.detection_alive, val: status.data.detection_alive ? 'alive' : 'dead' },
              { label: 'Forwarder', ok: status.data.forwarder_alive, val: status.data.forwarder_alive ? 'alive' : 'dead' },
              { label: 'Retry Queue', ok: status.data.pending_retry_queue === 0, val: String(status.data.pending_retry_queue) },
            ].map(({ label, ok, val }) => (
              <div key={label} className="flex items-center gap-2">
                <StatusDot ok={ok} />
                <div>
                  <div className="text-gray-500">{label}</div>
                  <div className={ok ? 'text-green-400' : 'text-red-400'}>{val}</div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-red-400 text-sm">Failed to fetch pipeline status</p>
        )}
      </div>

      {/* Self-detection rule board */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
        <h2 className="text-white font-semibold text-sm mb-1">Self-Detection Rules (SELF-001…005)</h2>
        <p className="text-gray-500 text-xs mb-4">
          Composed from /v1/rules (status) + /v1/detections?rule_id=SELF-00x (live firing)
        </p>
        {SELF_RULE_IDS.map((id) => (
          <SelfRuleRow key={id} ruleId={id} />
        ))}
      </div>

      {/* Forward ledger */}
      <ForwardLedger retryQueue={status.data?.pending_retry_queue ?? 0} />

      {/* Auth-failure / audit feed note */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-2">
        <h2 className="text-white font-semibold text-sm">Auth & Audit Feed</h2>
        <div className="bg-blue-900/20 border border-blue-700/30 rounded p-3 text-xs text-blue-300 space-y-1">
          <p>
            <strong>SIEMHunterSecurity_CL</strong> is Sentinel-side — view in Log Analytics Workspace.
          </p>
          <p className="text-blue-400 font-mono">
            SIEMHunterSecurity_CL | where EventType == "AuthFailure"
          </p>
          <p className="text-blue-400 font-mono">
            SIEMHunterSecurity_CL | where EventType == "RuleChangeAudit"
          </p>
        </div>
        <p className="text-gray-600 text-xs">
          Auth failures and rule change audit records are forwarded to Sentinel asynchronously
          and are not readable from the local API.
        </p>
      </div>
    </div>
  );
}
