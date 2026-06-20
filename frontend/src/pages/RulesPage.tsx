/**
 * RulesPage.tsx — Kanban board for the Sigma rule lifecycle.
 *
 * Rule lifecycle columns (left → right): draft → test → review → production → disabled.
 * A rule must be explicitly moved through each stage; there is no automatic promotion.
 *
 * Fail-closed status change invariant: when a status change is confirmed, the API
 * writes an audit record to Sentinel FIRST. Only if that write succeeds does it update
 * the rule's status in ClickHouse. If Sentinel is unreachable, the API returns 503
 * and the status is NOT changed. This prevents unaudited rule promotions (an
 * anti-tamper guarantee for regulated environments). The FailClosedModal below
 * surfaces this behaviour explicitly to the operator before they confirm.
 *
 * Severity display: RuleCard infers severity from rule_id prefix because the API's
 * rule registry does not return a severity field for the rule itself — severity is
 * a property of detection hits, not of the rule definition. The inference is a
 * best-effort visual aid, not authoritative.
 */
import { useState } from 'react';
import { useRules, useUpdateRuleStatus } from '../hooks/useApi';
import { SeverityBadge } from '../components/SeverityBadge';
import { ApiClientError } from '../api/client';
import type { Rule, RuleStatus } from '../types/api';

const STATUS_ORDER: RuleStatus[] = ['draft', 'test', 'review', 'production', 'disabled'];

const STATUS_COLORS: Record<RuleStatus, string> = {
  draft: 'bg-gray-700/40 border-gray-600',
  test: 'bg-blue-900/30 border-blue-700',
  review: 'bg-yellow-900/30 border-yellow-700',
  production: 'bg-green-900/30 border-green-700',
  disabled: 'bg-red-900/20 border-red-800',
};

const STATUS_LABEL_COLORS: Record<RuleStatus, string> = {
  draft: 'text-gray-400',
  test: 'text-blue-400',
  review: 'text-yellow-400',
  production: 'text-green-400',
  disabled: 'text-red-400',
};

function formatTime(iso: string): string {
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

// ── Sigma YAML viewer ─────────────────────────────────────────────────────────

function SigmaViewer({ rule }: { rule: Rule }) {
  // file_path is the local container path — show it as informational
  return (
    <div className="space-y-2">
      <div className="text-xs text-gray-500 font-mono break-all">{rule.file_path}</div>
      <div className="bg-gray-950 border border-gray-800 rounded p-3 text-xs text-gray-300 font-mono overflow-x-auto whitespace-pre-wrap">
        {`# Rule: ${rule.rule_id}\n# Version: ${rule.rule_version}\n# Status: ${rule.status}\n# Path: ${rule.file_path}\n# Updated: ${rule.updated_at}\n\n# Full Sigma YAML is loaded from the filesystem by the detection service.\n# This view shows registry metadata only.`}
      </div>
    </div>
  );
}

// ── Fail-closed modal ─────────────────────────────────────────────────────────

interface ModalProps {
  rule: Rule;
  targetStatus: RuleStatus;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
  submitting: boolean;
  error: string | null;
}

function FailClosedModal({ rule, targetStatus, onConfirm, onCancel, submitting, error }: ModalProps) {
  const [reason, setReason] = useState('');

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-6 w-full max-w-md space-y-4">
        <div className="flex items-start gap-3">
          <span className="text-yellow-400 mt-0.5 flex-shrink-0">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </span>
          <div>
            <h3 className="text-white font-semibold text-sm">Fail-closed rule status change</h3>
            <p className="text-gray-400 text-xs mt-1">
              This writes an audit record to Sentinel <strong className="text-white">before</strong> updating ClickHouse.
              If Sentinel is unreachable you will receive a 503 and the change will <strong className="text-red-400">NOT</strong> be applied.
            </p>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-3 text-xs space-y-1.5">
          <div className="flex justify-between">
            <span className="text-gray-500">Rule</span>
            <span className="text-white font-mono">{rule.rule_id}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">Current status</span>
            <span className={STATUS_LABEL_COLORS[rule.status]}>{rule.status}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">New status</span>
            <span className={STATUS_LABEL_COLORS[targetStatus]}>{targetStatus}</span>
          </div>
        </div>

        <div>
          <label className="block text-xs text-gray-400 mb-1.5">Reason (optional)</label>
          <input
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="e.g. Verified against 2 weeks of live data"
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-white text-xs"
          />
        </div>

        {error && (
          <div className="bg-red-900/20 border border-red-700/40 rounded p-3 text-red-400 text-xs">
            {error}
          </div>
        )}

        <div className="flex gap-3 pt-1">
          <button
            onClick={onCancel}
            disabled={submitting}
            className="flex-1 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded text-sm font-medium disabled:opacity-40"
          >
            Cancel
          </button>
          <button
            onClick={() => onConfirm(reason)}
            disabled={submitting}
            className="flex-1 py-2 bg-red-600 hover:bg-red-700 text-white rounded text-sm font-medium disabled:opacity-40"
          >
            {submitting ? 'Applying…' : 'Confirm Change'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Rule card ─────────────────────────────────────────────────────────────────

interface RuleCardProps {
  rule: Rule;
  onClick: () => void;
  selected: boolean;
}

function extractSeverity(rule: Rule): string {
  // Infer severity from rule_id prefix (SELF-* are usually high, WIN-* vary)
  if (rule.rule_id.startsWith('SELF-')) return 'high';
  return '—';
}

function RuleCard({ rule, onClick, selected }: RuleCardProps) {
  return (
    <div
      onClick={onClick}
      className={`border rounded-lg p-3 cursor-pointer transition-colors text-left w-full ${
        selected
          ? 'border-gray-500 bg-gray-800'
          : 'border-gray-700/50 bg-gray-800/30 hover:bg-gray-800/60'
      }`}
    >
      <div className="flex items-start justify-between gap-2 mb-1.5">
        <span className="font-mono text-xs text-white font-medium">{rule.rule_id}</span>
        <SeverityBadge severity={extractSeverity(rule)} />
      </div>
      <div className="text-xs text-gray-500 truncate">{rule.file_path.split('/').pop()}</div>
      <div className="text-xs text-gray-600 mt-1">{formatTime(rule.updated_at)}</div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function RulesPage() {
  const { data: rules, isLoading, isError } = useRules();
  const updateStatus = useUpdateRuleStatus();

  const [selectedRule, setSelectedRule] = useState<Rule | null>(null);
  const [pendingStatus, setPendingStatus] = useState<RuleStatus | null>(null);
  const [modalError, setModalError] = useState<string | null>(null);

  // Group rules by status for Kanban column rendering. STATUS_ORDER defines the
  // column order — cards are placed into the matching bucket as rules are iterated.
  const byStatus: Record<RuleStatus, Rule[]> = {
    draft: [],
    test: [],
    review: [],
    production: [],
    disabled: [],
  };

  for (const rule of rules ?? []) {
    const s = rule.status as RuleStatus;
    // Guard against unknown status values returned by the API (e.g. future statuses).
    if (s in byStatus) byStatus[s].push(rule);
  }

  function openStatusModal(status: RuleStatus) {
    setPendingStatus(status);
    setModalError(null);
  }

  async function handleConfirm(reason: string) {
    if (!selectedRule || !pendingStatus) return;
    try {
      // mutateAsync throws on failure; the catch block surfaces the API error
      // (including 503 if Sentinel is unreachable) in the modal without closing it.
      await updateStatus.mutateAsync({
        ruleId: selectedRule.rule_id,
        body: { new_status: pendingStatus, reason: reason || undefined },
      });
      // Only clear state on success — modal stays open with error on failure
      // so the operator can retry or cancel without losing their context.
      setPendingStatus(null);
      setSelectedRule(null);
    } catch (e) {
      const msg =
        e instanceof ApiClientError
          ? `${e.message} (${e.code})`
          : 'Unexpected error — check API connectivity.';
      setModalError(msg);
    }
  }

  return (
    <div className="p-6 flex flex-col gap-5">
      <h1 className="text-xl font-bold text-white">Rules Management</h1>

      {isError && (
        <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-4 text-red-400 text-sm">
          Failed to load rules.
        </div>
      )}

      {isLoading && (
        <div className="grid grid-cols-5 gap-4">
          {STATUS_ORDER.map((s) => (
            <div key={s} className="h-64 bg-gray-800 rounded-lg animate-pulse" />
          ))}
        </div>
      )}

      {/* Kanban board */}
      {!isLoading && (
        <div className="flex gap-4 overflow-x-auto scrollbar-thin pb-2">
          {STATUS_ORDER.map((status) => (
            <div key={status} className="flex-shrink-0 w-56">
              <div className={`border rounded-lg ${STATUS_COLORS[status]}`}>
                <div className="px-3 py-2.5 border-b border-white/5 flex items-center justify-between">
                  <span className={`text-xs font-semibold uppercase tracking-wide ${STATUS_LABEL_COLORS[status]}`}>
                    {status}
                  </span>
                  <span className="text-xs text-gray-500 bg-gray-800/60 rounded-full px-2 py-0.5">
                    {byStatus[status].length}
                  </span>
                </div>
                <div className="p-2 space-y-2 min-h-[120px]">
                  {byStatus[status].map((rule) => (
                    <RuleCard
                      key={rule.rule_id}
                      rule={rule}
                      onClick={() => setSelectedRule(rule === selectedRule ? null : rule)}
                      selected={selectedRule?.rule_id === rule.rule_id}
                    />
                  ))}
                  {byStatus[status].length === 0 && (
                    <p className="text-gray-600 text-xs text-center py-4">—</p>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Rule detail */}
      {selectedRule && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="text-white font-bold text-base font-mono">{selectedRule.rule_id}</h2>
              <p className="text-gray-500 text-xs mt-0.5">v{selectedRule.rule_version} · Updated {formatTime(selectedRule.updated_at)}</p>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs text-gray-500">Move to:</span>
              {STATUS_ORDER.filter((s) => s !== selectedRule.status).map((s) => (
                <button
                  key={s}
                  onClick={() => openStatusModal(s)}
                  className={`px-3 py-1 rounded text-xs font-medium border ${STATUS_COLORS[s]} ${STATUS_LABEL_COLORS[s]}`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          <div>
            <h3 className="text-gray-400 text-xs font-medium uppercase tracking-wide mb-2">Sigma YAML / Registry Info</h3>
            <SigmaViewer rule={selectedRule} />
          </div>
        </div>
      )}

      {/* Fail-closed modal */}
      {pendingStatus && selectedRule && (
        <FailClosedModal
          rule={selectedRule}
          targetStatus={pendingStatus}
          onConfirm={handleConfirm}
          onCancel={() => { setPendingStatus(null); setModalError(null); }}
          submitting={updateStatus.isPending}
          error={modalError}
        />
      )}
    </div>
  );
}
