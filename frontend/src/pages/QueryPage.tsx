/**
 * QueryPage.tsx — Ad-hoc SELECT console for the SIEMhunter ClickHouse database.
 *
 * All queries are proxied through POST /v1/query. SELECT-only enforcement is done
 * server-side: the API parses the SQL, rejects any statement containing mutation
 * keywords (INSERT, UPDATE, DELETE, DROP, ALTER, TRUNCATE, CREATE, etc.), and returns
 * 400 before the query reaches ClickHouse. Client-side filtering is not used because
 * it is trivially bypassed — a determined user could POST directly to the API.
 *
 * The 6 pre-built templates answer the most common analyst questions without
 * requiring ClickHouse SQL knowledge:
 *   1. "What happened in the last hour?" (recent events)
 *   2. "Which rules fired most today?" (top rule hits)
 *   3. "Where is my data coming from?" (event count by source)
 *   4. "What looks statistically unusual?" (high anomaly scores)
 *   5. "Is Kerberoasting happening?" (EID 4769 with non-machine service tickets)
 *   6. "What hasn't been forwarded to Sentinel yet?" (unforwarded hits)
 *
 * Ctrl+Enter (or Cmd+Enter on macOS) submits the query — standard SQL-tool convention.
 */
import { useState } from 'react';
import { api, ApiClientError } from '../api/client';
import { QueryResult } from '../components/QueryResult';
import { ClaudeChatbar } from '../components/ClaudeChatbar';
import type { QueryResponse } from '../types/api';

const TEMPLATES: { label: string; sql: string }[] = [
  {
    label: 'Recent events — last hour',
    sql: 'SELECT TimeGenerated, HostName, EventID, SubjectUserName, SrcIpAddr, ProvenanceTag\nFROM siemhunter.security_events\nWHERE TimeGenerated >= now() - INTERVAL 1 HOUR\nORDER BY TimeGenerated DESC\nLIMIT 100',
  },
  {
    label: 'Top rule hits — last 24h',
    sql: 'SELECT rule_id, severity, count() AS hit_count, max(anomaly_score) AS max_anomaly\nFROM siemhunter.detection_hits\nWHERE created_at >= now() - INTERVAL 24 HOUR\nGROUP BY rule_id, severity\nORDER BY hit_count DESC\nLIMIT 50',
  },
  {
    label: 'Event count by source',
    sql: 'SELECT ProvenanceTag, count() AS event_count\nFROM siemhunter.security_events\nWHERE TimeGenerated >= now() - INTERVAL 24 HOUR\nGROUP BY ProvenanceTag\nORDER BY event_count DESC',
  },
  {
    label: 'High anomaly scores',
    sql: 'SELECT rule_id, anomaly_score, hit_count, severity, created_at\nFROM siemhunter.detection_hits\nWHERE anomaly_score > 0.7\nORDER BY anomaly_score DESC\nLIMIT 50',
  },
  {
    label: 'Kerberoasting candidates (EID 4769)',
    // ServiceName NOT LIKE '%$' filters out machine account service tickets (which end
    // in '$') to surface only human-account tickets that could indicate Kerberoasting.
    sql: "SELECT TimeGenerated, HostName, SubjectUserName, ServiceName, TargetUserName\nFROM siemhunter.security_events\nWHERE EventID = 4769 AND ServiceName NOT LIKE '%$'\nORDER BY TimeGenerated DESC\nLIMIT 100",
  },
  {
    label: 'Unforwarded detection hits',
    sql: 'SELECT hit_id, rule_id, severity, hit_count, created_at\nFROM siemhunter.detection_hits\nWHERE forwarded_at IS NULL\nORDER BY created_at DESC\nLIMIT 100',
  },
];

export function QueryPage() {
  const [sql, setSql] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<QueryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function runQuery() {
    if (!sql.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await api.query({ sql });
      setResult(res);
    } catch (e) {
      if (e instanceof ApiClientError) {
        setError(`[${e.code}] ${e.message}`);
      } else {
        setError('Unexpected error — check API connectivity.');
      }
    } finally {
      setLoading(false);
    }
  }

  function loadTemplate(template: (typeof TEMPLATES)[number]) {
    setSql(template.sql);
    setError(null);
    setResult(null);
  }

  return (
    <div className="p-6 flex flex-col gap-5">
      <h1 className="text-xl font-bold text-white">Query Console</h1>

      {/* Security note */}
      <div className="bg-blue-900/20 border border-blue-700/30 rounded-lg px-4 py-2.5 text-xs text-blue-300 flex items-start gap-2">
        <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M12 2a10 10 0 100 20 10 10 0 000-20z" />
        </svg>
        <span>
          SELECT-only queries are allowed. The API enforces a 10,000-row cap and 30s timeout.
          Mutation keywords (INSERT, UPDATE, DELETE, DROP, etc.) are rejected server-side with a 400 error.
        </span>
      </div>

      {/* Template picker */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs text-gray-400 font-medium">Templates:</span>
        {TEMPLATES.map((t) => (
          <button
            key={t.label}
            onClick={() => loadTemplate(t)}
            className="px-3 py-1 bg-gray-800 hover:bg-gray-700 text-gray-300 hover:text-white rounded text-xs border border-gray-700 hover:border-gray-600 transition-colors"
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* SQL editor */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-gray-800">
          <span className="text-xs text-gray-400 font-mono">SQL</span>
          <div className="flex gap-2">
            <button
              onClick={() => { setSql(''); setResult(null); setError(null); }}
              className="px-3 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs"
            >
              Clear
            </button>
            <button
              onClick={runQuery}
              disabled={loading || !sql.trim()}
              className="px-4 py-1 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-medium disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1.5"
            >
              {loading && (
                <svg className="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              )}
              {loading ? 'Running…' : 'Run Query'}
            </button>
          </div>
        </div>
        <textarea
          value={sql}
          onChange={(e) => setSql(e.target.value)}
          onKeyDown={(e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
              e.preventDefault();
              void runQuery();
            }
          }}
          placeholder="SELECT TimeGenerated, HostName, EventID FROM siemhunter.security_events LIMIT 100"
          rows={10}
          className="w-full bg-transparent px-4 py-3 text-gray-200 font-mono text-sm resize-none focus:outline-none placeholder-gray-700"
          spellCheck={false}
        />
        <div className="px-4 py-1.5 border-t border-gray-800 text-xs text-gray-600">
          Ctrl+Enter to run
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-4 text-red-400 text-sm font-mono">
          {error}
        </div>
      )}

      {/* Result */}
      {result && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
          <h2 className="text-white font-semibold text-sm mb-3">Result</h2>
          <QueryResult result={result} />
        </div>
      )}

      <ClaudeChatbar />
    </div>
  );
}
