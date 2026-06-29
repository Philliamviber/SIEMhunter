/**
 * SigmaAuthorPage.tsx — In-UI Sigma rule authoring with compile preview and dry-run.
 *
 * Flow:
 *  1. Analyst types a Sigma YAML rule in the textarea editor.
 *  2. "Compile & Preview SQL" → POST /v1/sigma/compile → shows compiled ClickHouse SQL
 *     or a plain-English compile error.
 *  3. "Dry-Run (last 24h)" → POST /v1/sigma/dryrun → shows bounded sample matches
 *     and a count, or error.
 *
 * Security notes:
 *  - No rule_registry write occurs here; promotion is PR8.
 *  - The dry-run executes on a read-only ClickHouse connection server-side.
 *  - The server rejects any compiled SQL that is not a single SELECT.
 */
import { useState } from 'react';
import { useSigmaCompile, useSigmaDryRun } from '../hooks/useApi';
import { ApiClientError } from '../api/client';
import type { SigmaCompileResponse, SigmaDryRunResponse } from '../types/api';

const STARTER_YAML = `title: Example — Kerberoasting Detection
id: 00000000-0000-0000-0000-000000000001
status: test
description: Detects Kerberoasting by looking for TGS requests with RC4 encryption.
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        ServiceName|endswith: '$'
    condition: selection
level: high
tags:
    - attack.t1558.003
    - attack.credential_access
`.trimStart();

// ── Sub-components ────────────────────────────────────────────────────────────

function CompileResult({ result }: { result: SigmaCompileResponse }) {
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3">
        <span className="text-xs text-green-400 font-semibold uppercase tracking-wide">Compiled successfully</span>
        {result.title && (
          <span className="text-xs text-gray-400 truncate">{result.title}</span>
        )}
        {result.rule_id && (
          <span className="text-xs text-gray-600 font-mono truncate">{result.rule_id}</span>
        )}
      </div>
      <pre className="bg-gray-950 border border-gray-800 rounded p-3 text-xs text-green-300 font-mono overflow-x-auto whitespace-pre-wrap break-all">
        {result.sql}
      </pre>
    </div>
  );
}

interface DryRunResultProps {
  result: SigmaDryRunResponse;
}

function DryRunResult({ result }: DryRunResultProps) {
  const columns = result.sample_rows.length > 0 ? Object.keys(result.sample_rows[0]) : [];

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-4 text-xs">
        <span className="text-blue-400 font-semibold uppercase tracking-wide">Dry-run complete</span>
        <span data-testid="dryrun-match-count" className="text-white">
          {result.match_count} match{result.match_count !== 1 ? 'es' : ''} in last 24h
        </span>
        <span className="text-gray-500">{result.execution_time_ms.toFixed(1)} ms</span>
      </div>

      {result.match_count === 0 ? (
        <p data-testid="dryrun-no-results" className="text-gray-500 text-xs">No events matched in the last 24 hours.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="text-xs w-full border-collapse">
            <thead>
              <tr className="border-b border-gray-700">
                {columns.map((col) => (
                  <th key={col} className="text-left px-2 py-1.5 text-gray-400 font-medium whitespace-nowrap">
                    {col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {result.sample_rows.slice(0, 20).map((row, i) => (
                <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  {columns.map((col) => (
                    <td key={col} className="px-2 py-1.5 text-gray-300 font-mono max-w-xs truncate">
                      {String(row[col] ?? '')}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          {result.sample_rows.length > 20 && (
            <p className="text-gray-600 text-xs mt-1 px-2">
              Showing 20 of {result.match_count} matches.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function ErrorBox({ message }: { message: string }) {
  return (
    <div className="bg-red-900/20 border border-red-700/40 rounded p-3 text-red-400 text-xs font-mono whitespace-pre-wrap">
      {message}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function SigmaAuthorPage() {
  const [yaml, setYaml] = useState(STARTER_YAML);
  const [compileResult, setCompileResult] = useState<SigmaCompileResponse | null>(null);
  const [compileError, setCompileError] = useState<string | null>(null);
  const [dryRunResult, setDryRunResult] = useState<SigmaDryRunResponse | null>(null);
  const [dryRunError, setDryRunError] = useState<string | null>(null);

  const compile = useSigmaCompile();
  const dryRun = useSigmaDryRun();

  async function handleCompile() {
    setCompileResult(null);
    setCompileError(null);
    try {
      const result = await compile.mutateAsync({ sigma_yaml: yaml });
      setCompileResult(result);
    } catch (e) {
      setCompileError(
        e instanceof ApiClientError ? e.message : 'Unexpected error during compilation.',
      );
    }
  }

  async function handleDryRun() {
    setDryRunResult(null);
    setDryRunError(null);
    try {
      const result = await dryRun.mutateAsync({ sigma_yaml: yaml });
      setDryRunResult(result);
    } catch (e) {
      setDryRunError(
        e instanceof ApiClientError ? e.message : 'Unexpected error during dry-run.',
      );
    }
  }

  return (
    <div className="p-6 flex flex-col gap-5 max-w-5xl">
      <div>
        <h1 className="text-xl font-bold text-white">Sigma Rule Author</h1>
        <p className="text-gray-500 text-sm mt-1">
          Write a Sigma rule, compile it to ClickHouse SQL, then dry-run it against the last 24h of
          events. Promotion to the rule registry happens in the Rules page (PR8).
        </p>
      </div>

      {/* YAML editor */}
      <div className="space-y-2">
        <label className="block text-xs font-medium text-gray-400 uppercase tracking-wide">
          Sigma YAML
        </label>
        <textarea
          data-testid="sigma-editor"
          value={yaml}
          onChange={(e) => {
            setYaml(e.target.value);
            setCompileResult(null);
            setCompileError(null);
            setDryRunResult(null);
            setDryRunError(null);
          }}
          spellCheck={false}
          rows={20}
          className="w-full bg-gray-950 border border-gray-700 rounded p-3 text-sm text-gray-200 font-mono resize-y focus:outline-none focus:border-gray-500"
          placeholder="Paste or type your Sigma rule YAML here…"
        />
      </div>

      {/* Action buttons */}
      <div className="flex gap-3 flex-wrap">
        <button
          data-testid="compile-btn"
          onClick={handleCompile}
          disabled={compile.isPending || !yaml.trim()}
          className="px-4 py-2 bg-blue-700 hover:bg-blue-600 text-white rounded text-sm font-medium disabled:opacity-40 transition-colors"
        >
          {compile.isPending ? 'Compiling…' : 'Compile & Preview SQL'}
        </button>
        <button
          data-testid="dryrun-btn"
          onClick={handleDryRun}
          disabled={dryRun.isPending || !yaml.trim()}
          className="px-4 py-2 bg-purple-700 hover:bg-purple-600 text-white rounded text-sm font-medium disabled:opacity-40 transition-colors"
        >
          {dryRun.isPending ? 'Running…' : 'Dry-Run (last 24h)'}
        </button>
      </div>

      {/* Compile result */}
      {(compileResult || compileError) && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-2">
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wide">
            Compile Result
          </h2>
          {compileResult && <CompileResult result={compileResult} />}
          {compileError && <ErrorBox message={compileError} />}
        </div>
      )}

      {/* Dry-run result */}
      {(dryRunResult || dryRunError) && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-2">
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wide">
            Dry-Run Result
          </h2>
          {dryRunResult && <DryRunResult result={dryRunResult} />}
          {dryRunError && <ErrorBox message={dryRunError} />}
        </div>
      )}

      {/* Info banner */}
      <div className="bg-gray-800/30 border border-gray-700/40 rounded-lg p-4 text-xs text-gray-500 space-y-1">
        <p>
          <strong className="text-gray-400">Read-only dry-run:</strong> the server executes the
          compiled SQL on a read-only ClickHouse connection bounded to the last 24 hours, with a hard
          200-row LIMIT and 15-second timeout.
        </p>
        <p>
          <strong className="text-gray-400">No writes:</strong> this page never writes to the rule
          registry. Use the Rules page to promote a tested rule to production.
        </p>
      </div>
    </div>
  );
}
