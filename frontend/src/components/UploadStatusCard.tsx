/**
 * UploadStatusCard — displays the result of a completed file upload.
 *
 * Security note (MUST 7): all values from UploadResponse are rendered as
 * plain React text nodes. No dangerouslySetInnerHTML is used.
 */
import type { UploadResponse } from '../types/api';

interface Props {
  result: UploadResponse;
}

function StatusBadge({ status }: { status: UploadResponse['status'] }) {
  const styles: Record<UploadResponse['status'], string> = {
    success: 'bg-green-900/40 text-green-400 border border-green-700/40',
    partial: 'bg-yellow-900/40 text-yellow-400 border border-yellow-700/40',
    failed: 'bg-red-900/40 text-red-400 border border-red-700/40',
  };
  const labels: Record<UploadResponse['status'], string> = {
    success: 'Success',
    partial: 'Partial',
    failed: 'Failed',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${styles[status]}`}>
      {labels[status]}
    </span>
  );
}

export function UploadStatusCard({ result }: Props) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-white font-semibold text-sm">Upload Result</h3>
        <StatusBadge status={result.status} />
      </div>

      {/* File name — plain text node (MUST 7) */}
      <div className="space-y-1">
        <div className="text-xs text-gray-500">File</div>
        <div className="text-gray-300 text-sm font-mono break-all">{result.filename}</div>
      </div>

      {/* ProvenanceTag — plain text node (MUST 7) */}
      <div className="space-y-1">
        <div className="text-xs text-gray-500">ProvenanceTag (server-assigned)</div>
        <div className="text-purple-400 text-sm font-mono break-all">{result.provenance_tag}</div>
      </div>

      {/* Counts */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-gray-800 rounded-lg p-3 text-center">
          <div className="text-white text-xl font-bold">{result.events_parsed}</div>
          <div className="text-gray-500 text-xs mt-0.5">Parsed</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-3 text-center">
          <div className="text-green-400 text-xl font-bold">{result.events_written}</div>
          <div className="text-gray-500 text-xs mt-0.5">Written</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-3 text-center">
          <div className="text-yellow-400 text-xl font-bold">{result.events_unmapped}</div>
          <div className="text-gray-500 text-xs mt-0.5">Unmapped Fields</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-3 text-center">
          <div className={`text-xl font-bold ${result.error_count > 0 ? 'text-red-400' : 'text-gray-400'}`}>
            {result.error_count}
          </div>
          <div className="text-gray-500 text-xs mt-0.5">Errors</div>
        </div>
      </div>
    </div>
  );
}
