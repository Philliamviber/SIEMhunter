import type { QueryResponse } from '../types/api';

interface QueryResultProps {
  result: QueryResponse;
}

export function QueryResult({ result }: QueryResultProps) {
  const columns = result.rows.length > 0 ? Object.keys(result.rows[0]) : [];

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-4 text-sm text-gray-400">
        <span>{result.row_count} row{result.row_count !== 1 ? 's' : ''}</span>
        <span>•</span>
        <span>{result.execution_time_ms.toFixed(1)} ms</span>
        {result.truncated && (
          <>
            <span>•</span>
            <span className="text-yellow-400 font-medium">
              Result truncated at {result.row_count} rows — add a LIMIT clause to see more
            </span>
          </>
        )}
      </div>
      {columns.length > 0 ? (
        <div className="overflow-x-auto scrollbar-thin border border-gray-800 rounded">
          <table className="w-full text-sm text-left">
            <thead>
              <tr className="border-b border-gray-800 bg-gray-900">
                {columns.map((col) => (
                  <th
                    key={col}
                    className="px-3 py-2 text-xs font-medium text-gray-400 uppercase tracking-wide whitespace-nowrap"
                  >
                    {col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {result.rows.map((row, i) => (
                <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  {columns.map((col) => (
                    <td key={col} className="px-3 py-2 text-gray-300 font-mono text-xs">
                      {row[col] === null ? (
                        <span className="text-gray-600">null</span>
                      ) : (
                        String(row[col])
                      )}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-gray-500 text-sm">Query returned no rows.</p>
      )}
    </div>
  );
}
