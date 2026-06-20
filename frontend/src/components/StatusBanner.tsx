import clsx from 'clsx';
import type { StatusResponse } from '../types/api';

interface StatusBannerProps {
  status: StatusResponse | undefined;
  loading?: boolean;
  error?: boolean;
}

function deriveLevel(status: StatusResponse): 'green' | 'amber' | 'red' {
  if (status.clickhouse !== 'ok') return 'red';
  const allAlive = status.normalization_alive && status.detection_alive && status.forwarder_alive;
  if (!allAlive) return 'amber';
  if (status.pending_retry_queue > 0) return 'amber';
  return 'green';
}

const LEVEL_STYLES = {
  green: {
    banner: 'bg-green-900/30 border-green-700/40 text-green-300',
    dot: 'bg-green-400',
    label: 'All systems operational',
  },
  amber: {
    banner: 'bg-yellow-900/30 border-yellow-700/40 text-yellow-300',
    dot: 'bg-yellow-400',
    label: 'Degraded — one or more services impaired',
  },
  red: {
    banner: 'bg-red-900/30 border-red-700/40 text-red-300',
    dot: 'bg-red-500',
    label: 'Critical — ClickHouse unreachable',
  },
};

export function StatusBanner({ status, loading, error }: StatusBannerProps) {
  if (loading) {
    return (
      <div className="h-10 bg-gray-800 rounded-lg animate-pulse" />
    );
  }

  if (error || !status) {
    return (
      <div className="border border-red-700/40 bg-red-900/20 rounded-lg px-4 py-2 text-red-400 text-sm">
        Unable to fetch pipeline status
      </div>
    );
  }

  const level = deriveLevel(status);
  const styles = LEVEL_STYLES[level];

  return (
    <div className={clsx('border rounded-lg px-4 py-2 flex items-center gap-3 text-sm', styles.banner)}>
      <span className={clsx('inline-block w-2.5 h-2.5 rounded-full flex-shrink-0', styles.dot)} />
      <span className="font-medium">{styles.label}</span>
      {status.pending_retry_queue > 0 && (
        <span className="ml-auto text-yellow-400 text-xs">
          Retry queue: {status.pending_retry_queue} item{status.pending_retry_queue !== 1 ? 's' : ''}
        </span>
      )}
    </div>
  );
}
