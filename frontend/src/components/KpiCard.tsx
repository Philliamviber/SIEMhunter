import clsx from 'clsx';
import type { ReactNode } from 'react';

interface KpiCardProps {
  title: string;
  value: ReactNode;
  badge?: ReactNode;
  trend?: ReactNode;
  className?: string;
  loading?: boolean;
}

export function KpiCard({ title, value, badge, trend, className, loading }: KpiCardProps) {
  return (
    <div
      className={clsx(
        'bg-gray-900 border border-gray-800 rounded-lg p-4 flex flex-col gap-2',
        className,
      )}
    >
      <div className="flex items-center justify-between">
        <span className="text-gray-400 text-sm font-medium uppercase tracking-wide">{title}</span>
        {badge && <span>{badge}</span>}
      </div>
      {loading ? (
        <div className="h-8 bg-gray-800 rounded animate-pulse w-24" />
      ) : (
        <div className="text-2xl font-bold text-white truncate">{value}</div>
      )}
      {trend && <div className="text-xs text-gray-500">{trend}</div>}
    </div>
  );
}
