import clsx from 'clsx';

type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | string;

interface SeverityBadgeProps {
  severity: SeverityLevel;
  className?: string;
}

const SEVERITY_CLASSES: Record<string, string> = {
  critical: 'bg-red-600/20 text-red-400 border border-red-600/40',
  high: 'bg-orange-500/20 text-orange-400 border border-orange-500/40',
  medium: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40',
  low: 'bg-blue-400/20 text-blue-400 border border-blue-400/40',
};

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const key = severity?.toLowerCase() ?? '';
  const colorClass = SEVERITY_CLASSES[key] ?? 'bg-gray-600/20 text-gray-400 border border-gray-600/40';
  return (
    <span
      className={clsx(
        'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium uppercase tracking-wide',
        colorClass,
        className,
      )}
    >
      {severity}
    </span>
  );
}
