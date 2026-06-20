import clsx from 'clsx';

interface SentinelUnavailableProps {
  label?: string;
  className?: string;
}

export function SentinelUnavailable({
  label = 'Not available locally (Sentinel-side)',
  className,
}: SentinelUnavailableProps) {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 text-gray-500 text-sm italic',
        className,
      )}
    >
      <svg
        className="w-3.5 h-3.5 text-gray-600 flex-shrink-0"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        strokeWidth={2}
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M13 16h-1v-4h-1m1-4h.01M12 2a10 10 0 100 20 10 10 0 000-20z"
        />
      </svg>
      {label}
    </span>
  );
}
