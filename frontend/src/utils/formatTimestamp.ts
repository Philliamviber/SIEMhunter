// Single authoritative timestamp formatter — UTC with fixed EST offset
export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    const pad = (n: number) => String(n).padStart(2, '0');
    const utcDate = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
    const utcTime = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
    // EST is fixed UTC-5 (no DST adjustment — decision OQ-4)
    const estDate = new Date(d.getTime() - 5 * 60 * 60 * 1000);
    const estTime = `${pad(estDate.getUTCHours())}:${pad(estDate.getUTCMinutes())}:${pad(estDate.getUTCSeconds())}`;
    return `${utcDate} ${utcTime} UTC (${estTime} EST)`;
  } catch {
    return iso ?? '—';
  }
}
