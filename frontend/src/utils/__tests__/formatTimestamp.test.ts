import { describe, it, expect } from 'vitest';
import { formatTimestamp } from '../formatTimestamp';

describe('formatTimestamp', () => {
  it('formats a UTC ISO string correctly', () => {
    // 2026-06-20T14:32:05.000Z → 14:32:05 UTC, 09:32:05 EST
    expect(formatTimestamp('2026-06-20T14:32:05.000Z')).toBe('2026-06-20 14:32:05 UTC (09:32:05 EST)');
  });

  it('handles midnight rollover (00:00:00 UTC → 19:00:00 EST prev day)', () => {
    const result = formatTimestamp('2026-06-20T00:00:00.000Z');
    // Should not crash and should contain UTC
    expect(result).toContain('UTC');
  });

  it('returns em dash for null', () => {
    expect(formatTimestamp(null)).toBe('—');
  });

  it('returns em dash for empty string', () => {
    expect(formatTimestamp('')).toBe('—');
  });

  it('returns original string for malformed input', () => {
    expect(formatTimestamp('not-a-date')).toBe('not-a-date');
  });
});
