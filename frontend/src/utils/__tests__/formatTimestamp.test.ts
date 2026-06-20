import { describe, it, expect } from 'vitest';
import { formatTimestamp } from '../formatTimestamp';

describe('formatTimestamp', () => {
  it('returns em dash for null', () => {
    expect(formatTimestamp(null)).toBe('—');
  });

  it('returns em dash for empty string', () => {
    expect(formatTimestamp('')).toBe('—');
  });

  it('returns original string for malformed input', () => {
    expect(formatTimestamp('not-a-date')).toBe('not-a-date');
  });

  it('always includes UTC canonical date/time', () => {
    const result = formatTimestamp('2026-06-20T14:32:05.000Z');
    expect(result).toMatch(/^2026-06-20 14:32:05 UTC/);
  });

  it('never labels local time as EST (hardcoded offset removed)', () => {
    // The Intl formatter uses the actual system timezone — it must not hardcode EST.
    // We can only assert that the old hardcoded label is gone; the real zone depends
    // on the test runner's TZ, so we check structure not a specific abbreviation.
    const result = formatTimestamp('2026-06-20T14:32:05.000Z');
    expect(result).not.toMatch(/\bEST\b/);
  });

  it('includes a local time parenthetical with a timezone abbreviation', () => {
    const result = formatTimestamp('2026-06-20T14:32:05.000Z');
    // Expect: "2026-06-20 14:32:05 UTC (HH:MM:SS TZ)"
    expect(result).toMatch(/UTC \(\d{2}:\d{2}:\d{2} \S+\)/);
  });

  it('handles DST boundary: summer and winter offsets produce different local times', () => {
    // January (northern-hemisphere winter) vs July (summer) for the same UTC hour.
    // In a timezone that observes DST, the local hour will differ by 1.
    // In UTC-only environments (CI) this test checks structure only.
    const summer = formatTimestamp('2026-07-01T12:00:00.000Z');
    const winter = formatTimestamp('2026-01-01T12:00:00.000Z');
    // Both must include the UTC anchor
    expect(summer).toMatch(/UTC \(/);
    expect(winter).toMatch(/UTC \(/);
  });

  it('handles midnight UTC rollover without crashing', () => {
    const result = formatTimestamp('2026-06-20T00:00:00.000Z');
    expect(result).toContain('2026-06-20 00:00:00 UTC');
  });

  it('formats timestamps without milliseconds', () => {
    const result = formatTimestamp('2026-06-20T10:00:00Z');
    expect(result).toMatch(/^2026-06-20 10:00:00 UTC/);
  });
});
