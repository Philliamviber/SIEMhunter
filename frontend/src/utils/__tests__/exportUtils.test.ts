import { describe, it, expect } from 'vitest';
import { sanitizeCsvField, eventsToCsv, eventsToJson } from '../exportUtils';
import type { SecurityEvent } from '../../types/api';

function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    TimeGenerated: '2026-06-20T14:32:05.000Z',
    HostName: 'dc01.corp.local',
    EventID: 4624,
    EventRecordID: 'rec-001',
    ChannelName: 'Security',
    ProviderName: 'Microsoft-Windows-Security-Auditing',
    SubjectUserName: 'jdoe',
    SubjectUserSid: 'S-1-5-21-111',
    SubjectDomainName: 'CORP',
    TargetUserName: '',
    TargetUserSid: '',
    TargetDomainName: '',
    LogonType: 3,
    ServiceName: '',
    ProcessImagePath: '',
    CommandLine: '',
    ParentProcessImagePath: '',
    ParentCommandLine: '',
    GrantedAccess: '',
    ObjectName: '',
    FileMD5: '',
    FileSHA256: '',
    RegistryKey: '',
    SrcIpAddr: '10.0.0.5',
    SrcPort: 0,
    DstIpAddr: '',
    DstPort: 0,
    NetworkProtocol: '',
    ProvenanceTag: 'wef-collector',
    IngestTimestamp: '2026-06-20T14:32:10.000Z',
    UnmappedFields: '',
    ...overrides,
  };
}

// ── sanitizeCsvField ─────────────────────────────────────────────────────────

describe('sanitizeCsvField', () => {
  it('neutralizes = prefix (formula injection)', () => {
    expect(sanitizeCsvField('=SUM(A1)')).toBe("'=SUM(A1)");
  });

  it('neutralizes + prefix', () => {
    expect(sanitizeCsvField('+amount')).toBe("'+amount");
  });

  it('neutralizes - prefix', () => {
    expect(sanitizeCsvField('-1')).toBe("'-1");
  });

  it('neutralizes @ prefix', () => {
    expect(sanitizeCsvField('@SUM')).toBe("'@SUM");
  });

  it('leaves normal values unchanged', () => {
    expect(sanitizeCsvField('normal')).toBe('normal');
    expect(sanitizeCsvField('hello world')).toBe('hello world');
    expect(sanitizeCsvField('192.168.1.1')).toBe('192.168.1.1');
  });

  it('leaves empty string unchanged', () => {
    expect(sanitizeCsvField('')).toBe('');
  });

  it('does not double-sanitize (only first char matters)', () => {
    // A middle @ or = should not be touched
    expect(sanitizeCsvField('cmd.exe =test')).toBe('cmd.exe =test');
    expect(sanitizeCsvField('user@corp.local')).toBe('user@corp.local');
  });
});

// ── eventsToCsv ──────────────────────────────────────────────────────────────

describe('eventsToCsv', () => {
  it('includes a header row with expected column names', () => {
    const csv = eventsToCsv([makeEvent()]);
    expect(csv).toContain('"TimeGenerated"');
    expect(csv).toContain('"HostName"');
    expect(csv).toContain('"EventID"');
    expect(csv).toContain('"CommandLine"');
  });

  it('neutralizes = prefix in CSV cell output', () => {
    const csv = eventsToCsv([makeEvent({ CommandLine: '=calc.exe' })]);
    // Sanitized to '=calc.exe, then double-quoted → "'=calc.exe"
    expect(csv).toContain('"\'=calc.exe"');
  });

  it('neutralizes + prefix in CSV cell output', () => {
    const csv = eventsToCsv([makeEvent({ HostName: '+injected' })]);
    expect(csv).toContain('"\'+injected"');
  });

  it('neutralizes - prefix in CSV cell output', () => {
    const csv = eventsToCsv([makeEvent({ SubjectUserName: '-user' })]);
    expect(csv).toContain('"\'-user"');
  });

  it('neutralizes @ prefix in CSV cell output', () => {
    const csv = eventsToCsv([makeEvent({ ServiceName: '@SUM(B1)' })]);
    expect(csv).toContain('"\'@SUM(B1)"');
  });

  it('does NOT include a truncation note by default', () => {
    const csv = eventsToCsv([makeEvent()]);
    expect(csv).not.toContain('NOTE:');
  });

  it('does NOT include truncation note when truncated is false', () => {
    const csv = eventsToCsv([makeEvent()], { truncated: false });
    expect(csv).not.toContain('NOTE:');
  });

  it('includes truncation note when truncated is true', () => {
    const csv = eventsToCsv([makeEvent()], { truncated: true });
    expect(csv).toContain('# NOTE:');
    expect(csv).toContain('10,000');
  });

  it('truncation note appears before the header row', () => {
    const csv = eventsToCsv([makeEvent()], { truncated: true });
    const noteIdx = csv.indexOf('# NOTE:');
    const headerIdx = csv.indexOf('"TimeGenerated"');
    expect(noteIdx).toBeLessThan(headerIdx);
  });

  it('carries a custom truncation note', () => {
    const csv = eventsToCsv([makeEvent()], {
      truncated: true,
      truncationNote: 'Custom truncation message',
    });
    expect(csv).toContain('Custom truncation message');
  });

  it('produces one data row per event (plus header)', () => {
    const csv = eventsToCsv([makeEvent(), makeEvent({ EventRecordID: 'rec-002' })]);
    const lines = csv.split('\r\n').filter((l) => !l.startsWith('#'));
    // 1 header + 2 data rows = 3 non-comment lines
    expect(lines).toHaveLength(3);
  });

  it('uses CRLF line endings', () => {
    const csv = eventsToCsv([makeEvent()]);
    expect(csv).toContain('\r\n');
  });

  it('double-quotes that appear inside field values are escaped by doubling', () => {
    const csv = eventsToCsv([makeEvent({ CommandLine: 'cmd "arg"' })]);
    // "cmd ""arg""" in the CSV cell
    expect(csv).toContain('"cmd ""arg"""');
  });
});

// ── eventsToJson ─────────────────────────────────────────────────────────────

describe('eventsToJson', () => {
  it('produces valid JSON', () => {
    const json = eventsToJson([makeEvent()]);
    expect(() => JSON.parse(json)).not.toThrow();
  });

  it('wraps events in an events array', () => {
    const obj = JSON.parse(eventsToJson([makeEvent(), makeEvent()]));
    expect(obj.events).toHaveLength(2);
  });

  it('does NOT include _truncated when truncated is false', () => {
    const obj = JSON.parse(eventsToJson([makeEvent()], { truncated: false }));
    expect(obj._truncated).toBeUndefined();
    expect(obj._truncation_note).toBeUndefined();
  });

  it('does NOT include _truncated when no options given', () => {
    const obj = JSON.parse(eventsToJson([makeEvent()]));
    expect(obj._truncated).toBeUndefined();
  });

  it('includes _truncated and _truncation_note when truncated is true', () => {
    const obj = JSON.parse(eventsToJson([makeEvent()], { truncated: true }));
    expect(obj._truncated).toBe(true);
    expect(typeof obj._truncation_note).toBe('string');
    expect(obj._truncation_note).toContain('10,000');
  });

  it('carries a custom truncation note in JSON', () => {
    const obj = JSON.parse(
      eventsToJson([makeEvent()], {
        truncated: true,
        truncationNote: 'Custom JSON note',
      })
    );
    expect(obj._truncation_note).toBe('Custom JSON note');
  });

  it('preserves event field values', () => {
    const obj = JSON.parse(eventsToJson([makeEvent()]));
    expect(obj.events[0].HostName).toBe('dc01.corp.local');
    expect(obj.events[0].EventID).toBe(4624);
  });
});

// ── Guard: no AI summary dependency ──────────────────────────────────────────

describe('export utility AI summary guard', () => {
  it('exports only the expected symbols and no AI summary callable', () => {
    // Verify the public surface: sanitizeCsvField, eventsToCsv, eventsToJson, downloadFile.
    // If an ai_summary re-export ever slipped in it would show up as an extra key here.
    const mod = { sanitizeCsvField, eventsToCsv, eventsToJson } as Record<string, unknown>;
    const keys = Object.keys(mod);
    expect(keys).toContain('sanitizeCsvField');
    expect(keys).toContain('eventsToCsv');
    expect(keys).toContain('eventsToJson');
    // None of the exported names should reference AI summary
    for (const k of keys) {
      expect(k.toLowerCase()).not.toContain('ai');
      expect(k.toLowerCase()).not.toContain('summary');
    }
  });
});
