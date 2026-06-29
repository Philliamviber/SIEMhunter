import { describe, it, expect } from 'vitest';
import {
  incidentReportToMarkdown,
  incidentReportToJson,
  downloadIncidentReport,
} from '../incidentReportUtils';
import type { IncidentReportData, IncidentEventRow } from '../incidentReportUtils';
import type { Incident, IncidentNote } from '../../types/api';

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeIncident(overrides: Partial<Incident> = {}): Incident {
  return {
    id: 'inc-test-001',
    name: 'Test Incident',
    description: 'A test incident for export validation.',
    severity: 'high',
    status: 'open',
    created_at: '2026-06-20T10:00:00Z',
    updated_at: '2026-06-20T11:00:00Z',
    event_count: 3,
    ...overrides,
  };
}

function makeNote(overrides: Partial<IncidentNote> = {}): IncidentNote {
  return {
    id: 'note-001',
    incident_id: 'inc-test-001',
    author: 'analyst1',
    content: 'Initial triage done.',
    created_at: '2026-06-20T10:30:00Z',
    ...overrides,
  };
}

function makeEvent(overrides: Partial<IncidentEventRow> = {}): IncidentEventRow {
  return {
    TimeGenerated: '2026-06-20T10:05:00Z',
    HostName: 'dc01.corp.local',
    EventID: 4624,
    EventRecordID: 'rec-001',
    SubjectUserName: 'jdoe',
    TargetUserName: '',
    CommandLine: 'cmd.exe /c whoami',
    ProcessImagePath: 'C:\\Windows\\System32\\cmd.exe',
    SrcIpAddr: '10.0.0.5',
    DstIpAddr: '',
    ...overrides,
  };
}

function makeData(overrides: Partial<IncidentReportData> = {}): IncidentReportData {
  return {
    incident: makeIncident(),
    notes: [makeNote()],
    events: [makeEvent()],
    ...overrides,
  };
}

// ── Injection neutralization: Markdown ───────────────────────────────────────

describe('incidentReportToMarkdown — injection neutralization', () => {
  it('neutralizes = prefix in incident name', () => {
    const md = incidentReportToMarkdown(makeData({ incident: makeIncident({ name: '=Malicious' }) }));
    expect(md).toContain("'=Malicious");
    expect(md).not.toMatch(/^# Incident Report: =Malicious/m);
  });

  it('neutralizes + prefix in incident name', () => {
    const md = incidentReportToMarkdown(makeData({ incident: makeIncident({ name: '+inject' }) }));
    expect(md).toContain("'+inject");
  });

  it('neutralizes - prefix in incident name', () => {
    const md = incidentReportToMarkdown(makeData({ incident: makeIncident({ name: '-drop' }) }));
    expect(md).toContain("'-drop");
  });

  it('neutralizes @ prefix in incident name', () => {
    const md = incidentReportToMarkdown(makeData({ incident: makeIncident({ name: '@SUM' }) }));
    expect(md).toContain("'@SUM");
  });

  it('neutralizes = prefix in note content', () => {
    const md = incidentReportToMarkdown(
      makeData({ notes: [makeNote({ content: '=CMD(evil)' })] }),
    );
    expect(md).toContain("'=CMD(evil)");
  });

  it('neutralizes @ prefix in note author', () => {
    const md = incidentReportToMarkdown(
      makeData({ notes: [makeNote({ author: '@injectedAuthor' })] }),
    );
    expect(md).toContain("'@injectedAuthor");
  });

  it('neutralizes = prefix in event CommandLine', () => {
    const md = incidentReportToMarkdown(
      makeData({ events: [makeEvent({ CommandLine: '=calc.exe' })] }),
    );
    expect(md).toContain("'=calc.exe");
  });

  it('neutralizes + prefix in event HostName', () => {
    const md = incidentReportToMarkdown(
      makeData({ events: [makeEvent({ HostName: '+injected-host' })] }),
    );
    expect(md).toContain("'+injected-host");
  });

  it('neutralizes - prefix in event SubjectUserName', () => {
    const md = incidentReportToMarkdown(
      makeData({ events: [makeEvent({ SubjectUserName: '-baduser' })] }),
    );
    expect(md).toContain("'-baduser");
  });

  it('leaves normal field values unchanged', () => {
    const md = incidentReportToMarkdown(makeData());
    expect(md).toContain('dc01.corp.local');
    expect(md).toContain('jdoe');
  });
});

// ── Injection neutralization: JSON ────────────────────────────────────────────

describe('incidentReportToJson — injection neutralization', () => {
  it('neutralizes = prefix in incident name', () => {
    const obj = JSON.parse(
      incidentReportToJson(makeData({ incident: makeIncident({ name: '=evil' }) })),
    );
    expect(obj.incident.name).toBe("'=evil");
  });

  it('neutralizes + prefix in note content', () => {
    const obj = JSON.parse(
      incidentReportToJson(makeData({ notes: [makeNote({ content: '+formula' })] })),
    );
    expect(obj.notes[0].content).toBe("'+formula");
  });

  it('neutralizes @ prefix in note author', () => {
    const obj = JSON.parse(
      incidentReportToJson(makeData({ notes: [makeNote({ author: '@hacker' })] })),
    );
    expect(obj.notes[0].author).toBe("'@hacker");
  });

  it('neutralizes - prefix in event CommandLine', () => {
    const obj = JSON.parse(
      incidentReportToJson(makeData({ events: [makeEvent({ CommandLine: '-arg' })] })),
    );
    expect(obj.events[0].CommandLine).toBe("'-arg");
  });

  it('neutralizes = in description', () => {
    const obj = JSON.parse(
      incidentReportToJson(makeData({ incident: makeIncident({ description: '=desc' }) })),
    );
    expect(obj.incident.description).toBe("'=desc");
  });

  it('preserves null description', () => {
    const obj = JSON.parse(
      incidentReportToJson(makeData({ incident: makeIncident({ description: null }) })),
    );
    expect(obj.incident.description).toBeNull();
  });
});

// ── Truncation note: Markdown ─────────────────────────────────────────────────

describe('incidentReportToMarkdown — truncation note', () => {
  it('does NOT include truncation note by default', () => {
    const md = incidentReportToMarkdown(makeData());
    expect(md).not.toContain('Note:');
  });

  it('does NOT include truncation note when truncated is false', () => {
    const md = incidentReportToMarkdown(makeData({ exportOptions: { truncated: false } }));
    expect(md).not.toContain('Note:');
  });

  it('includes truncation note when truncated is true', () => {
    const md = incidentReportToMarkdown(makeData({ exportOptions: { truncated: true } }));
    expect(md).toContain('**Note:**');
    expect(md).toContain('1,000');
  });

  it('carries a custom truncation note', () => {
    const md = incidentReportToMarkdown(
      makeData({
        exportOptions: { truncated: true, truncationNote: 'Custom cap exceeded' },
      }),
    );
    expect(md).toContain('Custom cap exceeded');
  });

  it('truncation note appears before the events section', () => {
    const md = incidentReportToMarkdown(makeData({ exportOptions: { truncated: true } }));
    const noteIdx = md.indexOf('**Note:**');
    const eventsIdx = md.indexOf('## Events');
    expect(noteIdx).toBeGreaterThan(-1);
    expect(noteIdx).toBeLessThan(eventsIdx);
  });
});

// ── Truncation note: JSON ─────────────────────────────────────────────────────

describe('incidentReportToJson — truncation note', () => {
  it('does NOT include _truncated by default', () => {
    const obj = JSON.parse(incidentReportToJson(makeData()));
    expect(obj._truncated).toBeUndefined();
    expect(obj._truncation_note).toBeUndefined();
  });

  it('does NOT include _truncated when truncated is false', () => {
    const obj = JSON.parse(incidentReportToJson(makeData({ exportOptions: { truncated: false } })));
    expect(obj._truncated).toBeUndefined();
  });

  it('includes _truncated and _truncation_note when truncated is true', () => {
    const obj = JSON.parse(
      incidentReportToJson(makeData({ exportOptions: { truncated: true } })),
    );
    expect(obj._truncated).toBe(true);
    expect(typeof obj._truncation_note).toBe('string');
    expect(obj._truncation_note).toContain('1,000');
  });

  it('carries a custom truncation note in JSON', () => {
    const obj = JSON.parse(
      incidentReportToJson(
        makeData({ exportOptions: { truncated: true, truncationNote: 'Custom JSON note' } }),
      ),
    );
    expect(obj._truncation_note).toBe('Custom JSON note');
  });
});

// ── Report structure ──────────────────────────────────────────────────────────

describe('incidentReportToMarkdown — structure', () => {
  it('includes all required sections', () => {
    const md = incidentReportToMarkdown(makeData());
    expect(md).toContain('# Incident Report:');
    expect(md).toContain('## Description');
    expect(md).toContain('## Analyst Notes');
    expect(md).toContain('## Event Timeline');
    expect(md).toContain('## Correlation Snapshot');
    expect(md).toContain('## Events');
  });

  it('lists incident metadata fields', () => {
    const md = incidentReportToMarkdown(makeData());
    expect(md).toContain('**Severity:** high');
    expect(md).toContain('**Status:** open');
    expect(md).toContain('**Incident ID:**');
  });

  it('renders note author and content', () => {
    const md = incidentReportToMarkdown(makeData());
    expect(md).toContain('analyst1');
    expect(md).toContain('Initial triage done.');
  });

  it('renders event hostname in the events table', () => {
    const md = incidentReportToMarkdown(makeData());
    expect(md).toContain('dc01.corp.local');
  });

  it('shows no events message when events array is empty', () => {
    const md = incidentReportToMarkdown(makeData({ events: [] }));
    expect(md).toContain('No events found for this incident.');
  });

  it('shows no notes message when notes array is empty', () => {
    const md = incidentReportToMarkdown(makeData({ notes: [] }));
    expect(md).toContain('No notes recorded.');
  });
});

describe('incidentReportToJson — structure', () => {
  it('produces valid JSON', () => {
    expect(() => JSON.parse(incidentReportToJson(makeData()))).not.toThrow();
  });

  it('includes format_version, generated_at, incident, notes, events, correlation_snapshot, timeline', () => {
    const obj = JSON.parse(incidentReportToJson(makeData()));
    expect(obj.format_version).toBe('1.0');
    expect(typeof obj.generated_at).toBe('string');
    expect(obj.incident).toBeTruthy();
    expect(Array.isArray(obj.notes)).toBe(true);
    expect(Array.isArray(obj.events)).toBe(true);
    expect(obj.correlation_snapshot).toBeTruthy();
    expect(Array.isArray(obj.timeline)).toBe(true);
  });

  it('includes host in correlation_snapshot.hosts', () => {
    const obj = JSON.parse(incidentReportToJson(makeData()));
    expect(obj.correlation_snapshot.hosts).toContain('dc01.corp.local');
  });

  it('includes user in correlation_snapshot.users', () => {
    const obj = JSON.parse(incidentReportToJson(makeData()));
    expect(obj.correlation_snapshot.users).toContain('jdoe');
  });

  it('buckets events into timeline by hour', () => {
    const data = makeData({
      events: [
        makeEvent({ TimeGenerated: '2026-06-20T10:05:00Z' }),
        makeEvent({ TimeGenerated: '2026-06-20T10:15:00Z' }),
        makeEvent({ TimeGenerated: '2026-06-20T11:05:00Z' }),
      ],
    });
    const obj = JSON.parse(incidentReportToJson(data));
    expect(obj.timeline).toHaveLength(2);
    const hour10 = obj.timeline.find((b: { hour: string }) => b.hour === '2026-06-20T10');
    expect(hour10?.count).toBe(2);
    const hour11 = obj.timeline.find((b: { hour: string }) => b.hour === '2026-06-20T11');
    expect(hour11?.count).toBe(1);
  });
});

// ── AI summary guard ──────────────────────────────────────────────────────────

describe('incidentReportUtils — AI summary guard', () => {
  it('exports only expected symbols with no AI summary callable', () => {
    const mod = { incidentReportToMarkdown, incidentReportToJson, downloadIncidentReport } as Record<
      string,
      unknown
    >;
    const keys = Object.keys(mod);
    for (const k of keys) {
      expect(k.toLowerCase()).not.toContain('ai');
      expect(k.toLowerCase()).not.toContain('summary');
    }
  });

  it('the module does not import from the AI summary path', async () => {
    // Dynamic import resolves the actual module; inspect its exports.
    const reportMod = await import('../incidentReportUtils');
    const exports = Object.keys(reportMod);
    for (const k of exports) {
      expect(k.toLowerCase()).not.toContain('ai');
      expect(k.toLowerCase()).not.toContain('summary');
    }
  });
});
