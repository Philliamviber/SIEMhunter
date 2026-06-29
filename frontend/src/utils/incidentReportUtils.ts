import type { Incident, IncidentNote } from '../types/api';
import type { ExportOptions } from './exportUtils';
import { sanitizeCsvField, downloadFile } from './exportUtils';

const REPORT_TRUNCATION_NOTE =
  'Results capped at 1,000 rows — only the first 1,000 events are included in this report';

export type IncidentEventRow = Record<string, unknown>;

export interface IncidentReportData {
  incident: Incident;
  notes: IncidentNote[];
  events: IncidentEventRow[];
  exportOptions?: ExportOptions;
}

interface CorrelationSnapshot {
  hosts: string[];
  users: string[];
  ips: string[];
  processes: string[];
}

interface ReportTimelineBucket {
  hour: string;
  count: number;
}

function buildCorrelationSnapshot(events: IncidentEventRow[]): CorrelationSnapshot {
  const hosts = new Set<string>();
  const users = new Set<string>();
  const ips = new Set<string>();
  const processes = new Set<string>();

  for (const ev of events) {
    if (ev['HostName']) hosts.add(String(ev['HostName']));
    if (ev['SubjectUserName']) users.add(String(ev['SubjectUserName']));
    if (ev['TargetUserName']) users.add(String(ev['TargetUserName']));
    if (ev['SrcIpAddr']) ips.add(String(ev['SrcIpAddr']));
    if (ev['DstIpAddr']) ips.add(String(ev['DstIpAddr']));
    if (ev['ProcessImagePath']) processes.add(String(ev['ProcessImagePath']));
  }

  return {
    hosts: Array.from(hosts).filter(Boolean),
    users: Array.from(users).filter(Boolean),
    ips: Array.from(ips).filter(Boolean),
    processes: Array.from(processes).filter(Boolean),
  };
}

function buildTimeline(events: IncidentEventRow[]): ReportTimelineBucket[] {
  const buckets = new Map<string, number>();
  for (const ev of events) {
    const raw = String(ev['TimeGenerated'] ?? '');
    if (raw.length >= 13) {
      const hour = raw.slice(0, 13);
      buckets.set(hour, (buckets.get(hour) ?? 0) + 1);
    }
  }
  return Array.from(buckets.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([hour, count]) => ({ hour, count }));
}

function s(value: unknown): string {
  return sanitizeCsvField(String(value ?? ''));
}

export function incidentReportToMarkdown(data: IncidentReportData): string {
  const { incident, notes, events, exportOptions } = data;
  const generatedAt = new Date().toISOString();
  const lines: string[] = [];

  lines.push(`# Incident Report: ${s(incident.name)}`);
  lines.push('');
  lines.push(`**Generated:** ${generatedAt}  `);
  lines.push(`**Incident ID:** ${s(incident.id)}  `);
  lines.push(`**Severity:** ${incident.severity}  `);
  lines.push(`**Status:** ${incident.status}  `);
  lines.push(`**Created:** ${incident.created_at}  `);
  lines.push(`**Updated:** ${incident.updated_at}  `);
  lines.push(`**Event Count:** ${incident.event_count}`);
  lines.push('');

  if (exportOptions?.truncated) {
    const note = exportOptions.truncationNote ?? REPORT_TRUNCATION_NOTE;
    lines.push(`> **Note:** ${note}`);
    lines.push('');
  }

  lines.push('## Description');
  lines.push('');
  lines.push(incident.description ? s(incident.description) : '_No description provided_');
  lines.push('');

  lines.push('## Analyst Notes');
  lines.push('');
  if (notes.length === 0) {
    lines.push('_No notes recorded._');
  } else {
    for (const note of notes) {
      lines.push(`### ${s(note.author)} — ${note.created_at}`);
      lines.push('');
      lines.push(s(note.content));
      lines.push('');
    }
  }

  const timeline = buildTimeline(events);
  lines.push('## Event Timeline');
  lines.push('');
  if (timeline.length === 0) {
    lines.push('_No events associated with this incident._');
  } else {
    lines.push('| Hour (UTC) | Event Count |');
    lines.push('|-----------|-------------|');
    for (const bucket of timeline) {
      lines.push(`| ${bucket.hour}:00 | ${bucket.count} |`);
    }
  }
  lines.push('');

  const snapshot = buildCorrelationSnapshot(events);
  lines.push('## Correlation Snapshot');
  lines.push('');
  lines.push(
    `**Hosts (${snapshot.hosts.length}):** ${snapshot.hosts.map(s).join(', ') || '_none_'}`,
  );
  lines.push('');
  lines.push(
    `**Users (${snapshot.users.length}):** ${snapshot.users.map(s).join(', ') || '_none_'}`,
  );
  lines.push('');
  lines.push(
    `**IP Addresses (${snapshot.ips.length}):** ${snapshot.ips.map((v) => s(v)).join(', ') || '_none_'}`,
  );
  lines.push('');
  lines.push(
    `**Processes (${snapshot.processes.length}):** ${snapshot.processes.map(s).join(', ') || '_none_'}`,
  );
  lines.push('');

  lines.push('## Events');
  lines.push('');
  if (events.length === 0) {
    lines.push('_No events found for this incident._');
  } else {
    const cap = 100;
    const visible = events.slice(0, cap);
    lines.push('| Time | Host | EventID | Subject User | Command |');
    lines.push('|------|------|---------|--------------|---------|');
    for (const ev of visible) {
      const cmd = String(ev['CommandLine'] ?? '').slice(0, 80);
      lines.push(
        `| ${ev['TimeGenerated']} | ${s(String(ev['HostName'] ?? ''))} | ${ev['EventID']} | ${s(String(ev['SubjectUserName'] ?? ''))} | ${s(cmd)} |`,
      );
    }
    if (events.length > cap) {
      lines.push('');
      lines.push(`_… and ${events.length - cap} more events (see JSON export for full list)_`);
    }
  }
  lines.push('');

  return lines.join('\n');
}

export function incidentReportToJson(data: IncidentReportData): string {
  const { incident, notes, events, exportOptions } = data;
  const generatedAt = new Date().toISOString();

  const payload: Record<string, unknown> = {
    format_version: '1.0',
    generated_at: generatedAt,
    incident: {
      id: s(incident.id),
      name: s(incident.name),
      description: incident.description != null ? s(incident.description) : null,
      severity: incident.severity,
      status: incident.status,
      created_at: incident.created_at,
      updated_at: incident.updated_at,
      event_count: incident.event_count,
    },
    notes: notes.map((n) => ({
      id: n.id,
      author: s(n.author),
      content: s(n.content),
      created_at: n.created_at,
    })),
    correlation_snapshot: buildCorrelationSnapshot(events),
    timeline: buildTimeline(events),
    events: events.map((ev) => ({
      TimeGenerated: ev['TimeGenerated'],
      HostName: s(String(ev['HostName'] ?? '')),
      EventID: ev['EventID'],
      EventRecordID: ev['EventRecordID'],
      SubjectUserName: s(String(ev['SubjectUserName'] ?? '')),
      TargetUserName: s(String(ev['TargetUserName'] ?? '')),
      CommandLine: s(String(ev['CommandLine'] ?? '')),
      ProcessImagePath: s(String(ev['ProcessImagePath'] ?? '')),
      SrcIpAddr: ev['SrcIpAddr'],
      DstIpAddr: ev['DstIpAddr'],
    })),
  };

  if (exportOptions?.truncated) {
    payload['_truncated'] = true;
    payload['_truncation_note'] = exportOptions.truncationNote ?? REPORT_TRUNCATION_NOTE;
  }

  return JSON.stringify(payload, null, 2);
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function buildPrintHtml(data: IncidentReportData): string {
  const { incident, notes, events, exportOptions } = data;
  const generatedAt = new Date().toISOString();
  const snapshot = buildCorrelationSnapshot(events);
  const timeline = buildTimeline(events);

  const truncatedBanner = exportOptions?.truncated
    ? `<div class="note"><strong>Note:</strong> ${escapeHtml(exportOptions.truncationNote ?? REPORT_TRUNCATION_NOTE)}</div>`
    : '';

  const notesHtml =
    notes.length === 0
      ? '<p><em>No notes recorded.</em></p>'
      : notes
          .map(
            (n) =>
              `<div class="note-item"><div class="note-meta">${escapeHtml(s(n.author))} — ${escapeHtml(n.created_at)}</div><p>${escapeHtml(s(n.content))}</p></div>`,
          )
          .join('');

  const timelineHtml =
    timeline.length === 0
      ? '<p><em>No events associated with this incident.</em></p>'
      : `<table><thead><tr><th>Hour (UTC)</th><th>Event Count</th></tr></thead><tbody>${timeline.map((b) => `<tr><td>${escapeHtml(b.hour)}:00</td><td>${b.count}</td></tr>`).join('')}</tbody></table>`;

  const eventsHtml = (() => {
    if (events.length === 0) return '<p><em>No events found for this incident.</em></p>';
    const cap = 100;
    const visible = events.slice(0, cap);
    const rows = visible
      .map(
        (ev) =>
          `<tr><td>${escapeHtml(String(ev['TimeGenerated'] ?? ''))}</td><td>${escapeHtml(s(String(ev['HostName'] ?? '')))}</td><td>${escapeHtml(String(ev['EventID'] ?? ''))}</td><td>${escapeHtml(s(String(ev['SubjectUserName'] ?? '')))}</td><td>${escapeHtml(s(String(ev['CommandLine'] ?? '').slice(0, 80)))}</td></tr>`,
      )
      .join('');
    const moreNote =
      events.length > cap
        ? `<p><em>… and ${events.length - cap} more events (see JSON export for full list)</em></p>`
        : '';
    return `<table><thead><tr><th>Time</th><th>Host</th><th>EventID</th><th>Subject User</th><th>Command</th></tr></thead><tbody>${rows}</tbody></table>${moreNote}`;
  })();

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Incident Report — ${escapeHtml(incident.name)}</title>
<style>
  body{font-family:Arial,sans-serif;font-size:11pt;color:#000;margin:0;padding:20px}
  h1{font-size:18pt;margin-bottom:4pt}
  h2{font-size:13pt;margin-top:18pt;border-bottom:1px solid #ccc;padding-bottom:4pt}
  .meta{font-size:9pt;color:#555;margin-bottom:12pt}
  .meta span{display:inline-block;margin-right:16pt}
  .note{background:#fffbe6;border-left:3px solid #f0a500;padding:6pt 10pt;margin:8pt 0;font-size:10pt}
  .note-item{border:1px solid #e0e0e0;padding:8pt;margin:6pt 0;border-radius:3pt}
  .note-meta{font-size:9pt;color:#777;margin-bottom:4pt}
  table{border-collapse:collapse;width:100%;margin:8pt 0;font-size:9pt}
  th{background:#f5f5f5;text-align:left;padding:4pt 6pt;border:1px solid #ccc}
  td{padding:3pt 6pt;border:1px solid #e0e0e0;word-break:break-all}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:10pt}
  .box{border:1px solid #e0e0e0;padding:8pt;border-radius:3pt}
  .box h3{font-size:10pt;margin:0 0 4pt 0;color:#555}
  .box ul{margin:0;padding-left:14pt;font-size:9pt}
  @media print{@page{margin:2cm;size:A4 portrait}}
</style>
</head>
<body>
<h1>Incident Report: ${escapeHtml(s(incident.name))}</h1>
<div class="meta">
  <span><strong>ID:</strong> ${escapeHtml(s(incident.id))}</span>
  <span><strong>Severity:</strong> ${escapeHtml(incident.severity)}</span>
  <span><strong>Status:</strong> ${escapeHtml(incident.status)}</span>
  <span><strong>Generated:</strong> ${escapeHtml(generatedAt)}</span>
</div>
${truncatedBanner}
<h2>Description</h2>
<p>${incident.description ? escapeHtml(s(incident.description)) : '<em>No description provided</em>'}</p>
<div class="meta">
  <span><strong>Created:</strong> ${escapeHtml(incident.created_at)}</span>
  <span><strong>Updated:</strong> ${escapeHtml(incident.updated_at)}</span>
  <span><strong>Event Count:</strong> ${incident.event_count}</span>
</div>
<h2>Analyst Notes</h2>
${notesHtml}
<h2>Event Timeline</h2>
${timelineHtml}
<h2>Correlation Snapshot</h2>
<div class="grid">
  <div class="box"><h3>Hosts (${snapshot.hosts.length})</h3><ul>${snapshot.hosts.length ? snapshot.hosts.map((h) => `<li>${escapeHtml(s(h))}</li>`).join('') : '<li><em>none</em></li>'}</ul></div>
  <div class="box"><h3>Users (${snapshot.users.length})</h3><ul>${snapshot.users.length ? snapshot.users.map((u) => `<li>${escapeHtml(s(u))}</li>`).join('') : '<li><em>none</em></li>'}</ul></div>
  <div class="box"><h3>IP Addresses (${snapshot.ips.length})</h3><ul>${snapshot.ips.length ? snapshot.ips.map((ip) => `<li>${escapeHtml(ip)}</li>`).join('') : '<li><em>none</em></li>'}</ul></div>
  <div class="box"><h3>Processes (${snapshot.processes.length})</h3><ul>${snapshot.processes.length ? snapshot.processes.map((p) => `<li>${escapeHtml(s(p))}</li>`).join('') : '<li><em>none</em></li>'}</ul></div>
</div>
<h2>Events</h2>
${eventsHtml}
</body>
</html>`;
}

export function incidentReportToPdf(data: IncidentReportData): void {
  const html = buildPrintHtml(data);
  const win = window.open('', '_blank', 'width=900,height=700');
  if (!win) return;
  win.document.open();
  win.document.write(html);
  win.document.close();
  win.focus();
  // Small delay allows the browser to fully render before opening the print dialog.
  setTimeout(() => win.print(), 300);
}

export function downloadIncidentReport(
  data: IncidentReportData,
  format: 'markdown' | 'json' | 'pdf',
): void {
  const slug = data.incident.id.replace(/[^a-zA-Z0-9-]/g, '').slice(0, 16);
  if (format === 'markdown') {
    downloadFile(incidentReportToMarkdown(data), `incident-${slug}.md`, 'text/markdown');
  } else if (format === 'json') {
    downloadFile(incidentReportToJson(data), `incident-${slug}.json`, 'application/json');
  } else {
    incidentReportToPdf(data);
  }
}
