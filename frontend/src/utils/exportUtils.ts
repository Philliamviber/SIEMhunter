import type { SecurityEvent } from '../types/api';

const INJECTION_CHARS = new Set<string>(['=', '+', '-', '@']);

export function sanitizeCsvField(value: string): string {
  if (value.length > 0 && INJECTION_CHARS.has(value[0])) {
    return `'${value}`;
  }
  return value;
}

function quoteCsvCell(raw: string): string {
  const safe = sanitizeCsvField(raw);
  return `"${safe.replace(/"/g, '""')}"`;
}

const CSV_COLUMNS: (keyof SecurityEvent)[] = [
  'TimeGenerated', 'HostName', 'EventID', 'EventRecordID', 'ChannelName',
  'ProviderName', 'SubjectUserName', 'SubjectUserSid', 'SubjectDomainName',
  'TargetUserName', 'TargetUserSid', 'TargetDomainName', 'LogonType',
  'ServiceName', 'ProcessImagePath', 'CommandLine', 'ParentProcessImagePath',
  'ParentCommandLine', 'GrantedAccess', 'ObjectName', 'FileMD5', 'FileSHA256',
  'RegistryKey', 'SrcIpAddr', 'SrcPort', 'DstIpAddr', 'DstPort',
  'NetworkProtocol', 'ProvenanceTag', 'IngestTimestamp', 'UnmappedFields',
];

const DEFAULT_TRUNCATION_NOTE =
  'Results capped at 10,000 rows — narrow your time range for completeness';

export interface ExportOptions {
  truncated?: boolean;
  truncationNote?: string;
}

export function eventsToCsv(events: SecurityEvent[], options: ExportOptions = {}): string {
  const lines: string[] = [];

  if (options.truncated) {
    lines.push(`# NOTE: ${options.truncationNote ?? DEFAULT_TRUNCATION_NOTE}`);
  }

  lines.push(CSV_COLUMNS.map((col) => quoteCsvCell(col)).join(','));

  for (const event of events) {
    lines.push(
      CSV_COLUMNS.map((col) => quoteCsvCell(String(event[col] ?? ''))).join(',')
    );
  }

  return lines.join('\r\n');
}

export function eventsToJson(events: SecurityEvent[], options: ExportOptions = {}): string {
  const payload: Record<string, unknown> = { events };

  if (options.truncated) {
    payload['_truncated'] = true;
    payload['_truncation_note'] = options.truncationNote ?? DEFAULT_TRUNCATION_NOTE;
  }

  return JSON.stringify(payload, null, 2);
}

export function downloadFile(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
