/**
 * api.ts — TypeScript interfaces mirroring the Pydantic response models in
 * services/api/src/routers/.
 *
 * These interfaces are NOT auto-generated from the OpenAPI schema. They must be
 * kept in sync manually whenever the API contracts change. If a field is added to
 * a Pydantic model and not added here, the TypeScript compiler will not catch the
 * mismatch — the field will simply be absent from the typed object at runtime.
 *
 * Non-obvious fields are called out with inline comments below.
 */

// ── Metrics ───────────────────────────────────────────────────────────────────

export interface SourceCount {
  provenance_tag: string;
  event_count: number;
}

export interface AnomalyBucket {
  bucket_label: string;
  count: number;
}

export interface MetricsResponse {
  events_by_source: SourceCount[];
  detection_hits_24h: number;
  anomaly_score_distribution: AnomalyBucket[] | null;
  last_batch_run_at: string | null;
  last_batch_duration_seconds: null;
}

// ── Status ────────────────────────────────────────────────────────────────────

export interface StatusResponse {
  clickhouse: string;
  normalization_alive: boolean;
  detection_alive: boolean;
  forwarder_alive: boolean;
  pending_retry_queue: number;
}

// ── Health ────────────────────────────────────────────────────────────────────

export interface ServiceHealthResponse {
  service: string;
  status: 'ok' | 'degraded' | 'unknown' | 'error';
  detail: string | null;
  alive_file_age_seconds: number | null;
}

// ── Events ────────────────────────────────────────────────────────────────────

export interface SecurityEvent {
  TimeGenerated: string;
  HostName: string;
  EventID: number;
  EventRecordID: string;
  ChannelName: string;
  ProviderName: string;
  SubjectUserName: string;
  SubjectUserSid: string;
  SubjectDomainName: string;
  TargetUserName: string;
  TargetUserSid: string;
  TargetDomainName: string;
  LogonType: number;
  ServiceName: string;
  ProcessImagePath: string;
  CommandLine: string;
  ParentProcessImagePath: string;
  ParentCommandLine: string;
  GrantedAccess: string;
  ObjectName: string;
  FileMD5: string;
  FileSHA256: string;
  RegistryKey: string;
  SrcIpAddr: string;
  SrcPort: number;
  DstIpAddr: string;
  DstPort: number;
  NetworkProtocol: string;
  ProvenanceTag: string;
  IngestTimestamp: string;
  // UnmappedFields is a JSON string (not a parsed object) containing event fields
  // that the normalizer could not map to a canonical column. It is stored as a
  // plain String in ClickHouse and is not Sigma-queryable. Parse before displaying.
  UnmappedFields: string;
}

export interface EventsResponse {
  events: SecurityEvent[];
  total_count: number;
  limit: number;
  offset: number;
}

export interface EventsFilter {
  start?: string;
  end?: string;
  hostname?: string;
  event_id?: number;
  subject_user_name?: string;
  src_ip_addr?: string;
  provenance_tag?: string;
  limit?: number;
  offset?: number;
}

// ── Detections ────────────────────────────────────────────────────────────────

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface DetectionHit {
  // hit_id is a deterministic SHA-256 fingerprint of rule_id + sorted event_record_ids.
  // The same detection firing twice in the same batch produces the same hit_id, which
  // the forwarder uses to deduplicate Sentinel incidents (idempotent PUT).
  hit_id: string;
  rule_id: string;
  rule_version: string;
  batch_start: string;
  batch_end: string;
  event_record_ids: string;
  hit_count: number;
  severity: string;
  mitre_tag: string;
  // anomaly_score is an Isolation Forest output in [0, 1]. It is advisory only —
  // not a threshold gate. A high score does not suppress or promote an alert.
  // Rules fire on Sigma matches regardless of anomaly_score.
  anomaly_score: number;
  created_at: string;
  // forwarded_at is null until the forwarder successfully pushes this hit to
  // Sentinel. A null value means the hit is in the on-disk retry queue or has
  // not yet been picked up by the forwarder batch. It does NOT mean forwarding failed.
  forwarded_at: string | null;
}

export interface TimelineBucket {
  hour: string;
  severity: string;
  hit_count: number;
}

export interface DetectionsResponse {
  hits: DetectionHit[];
  total_count: number;
  limit: number;
  offset: number;
  timeline: TimelineBucket[];
}

export interface DetectionsFilter {
  severity?: string;
  rule_id?: string;
  forwarded?: 'yes' | 'no';
  start?: string;
  end?: string;
  limit?: number;
  offset?: number;
}

// ── Rules ─────────────────────────────────────────────────────────────────────

export type RuleStatus = 'draft' | 'test' | 'review' | 'production' | 'disabled';

export interface Rule {
  rule_id: string;
  rule_version: string;
  status: RuleStatus;
  file_path: string;
  updated_at: string;
}

export interface RuleStatusUpdate {
  new_status: RuleStatus;
  reason?: string;
}

// ── Ingestion ─────────────────────────────────────────────────────────────────

export interface ProvenanceCount {
  provenance_tag: string;
  event_count: number;
}

export interface HourlyVolume {
  hour: string;
  provenance_tag: string;
  event_count: number;
}

export interface PipelineLatency {
  avg_seconds: number | null;
  p95_seconds: number | null;
}

export interface PerSourceStat {
  provenance_tag: string;
  last_seen: string | null;
  events_per_hour: number;
  unmapped_nonempty_pct: number;
}

export interface IngestionSummaryResponse {
  provenance_breakdown: ProvenanceCount[];
  volume_over_time: HourlyVolume[];
  pipeline_latency: PipelineLatency;
  per_source: PerSourceStat[];
  rate_limit_flood_panel: null;
  rate_limit_flood_note: string;
}

// ── AI Summary ────────────────────────────────────────────────────────────────

export interface AISummaryResponse {
  narrative: string;
  notable_items: string[];
  disclaimer: string;
  source_window: string;
  generated_at: string;
}

// ── Query ─────────────────────────────────────────────────────────────────────

export interface QueryRequest {
  sql: string;
  params?: Record<string, unknown>;
}

export interface QueryResponse {
  rows: Record<string, unknown>[];
  row_count: number;
  truncated: boolean;
  execution_time_ms: number;
}

// ── Search ────────────────────────────────────────────────────────────────────

export type SearchFieldType =
  | 'IP'
  | 'Hostname'
  | 'Username'
  | 'Port'
  | 'EventID'
  | 'FileHash'
  | 'ProcessName';

export interface SearchRequest {
  field_type: SearchFieldType;
  value: string;
  start?: string;
  end?: string;
  incident_id?: string;
}

export interface SearchResponse {
  rows: Record<string, unknown>[];
  row_count: number;
  truncated: boolean;
  execution_time_ms: number;
  field_type: string;
  columns_searched: string[];
}

// ── API Error ─────────────────────────────────────────────────────────────────

export interface ApiError {
  error: string;
  code: string;
}

// ── Incidents ─────────────────────────────────────────────────────────────────

export type IncidentSeverity = 'low' | 'medium' | 'high' | 'critical';
export type IncidentStatus = 'open' | 'closed' | 'archived';

export interface Incident {
  id: string;
  name: string;
  description: string | null;
  severity: IncidentSeverity;
  status: IncidentStatus;
  created_at: string;
  updated_at: string;
  event_count: number;
}

export interface CreateIncidentRequest {
  name: string;
  description?: string;
  severity: IncidentSeverity;
}

export interface IncidentStatusUpdate {
  new_status: IncidentStatus;
}

export interface IncidentsListResponse {
  incidents: Incident[];
  total: number;
}

export interface IncidentNote {
  id: string;
  incident_id: string;
  /** Server-set from the authenticated identity — never client-supplied. */
  author: string;
  /** Plain text; never rendered as HTML. */
  content: string;
  /** Server-set ISO 8601 UTC timestamp. */
  created_at: string;
}

export interface CreateNoteRequest {
  content: string;
}

export interface NotesListResponse {
  notes: IncidentNote[];
  total: number;
}

// ── File Upload ───────────────────────────────────────────────────────────────

export type UploadMode = 'global' | 'incident';

export interface UploadResponse {
  filename: string;
  provenance_tag: string;
  events_parsed: number;
  events_written: number;
  events_unmapped: number;
  error_count: number;
  status: 'success' | 'partial' | 'failed';
}
