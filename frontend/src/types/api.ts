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
  hit_id: string;
  rule_id: string;
  rule_version: string;
  batch_start: string;
  batch_end: string;
  event_record_ids: string;
  hit_count: number;
  severity: string;
  mitre_tag: string;
  anomaly_score: number;
  created_at: string;
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
