/**
 * client.ts — Typed API client for the SIEMhunter FastAPI control plane.
 *
 * Every request injects a Bearer token from sessionStorage. sessionStorage is used
 * instead of localStorage or a cookie because it is automatically cleared when the
 * browser tab closes — the token does not persist across sessions, which limits the
 * window of exposure if the machine is left unattended or shared.
 *
 * All JSON endpoints go through the shared `request<T>()` helper, which sets
 * Content-Type: application/json by default and handles structured error extraction
 * from FastAPI's {"detail": {"code": ..., "error": ...}} response shape.
 *
 * File uploads bypass `request()` entirely — see `uploadFile()` for why.
 */
import type {
  MetricsResponse,
  StatusResponse,
  ServiceHealthResponse,
  EventsResponse,
  EventsFilter,
  DetectionsResponse,
  DetectionsFilter,
  Rule,
  RuleStatusUpdate,
  IngestionSummaryResponse,
  AISummaryResponse,
  QueryRequest,
  QueryResponse,
  SearchRequest,
  SearchResponse,
  Incident,
  CreateIncidentRequest,
  IncidentStatus,
  IncidentsListResponse,
  UploadMode,
  UploadResponse,
} from '../types/api';

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080';
const TOKEN_KEY = 'siemhunter_token';

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  sessionStorage.removeItem(TOKEN_KEY);
}

class ApiClientError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiClientError';
    this.status = status;
    this.code = code;
  }
}

export { ApiClientError };

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    // Set Content-Type: application/json by default so FastAPI's JSON body
    // parser accepts the request. Callers can override by passing options.headers.
    // Do NOT set this for multipart/form-data uploads — see uploadFile() below.
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> | undefined),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    let code = 'UNKNOWN_ERROR';
    let message = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body && typeof body === 'object') {
        const detail = (body as { detail?: { code?: string; error?: string } | string }).detail;
        if (detail && typeof detail === 'object') {
          code = detail.code ?? code;
          message = detail.error ?? message;
        } else if (typeof detail === 'string') {
          message = detail;
        }
      }
    } catch {
      // ignore parse error; use defaults
    }
    throw new ApiClientError(res.status, code, message);
  }

  return res.json() as Promise<T>;
}

// buildQuery omits undefined, null, and empty-string values so that unset
// optional filter fields don't appear as "?hostname=" in the URL. The API
// treats a missing parameter as "no filter" and an empty string as a literal
// empty-string filter — two very different behaviours.
function buildQuery(params: Record<string, string | number | boolean | undefined>): string {
  const q = new URLSearchParams();
  for (const [key, val] of Object.entries(params)) {
    if (val !== undefined && val !== null && val !== '') {
      q.set(key, String(val));
    }
  }
  const s = q.toString();
  return s ? `?${s}` : '';
}

// ── File upload (multipart/form-data — NOT using request() which sets JSON CT) ─
// When the browser sends FormData, it must set Content-Type to
// "multipart/form-data; boundary=<generated_boundary>" itself. If we set
// Content-Type: application/json (as request() does), the boundary is missing
// and the FastAPI multipart parser rejects the request with a 422.
// Solution: pass no Content-Type header at all; the browser fills it in.

export async function uploadFile(
  file: File,
  mode: UploadMode = 'global',
  incidentId?: string,
): Promise<UploadResponse> {
  const token = getToken();
  const formData = new FormData();
  formData.append('file', file);
  formData.append('mode', mode);
  if (incidentId) formData.append('incident_id', incidentId);

  // Do NOT set Content-Type — browser sets it with the multipart boundary automatically.
  const headers: Record<string, string> = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}/v1/ingestion/upload`, {
    method: 'POST',
    headers,
    body: formData,
  });

  if (!res.ok) {
    let code = 'UPLOAD_ERROR';
    let message = 'Upload failed';
    try {
      const body = await res.json();
      if (body && typeof body === 'object') {
        const detail = (body as { detail?: { code?: string; error?: string } | string }).detail;
        if (detail && typeof detail === 'object') {
          code = detail.code ?? code;
          message = detail.error ?? message;
        } else if (typeof detail === 'string') {
          message = detail;
        }
      }
    } catch {
      // ignore parse error; use defaults
    }
    throw new ApiClientError(res.status, code, message);
  }

  return res.json() as Promise<UploadResponse>;
}

// ── Endpoints ─────────────────────────────────────────────────────────────────

export const api = {
  metrics: (): Promise<MetricsResponse> =>
    request<MetricsResponse>('/v1/metrics'),

  status: (): Promise<StatusResponse> =>
    request<StatusResponse>('/v1/status'),

  healthService: (service: string): Promise<ServiceHealthResponse> =>
    request<ServiceHealthResponse>(`/v1/health/${service}`),

  events: (filter: EventsFilter = {}): Promise<EventsResponse> =>
    request<EventsResponse>(`/v1/events${buildQuery(filter as Record<string, string | number | boolean | undefined>)}`),

  detections: (filter: DetectionsFilter = {}): Promise<DetectionsResponse> =>
    request<DetectionsResponse>(`/v1/detections${buildQuery(filter as Record<string, string | number | boolean | undefined>)}`),

  rules: (): Promise<Rule[]> =>
    request<Rule[]>('/v1/rules'),

  updateRuleStatus: (ruleId: string, body: RuleStatusUpdate): Promise<Rule> =>
    request<Rule>(`/v1/rules/${encodeURIComponent(ruleId)}/status`, {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  ingestionSummary: (): Promise<IngestionSummaryResponse> =>
    request<IngestionSummaryResponse>('/v1/ingestion/summary'),

  aiSummary: (): Promise<AISummaryResponse> =>
    request<AISummaryResponse>('/v1/ai/summary'),

  query: (body: QueryRequest): Promise<QueryResponse> =>
    request<QueryResponse>('/v1/query', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  listIncidents: (): Promise<IncidentsListResponse> =>
    request<IncidentsListResponse>('/v1/incidents'),

  createIncident: (req: CreateIncidentRequest): Promise<Incident> =>
    request<Incident>('/v1/incidents', {
      method: 'POST',
      body: JSON.stringify(req),
    }),

  getIncident: (id: string): Promise<Incident> =>
    request<Incident>(`/v1/incidents/${encodeURIComponent(id)}`),

  updateIncidentStatus: (id: string, newStatus: IncidentStatus): Promise<Incident> =>
    request<Incident>(`/v1/incidents/${encodeURIComponent(id)}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ new_status: newStatus }),
    }),

  search: (req: SearchRequest): Promise<SearchResponse> =>
    request<SearchResponse>('/v1/search', {
      method: 'POST',
      body: JSON.stringify(req),
    }),
};
