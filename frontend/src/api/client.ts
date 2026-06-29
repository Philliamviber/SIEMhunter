/**
 * client.ts — Typed API client for the SIEMhunter FastAPI control plane.
 *
 * v3.0.0 auth contract (FR #10):
 *   - The interactive credential is now an HttpOnly/Secure/SameSite=Strict
 *     session COOKIE issued by POST /v1/auth/login. The browser stores and
 *     sends it automatically — JS cannot read it (XSS can no longer steal it).
 *   - The old XSS-readable `siemhunter_token` sessionStorage bearer is GONE
 *     (GATE B C7). getToken/setToken/clearToken were deleted, not commented out.
 *   - State-changing requests (POST/PUT/PATCH/DELETE) carry an X-CSRF-Token
 *     header read from sessionStorage `siemhunter_csrf` (double-submit). The
 *     CSRF token is NOT a session credential — losing it only blocks writes.
 *   - All requests set `credentials: 'include'` so the cookie rides along.
 *   - A central 401 interceptor clears the CSRF token, surfaces a toast, and
 *     hard-reloads to force the LoginGate to re-render (FR #23).
 *   - Idle-timeout (30 min of no API activity) and absolute-lifetime tracking
 *     mirror the server-side session limits so the client redirects promptly.
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
  IncidentsFilter,
  IncidentNote,
  CreateNoteRequest,
  NotesListResponse,
  UploadMode,
  UploadResponse,
  AnalystPreferences,
  AnalystPreferencesUpdate,
  SavedView,
  SavedViewPage,
  SavedViewsResponse,
  QueryHistoryResponse,
} from '../types/api';

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080';

// ── CSRF token (double-submit) ────────────────────────────────────────────────
// Stored in sessionStorage (NOT the session credential — that is the HttpOnly
// cookie). The CSRF token is only useful in combination with the cookie, so a
// stolen CSRF token alone grants nothing.
const CSRF_KEY = 'siemhunter_csrf';

export function getCsrfToken(): string | null {
  return sessionStorage.getItem(CSRF_KEY);
}

export function setCsrfToken(token: string): void {
  sessionStorage.setItem(CSRF_KEY, token);
}

export function clearCsrfToken(): void {
  sessionStorage.removeItem(CSRF_KEY);
}

// Methods that change server state require a CSRF header.
const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

// ── Client-side session timers (mirror the server limits) ─────────────────────
const IDLE_TIMEOUT_MS = 30 * 60 * 1000;        // 30 min of no API activity
const ABSOLUTE_LIFETIME_MS = 10 * 60 * 60 * 1000; // 10 h hard cap
const SESSION_START_KEY = 'siemhunter_session_start';

let lastActivity = Date.now();

/** Call when a session begins (after login / on validated mount). */
export function markSessionStart(): void {
  lastActivity = Date.now();
  sessionStorage.setItem(SESSION_START_KEY, String(Date.now()));
}

function sessionStart(): number {
  const raw = sessionStorage.getItem(SESSION_START_KEY);
  return raw ? Number(raw) : Date.now();
}

/** True if the client-side idle or absolute deadline has passed. */
export function isClientSessionExpired(): boolean {
  const now = Date.now();
  if (now - lastActivity >= IDLE_TIMEOUT_MS) return true;
  if (now - sessionStart() >= ABSOLUTE_LIFETIME_MS) return true;
  return false;
}

function touchActivity(): void {
  lastActivity = Date.now();
}

// ── 401 / expiry handling ─────────────────────────────────────────────────────
// Guarded so we only fire the toast + redirect once even if several in-flight
// requests 401 at the same time.
let redirecting = false;

async function emitToast(message: string): Promise<void> {
  // Lazy import to avoid a hard dependency cycle (toastBridge is a plain module
  // but lives under hooks/). Falls back silently if unavailable (e.g. tests).
  try {
    const { toastBridge } = await import('../hooks/useToast');
    toastBridge.error(message);
  } catch {
    // no-op
  }
}

/** Central handler: clear CSRF, toast, and force LoginGate to re-render. */
export function handleSessionExpired(): void {
  if (redirecting) return;
  redirecting = true;
  clearCsrfToken();
  sessionStorage.removeItem(SESSION_START_KEY);
  void emitToast('Session expired. Please log in again.');
  // Hard reload forces App.tsx to re-evaluate auth state and show LoginGate.
  // Small delay lets the toast paint before the reload.
  setTimeout(() => {
    if (typeof window !== 'undefined') window.location.reload();
  }, 150);
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
  // Client-side idle/absolute expiry check before we even hit the network.
  if (isClientSessionExpired()) {
    handleSessionExpired();
    throw new ApiClientError(401, 'SESSION_EXPIRED', 'Session expired');
  }

  const method = (options.method ?? 'GET').toUpperCase();
  const headers: Record<string, string> = {
    // Set Content-Type: application/json by default so FastAPI's JSON body
    // parser accepts the request. Callers can override by passing options.headers.
    // Do NOT set this for multipart/form-data uploads — see uploadFile() below.
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> | undefined),
  };

  // Attach the CSRF token to state-changing requests (double-submit).
  if (STATE_CHANGING.has(method)) {
    const csrf = getCsrfToken();
    if (csrf) headers['X-CSRF-Token'] = csrf;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    // Send the HttpOnly session cookie with every request.
    credentials: 'include',
  });

  touchActivity();

  // Central 401 interceptor: any 401 means the session is gone/expired.
  if (res.status === 401) {
    handleSessionExpired();
    throw new ApiClientError(401, 'AUTH_REQUIRED', 'Session expired');
  }

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
  if (isClientSessionExpired()) {
    handleSessionExpired();
    throw new ApiClientError(401, 'SESSION_EXPIRED', 'Session expired');
  }

  const formData = new FormData();
  formData.append('file', file);
  formData.append('mode', mode);
  if (incidentId) formData.append('incident_id', incidentId);

  // Do NOT set Content-Type — browser sets it with the multipart boundary automatically.
  // Upload is a state-changing POST → attach the CSRF token.
  const headers: Record<string, string> = {};
  const csrf = getCsrfToken();
  if (csrf) headers['X-CSRF-Token'] = csrf;

  const res = await fetch(`${API_BASE}/v1/ingestion/upload`, {
    method: 'POST',
    headers,
    body: formData,
    credentials: 'include',
  });

  touchActivity();

  if (res.status === 401) {
    handleSessionExpired();
    throw new ApiClientError(401, 'AUTH_REQUIRED', 'Session expired');
  }

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

/**
 * XHR-based upload with byte-level progress events and abort support.
 *
 * `fetch` does not expose upload progress. XHR's `upload.onprogress` does.
 * The caller passes an AbortSignal; aborting it calls `xhr.abort()`, which
 * triggers `xhr.onabort` and rejects the promise with a DOMException('AbortError').
 */
export function uploadFileWithProgress(
  file: File,
  mode: UploadMode,
  incidentId: string | undefined,
  onProgress: (pct: number) => void,
  signal: AbortSignal,
): Promise<UploadResponse> {
  return new Promise<UploadResponse>((resolve, reject) => {
    if (isClientSessionExpired()) {
      handleSessionExpired();
      reject(new ApiClientError(401, 'SESSION_EXPIRED', 'Session expired'));
      return;
    }

    const xhr = new XMLHttpRequest();

    const abortHandler = () => xhr.abort();
    signal.addEventListener('abort', abortHandler, { once: true });

    xhr.upload.onprogress = (e: ProgressEvent) => {
      if (e.lengthComputable) {
        onProgress(Math.round((e.loaded / e.total) * 100));
      }
    };

    xhr.onload = () => {
      signal.removeEventListener('abort', abortHandler);
      touchActivity();
      if (xhr.status === 401) {
        handleSessionExpired();
        reject(new ApiClientError(401, 'AUTH_REQUIRED', 'Session expired'));
        return;
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve(JSON.parse(xhr.responseText) as UploadResponse);
        } catch {
          reject(new ApiClientError(xhr.status, 'PARSE_ERROR', 'Invalid server response'));
        }
        return;
      }
      let code = 'UPLOAD_ERROR';
      let message = 'Upload failed';
      try {
        const body = JSON.parse(xhr.responseText) as { detail?: { code?: string; error?: string } | string };
        if (body?.detail && typeof body.detail === 'object') {
          code = body.detail.code ?? code;
          message = body.detail.error ?? message;
        } else if (typeof body?.detail === 'string') {
          message = body.detail;
        }
      } catch { /* use defaults */ }
      reject(new ApiClientError(xhr.status, code, message));
    };

    xhr.onerror = () => {
      signal.removeEventListener('abort', abortHandler);
      reject(new ApiClientError(0, 'NETWORK_ERROR', 'Network error during upload'));
    };

    xhr.onabort = () => {
      signal.removeEventListener('abort', abortHandler);
      reject(new DOMException('Upload cancelled', 'AbortError'));
    };

    const formData = new FormData();
    formData.append('file', file);
    formData.append('mode', mode);
    if (incidentId) formData.append('incident_id', incidentId);

    xhr.open('POST', `${API_BASE}/v1/ingestion/upload`);
    xhr.withCredentials = true;
    const csrf = getCsrfToken();
    if (csrf) xhr.setRequestHeader('X-CSRF-Token', csrf);

    xhr.send(formData);
  });
}

// ── Auth (FR #10) ─────────────────────────────────────────────────────────────
// These bypass request() on purpose: login runs before a session exists (a 401
// here is an expected wrong-credentials result, NOT a session-expiry redirect),
// and session/logout must not trip the global interceptor.

export interface LoginResult {
  username: string;
  csrf_token: string;
  expires_at: string;
}

export interface SessionInfo {
  valid: boolean;
  username: string;
  expires_at: string;
}

/** POST /v1/auth/login — sets the session cookie, returns + stores the CSRF token. */
export async function login(username: string, password: string): Promise<LoginResult> {
  const res = await fetch(`${API_BASE}/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) {
    let code = 'AUTH_FAILED';
    let message = 'Invalid username or password';
    try {
      const body = await res.json();
      const detail = (body as { detail?: { code?: string; error?: string } }).detail;
      if (detail && typeof detail === 'object') {
        code = detail.code ?? code;
        message = detail.error ?? message;
      }
    } catch {
      // use defaults
    }
    throw new ApiClientError(res.status, code, message);
  }
  const result = (await res.json()) as LoginResult;
  setCsrfToken(result.csrf_token);
  markSessionStart();
  return result;
}

/** POST /v1/auth/logout — invalidates the server session and clears local state. */
export async function logout(): Promise<void> {
  try {
    await fetch(`${API_BASE}/v1/auth/logout`, {
      method: 'POST',
      headers: { 'X-CSRF-Token': getCsrfToken() ?? '' },
      credentials: 'include',
    });
  } finally {
    clearCsrfToken();
    sessionStorage.removeItem(SESSION_START_KEY);
  }
}

/** GET /v1/auth/session — re-validate; throws ApiClientError(401) if invalid. */
export async function getSession(): Promise<SessionInfo> {
  const res = await fetch(`${API_BASE}/v1/auth/session`, {
    method: 'GET',
    credentials: 'include',
  });
  if (res.status === 401) {
    throw new ApiClientError(401, 'AUTH_REQUIRED', 'No active session');
  }
  if (!res.ok) {
    throw new ApiClientError(res.status, 'UNKNOWN_ERROR', `HTTP ${res.status}`);
  }
  return (await res.json()) as SessionInfo;
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

  listIncidents: (filter: IncidentsFilter = {}): Promise<IncidentsListResponse> =>
    request<IncidentsListResponse>(`/v1/incidents${buildQuery(filter as Record<string, string | number | boolean | undefined>)}`),

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

  listIncidentNotes: (incidentId: string): Promise<NotesListResponse> =>
    request<NotesListResponse>(`/v1/incidents/${encodeURIComponent(incidentId)}/notes`),

  addIncidentNote: (incidentId: string, req: CreateNoteRequest): Promise<IncidentNote> =>
    request<IncidentNote>(`/v1/incidents/${encodeURIComponent(incidentId)}/notes`, {
      method: 'POST',
      body: JSON.stringify(req),
    }),

  getPreferences: (): Promise<AnalystPreferences> =>
    request<AnalystPreferences>('/v1/analyst/preferences'),

  setPreferences: (update: AnalystPreferencesUpdate): Promise<AnalystPreferences> =>
    request<AnalystPreferences>('/v1/analyst/preferences', {
      method: 'PUT',
      body: JSON.stringify(update),
    }),

  listSavedViews: (page?: SavedViewPage): Promise<SavedViewsResponse> =>
    request<SavedViewsResponse>(`/v1/analyst/saved-views${page ? `?page=${encodeURIComponent(page)}` : ''}`),

  upsertSavedView: (view: SavedView): Promise<SavedViewsResponse> =>
    request<SavedViewsResponse>('/v1/analyst/saved-views', {
      method: 'POST',
      body: JSON.stringify(view),
    }),

  deleteSavedView: (page: SavedViewPage, name: string): Promise<SavedViewsResponse> =>
    request<SavedViewsResponse>(
      `/v1/analyst/saved-views/${encodeURIComponent(page)}/${encodeURIComponent(name)}`,
      { method: 'DELETE' },
    ),

  getQueryHistory: (): Promise<QueryHistoryResponse> =>
    request<QueryHistoryResponse>('/v1/analyst/query-history'),

  addQueryHistory: (sql: string): Promise<QueryHistoryResponse> =>
    request<QueryHistoryResponse>('/v1/analyst/query-history', {
      method: 'POST',
      body: JSON.stringify({ sql }),
    }),
};
