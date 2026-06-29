/**
 * useApi.ts — TanStack Query wrapper hooks for all SIEMhunter API endpoints.
 *
 * All useQuery hooks poll at 30-second intervals (POLL_MS). This keeps dashboard
 * data live without requiring WebSocket infrastructure. If a page is not visible,
 * TanStack Query automatically pauses polling (windowFocus refetch behaviour).
 *
 * Mutation hooks (useUpdateRuleStatus, useCreateIncident, useUpdateIncidentStatus,
 * useSearch) do NOT poll — they are triggered by explicit user actions.
 *
 * useSearch is a useMutation (not useQuery) because search is user-initiated and
 * the results should not auto-refresh in the background. A useQuery that depended
 * on search parameters would refetch every 30 s even while the user is reviewing
 * results, which would reset their view and waste API budget.
 */
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { EventsFilter, DetectionsFilter, RuleStatusUpdate, CreateIncidentRequest, IncidentStatus, IncidentsFilter, SearchRequest, CreateNoteRequest, AnalystPreferencesUpdate, SavedView, SavedViewPage, SigmaCompileRequest, SigmaDryRunRequest } from '../types/api';

const POLL_MS = 30_000; // 30s poll interval

export function useMetrics() {
  return useQuery({
    queryKey: ['metrics'],
    queryFn: () => api.metrics(),
    refetchInterval: POLL_MS,
  });
}

export function useStatus() {
  return useQuery({
    queryKey: ['status'],
    queryFn: () => api.status(),
    refetchInterval: POLL_MS,
  });
}

export function useHealthService(service: string) {
  return useQuery({
    queryKey: ['health', service],
    queryFn: () => api.healthService(service),
    refetchInterval: POLL_MS,
  });
}

export function useEvents(filter: EventsFilter = {}) {
  return useQuery({
    queryKey: ['events', filter],
    queryFn: () => api.events(filter),
    refetchInterval: POLL_MS,
  });
}

export function useDetections(filter: DetectionsFilter = {}) {
  return useQuery({
    queryKey: ['detections', filter],
    queryFn: () => api.detections(filter),
    refetchInterval: POLL_MS,
  });
}

export function useRules() {
  return useQuery({
    queryKey: ['rules'],
    queryFn: () => api.rules(),
    refetchInterval: POLL_MS,
  });
}

export function useUpdateRuleStatus() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ ruleId, body }: { ruleId: string; body: RuleStatusUpdate }) =>
      api.updateRuleStatus(ruleId, body),
    onSuccess: () => {
      // Invalidate the rules list so the Kanban board reflects the new status
      // immediately. Without this, the card would stay in the old column until
      // the 30-second poll fires. useMutation does not invalidate automatically.
      void queryClient.invalidateQueries({ queryKey: ['rules'] });
    },
  });
}

export function useIngestionSummary() {
  return useQuery({
    queryKey: ['ingestion'],
    queryFn: () => api.ingestionSummary(),
    refetchInterval: POLL_MS,
  });
}

export function useAiSummary() {
  return useQuery({
    queryKey: ['ai-summary'],
    queryFn: () => api.aiSummary(),
    refetchInterval: POLL_MS,
  });
}

export function useIncidents(filter: IncidentsFilter = {}) {
  return useQuery({
    queryKey: ['incidents', filter],
    queryFn: () => api.listIncidents(filter),
    refetchInterval: POLL_MS,
  });
}

export function useIncident(id: string) {
  return useQuery({
    queryKey: ['incidents', id],
    queryFn: () => api.getIncident(id),
    enabled: Boolean(id),
    refetchInterval: POLL_MS,
  });
}

export function useCreateIncident() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (req: CreateIncidentRequest) => api.createIncident(req),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['incidents'] });
    },
  });
}

export function useUpdateIncidentStatus() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, newStatus }: { id: string; newStatus: IncidentStatus }) =>
      api.updateIncidentStatus(id, newStatus),
    onSuccess: (_data, { id }) => {
      void queryClient.invalidateQueries({ queryKey: ['incidents'] });
      void queryClient.invalidateQueries({ queryKey: ['incidents', id] });
    },
  });
}

// useSearch is a mutation, not a query. Search is triggered by the user pressing
// Enter/clicking Search — it must not auto-refresh. If this were a useQuery,
// TanStack Query would re-run it every 30 s, overwriting the user's current
// result view and consuming API quota for stale searches.
export function useSearch() {
  return useMutation({
    mutationFn: (req: SearchRequest) => api.search(req),
  });
}

export function useIncidentNotes(incidentId: string) {
  return useQuery({
    queryKey: ['incidents', incidentId, 'notes'],
    queryFn: () => api.listIncidentNotes(incidentId),
    enabled: Boolean(incidentId),
    refetchInterval: POLL_MS,
  });
}

export function useAddIncidentNote(incidentId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (req: CreateNoteRequest) => api.addIncidentNote(incidentId, req),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['incidents', incidentId, 'notes'] });
    },
  });
}

export function usePreferences() {
  return useQuery({
    queryKey: ['analyst-preferences'],
    queryFn: () => api.getPreferences(),
    // Preferences are user-owned and change infrequently; a long staleTime
    // prevents unnecessary re-fetches during normal SPA navigation.
    staleTime: 5 * 60 * 1000,
  });
}

export function useSetPreferences() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (update: AnalystPreferencesUpdate) => api.setPreferences(update),
    onSuccess: (data) => {
      queryClient.setQueryData(['analyst-preferences'], data);
    },
  });
}

export function useSavedViews(page?: SavedViewPage) {
  return useQuery({
    queryKey: ['saved-views', page ?? 'all'],
    queryFn: () => api.listSavedViews(page),
    staleTime: 60_000,
  });
}

export function useUpsertSavedView(page?: SavedViewPage) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (view: SavedView) => api.upsertSavedView(view),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['saved-views', page ?? 'all'] });
      void queryClient.invalidateQueries({ queryKey: ['saved-views', 'all'] });
    },
  });
}

export function useDeleteSavedView(page?: SavedViewPage) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ page: p, name }: { page: SavedViewPage; name: string }) =>
      api.deleteSavedView(p, name),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['saved-views', page ?? 'all'] });
      void queryClient.invalidateQueries({ queryKey: ['saved-views', 'all'] });
    },
  });
}

export function useQueryHistory() {
  return useQuery({
    queryKey: ['query-history'],
    queryFn: () => api.getQueryHistory(),
    staleTime: 30_000,
  });
}

export function useAddQueryHistory() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (sql: string) => api.addQueryHistory(sql),
    onSuccess: (data) => {
      queryClient.setQueryData(['query-history'], data);
    },
  });
}

export function useSigmaCompile() {
  return useMutation({
    mutationFn: (req: SigmaCompileRequest) => api.sigmaCompile(req),
  });
}

export function useSigmaDryRun() {
  return useMutation({
    mutationFn: (req: SigmaDryRunRequest) => api.sigmaDryRun(req),
  });
}
