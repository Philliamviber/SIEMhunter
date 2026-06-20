import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { EventsFilter, DetectionsFilter, RuleStatusUpdate, CreateIncidentRequest, IncidentStatus, SearchRequest } from '../types/api';

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

export function useIncidents() {
  return useQuery({
    queryKey: ['incidents'],
    queryFn: () => api.listIncidents(),
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

export function useSearch() {
  return useMutation({
    mutationFn: (req: SearchRequest) => api.search(req),
  });
}
