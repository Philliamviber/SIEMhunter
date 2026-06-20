/**
 * App.tsx — Root React component for the SIEMhunter dashboard.
 *
 * Auth gate: TokenGate is rendered OUTSIDE QueryClientProvider and BrowserRouter.
 * This is deliberate — if TokenGate were inside QueryClientProvider, TanStack Query
 * could fire background fetches (e.g. from useQuery hooks in child components) before
 * the user has submitted a token, causing a flood of 401 errors and polluting the
 * query cache.
 *
 * staleTime (10 s): fast re-renders (e.g. navigating between pages) won't trigger a
 * refetch if cached data is less than 10 seconds old. Without this, every page mount
 * would hammer the API. 10 s is short enough that data feels live but long enough to
 * absorb SPA navigation.
 *
 * QueryClientProvider: must wrap the entire authenticated app so every useQuery /
 * useMutation call shares the same cache and devtools instance.
 *
 * IncidentProvider: wraps the router so every page and the nav bar can read and set
 * the active incident without prop-drilling. Three unrelated UI surfaces (UploadZone,
 * GlobalSearchBar, nav label) all need the same value simultaneously.
 */
import { useState } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { getToken } from './api/client';
import { TokenGate } from './components/TokenGate';
import { PageLayout } from './components/PageLayout';
import { OverviewPage } from './pages/OverviewPage';
import { EventsPage } from './pages/EventsPage';
import { DetectionsPage } from './pages/DetectionsPage';
import { RulesPage } from './pages/RulesPage';
import { IngestionPage } from './pages/IngestionPage';
import { HealthPage } from './pages/HealthPage';
import { QueryPage } from './pages/QueryPage';
import { CategoryDashboardPage } from './pages/CategoryDashboardPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { IncidentDetailPage } from './pages/IncidentDetailPage';
import { CorrelationPage } from './pages/CorrelationPage';
import { IncidentProvider } from './context/IncidentContext';

// Single shared QueryClient for the whole app. Constructed outside the component
// so it survives re-renders and is not recreated on every auth state change.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      // 10 s: absorbs SPA navigation re-mounts without hammering the API.
      // See file-level comment for rationale.
      staleTime: 10_000,
    },
  },
});

export default function App() {
  // Lazy initialiser: if a token is already in sessionStorage (e.g. page refresh),
  // skip the gate immediately without a flicker.
  const [authenticated, setAuthenticated] = useState(() => Boolean(getToken()));

  // TokenGate intentionally rendered before QueryClientProvider — see file-level comment.
  if (!authenticated) {
    return (
      <TokenGate
        onAuthenticated={() => setAuthenticated(true)}
      />
    );
  }

  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        {/* IncidentProvider inside BrowserRouter so context consumers can use
            useNavigate if needed, but outside PageLayout so the nav bar can
            also read the active incident. */}
        <IncidentProvider>
          <PageLayout>
            <Routes>
              <Route path="/" element={<OverviewPage />} />
              <Route path="/events" element={<EventsPage />} />
              <Route path="/detections" element={<DetectionsPage />} />
              <Route path="/rules" element={<RulesPage />} />
              <Route path="/ingestion" element={<IngestionPage />} />
              <Route path="/health" element={<HealthPage />} />
              <Route path="/query" element={<QueryPage />} />
              <Route path="/categories" element={<CategoryDashboardPage />} />
              <Route path="/incidents" element={<IncidentsPage />} />
              <Route path="/incidents/:id" element={<IncidentDetailPage />} />
              <Route path="/correlation" element={<CorrelationPage />} />
            </Routes>
          </PageLayout>
        </IncidentProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
