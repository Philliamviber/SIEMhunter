/**
 * App.tsx — Root React component for the SIEMhunter dashboard.
 *
 * Auth gate: LoginGate is rendered OUTSIDE QueryClientProvider and BrowserRouter.
 * This is deliberate — if LoginGate were inside QueryClientProvider, TanStack Query
 * could fire background fetches (e.g. from useQuery hooks in child components) before
 * the analyst has signed in, causing a flood of 401 errors and polluting the
 * query cache. (FR #10 replaced the paste-token TokenGate with a per-analyst
 * username/password LoginGate backed by a server-side cookie session.)
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
import { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { getSession, getCsrfToken, markSessionStart } from './api/client';
import { LoginGate } from './components/LoginGate';
import { ToastProvider } from './components/ToastProvider';
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
  // Lazy initialiser: if a CSRF token is present (e.g. page refresh inside a
  // live session), optimistically skip the gate — the mount-time session
  // re-validation below confirms or revokes it. The HttpOnly session cookie
  // itself is not readable by JS, so the CSRF token is our only client-side hint.
  const [authenticated, setAuthenticated] = useState(() => Boolean(getCsrfToken()));

  // AC#6/AC#8: re-validate the session against the server on mount and on
  // window focus (covers the back-button-after-logout case and idle expiry).
  // If the server says the session is gone, fall back to the LoginGate.
  useEffect(() => {
    if (!authenticated) return;
    let cancelled = false;

    async function revalidate() {
      try {
        await getSession();
        if (!cancelled) markSessionStart();
      } catch {
        if (!cancelled) setAuthenticated(false);
      }
    }

    void revalidate();
    window.addEventListener('focus', revalidate);
    return () => {
      cancelled = true;
      window.removeEventListener('focus', revalidate);
    };
  }, [authenticated]);

  // LoginGate intentionally rendered before QueryClientProvider — see file-level comment.
  if (!authenticated) {
    return (
      <LoginGate
        onAuthenticated={() => setAuthenticated(true)}
      />
    );
  }

  return (
    <QueryClientProvider client={queryClient}>
      {/* ToastProvider sits inside QueryClientProvider (after the LoginGate
          check) so the global toast container renders once for the whole app
          and the 401 interceptor can surface 'Session expired' (FR #23). */}
      <ToastProvider>
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
      </ToastProvider>
    </QueryClientProvider>
  );
}
