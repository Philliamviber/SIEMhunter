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

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 10_000,
    },
  },
});

export default function App() {
  const [authenticated, setAuthenticated] = useState(() => Boolean(getToken()));

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
