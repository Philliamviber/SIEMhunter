/**
 * OverviewPage render test.
 *
 * Verifies the component mounts without crashing when data is loading.
 * All API hooks are mocked so no network requests are made.
 * ReactECharts is mocked to avoid canvas/SVG rendering complexity in jsdom.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

// Mock echarts-for-react — jsdom has no canvas
vi.mock('echarts-for-react', () => ({
  default: () => <div data-testid="echarts-mock" />,
}));

// Mock all API hooks used by OverviewPage
vi.mock('../../hooks/useApi', () => ({
  useMetrics: () => ({ data: undefined, isLoading: true, isError: false }),
  useStatus: () => ({ data: undefined, isLoading: true, isError: false }),
  useAiSummary: () => ({ data: undefined, isLoading: true, isError: false }),
  useDetections: () => ({ data: undefined, isLoading: true, isError: false }),
}));

import { OverviewPage } from '../OverviewPage';

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

describe('OverviewPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders without crashing', () => {
    render(<OverviewPage />, { wrapper });
    // The heading must be present
    expect(screen.getByText('Overview')).toBeTruthy();
  });

  it('renders KPI card labels while loading', () => {
    render(<OverviewPage />, { wrapper });
    expect(screen.getByText('Events (24h)')).toBeTruthy();
    expect(screen.getByText('Detection Hits (24h)')).toBeTruthy();
  });

  it('renders AI Security Summary section while loading', () => {
    render(<OverviewPage />, { wrapper });
    expect(screen.getByText('AI Security Summary')).toBeTruthy();
  });

  it('renders Recent High Severity Hits section', () => {
    render(<OverviewPage />, { wrapper });
    expect(screen.getByText('Recent High Severity Hits')).toBeTruthy();
  });
});
