/**
 * IngestionPage render test.
 *
 * Verifies the component mounts without crashing in loading and data states.
 * ReactECharts is mocked to avoid canvas issues in jsdom.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { IngestionSummaryResponse } from '../../types/api';

vi.mock('echarts-for-react', () => ({
  default: () => <div data-testid="echarts-mock" />,
}));

let ingestionState: {
  data: IngestionSummaryResponse | undefined;
  isLoading: boolean;
  isError: boolean;
} = { data: undefined, isLoading: true, isError: false };

vi.mock('../../hooks/useApi', () => ({
  useIngestionSummary: () => ingestionState,
}));

import { IngestionPage } from '../IngestionPage';

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

describe('IngestionPage', () => {
  beforeEach(() => {
    ingestionState = { data: undefined, isLoading: true, isError: false };
    vi.clearAllMocks();
  });

  it('renders without crashing', () => {
    render(<IngestionPage />, { wrapper });
    expect(screen.getByText('Ingestion Context')).toBeTruthy();
  });

  it('renders section headings', () => {
    render(<IngestionPage />, { wrapper });
    expect(screen.getByText('Source Breakdown (24h)')).toBeTruthy();
    expect(screen.getByText('Event Volume Over Time (24h)')).toBeTruthy();
    expect(screen.getByText('Per-Source Stats')).toBeTruthy();
  });

  it('renders pipeline latency section', () => {
    render(<IngestionPage />, { wrapper });
    expect(screen.getByText('Pipeline Latency (24h)')).toBeTruthy();
  });

  it('renders rate-limit panel', () => {
    render(<IngestionPage />, { wrapper });
    expect(screen.getByText('Rate-Limit / Flood Panel')).toBeTruthy();
  });

  it('does not show error banner in loading state', () => {
    render(<IngestionPage />, { wrapper });
    expect(screen.queryByText(/Failed to load ingestion summary/i)).toBeNull();
  });

  it('shows error banner when isError=true', () => {
    ingestionState = { data: undefined, isLoading: false, isError: true };
    render(<IngestionPage />, { wrapper });
    expect(screen.getByText(/Failed to load ingestion summary/i)).toBeTruthy();
  });
});
