/**
 * DetectionsPage render test.
 *
 * Verifies the component mounts without crashing in the loading state.
 * ReactECharts is mocked to avoid canvas issues in jsdom.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

vi.mock('echarts-for-react', () => ({
  default: () => <div data-testid="echarts-mock" />,
}));

vi.mock('../../hooks/useApi', () => ({
  useDetections: () => ({ data: undefined, isLoading: true, isError: false }),
  useAiSummary: () => ({ data: null, isLoading: false, isError: false }),
}));

import { DetectionsPage } from '../DetectionsPage';

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

describe('DetectionsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders without crashing', () => {
    render(<DetectionsPage />, { wrapper });
    expect(screen.getByText('Detections')).toBeTruthy();
  });

  it('renders timeline section heading', () => {
    render(<DetectionsPage />, { wrapper });
    expect(screen.getByText('Hit Timeline by Severity')).toBeTruthy();
  });

  it('renders filter sidebar', () => {
    render(<DetectionsPage />, { wrapper });
    expect(screen.getByText('Filters')).toBeTruthy();
  });

  it('renders severity filter options', () => {
    render(<DetectionsPage />, { wrapper });
    // The select element for severity contains these option texts
    expect(screen.getByText('Critical')).toBeTruthy();
    expect(screen.getByText('High')).toBeTruthy();
    expect(screen.getByText('Medium')).toBeTruthy();
    expect(screen.getByText('Low')).toBeTruthy();
  });

  it('does not render error banner in loading state', () => {
    render(<DetectionsPage />, { wrapper });
    expect(screen.queryByText(/Failed to load detections/i)).toBeNull();
  });
});
