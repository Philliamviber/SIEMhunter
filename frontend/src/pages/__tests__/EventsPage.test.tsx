/**
 * EventsPage render test.
 *
 * Verifies the component mounts without crashing in the loading state.
 * The useEvents hook is mocked; no network requests are made.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

vi.mock('../../hooks/useApi', () => ({
  useEvents: () => ({ data: undefined, isLoading: true, isError: false }),
  useAiSummary: () => ({ data: null, isLoading: false, isError: false }),
}));

import { EventsPage } from '../EventsPage';

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

describe('EventsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders without crashing', () => {
    render(<EventsPage />, { wrapper });
    expect(screen.getByText('Security Events')).toBeTruthy();
  });

  it('renders filter controls', () => {
    render(<EventsPage />, { wrapper });
    expect(screen.getByPlaceholderText('dc01')).toBeTruthy();
    expect(screen.getByPlaceholderText('4624')).toBeTruthy();
    expect(screen.getByPlaceholderText('192.168.1.1')).toBeTruthy();
  });

  it('renders Apply and Clear buttons', () => {
    render(<EventsPage />, { wrapper });
    expect(screen.getByText('Apply')).toBeTruthy();
    expect(screen.getByText('Clear')).toBeTruthy();
  });

  it('does not render error banner in loading state', () => {
    render(<EventsPage />, { wrapper });
    expect(
      screen.queryByText(/Failed to load events/i)
    ).toBeNull();
  });
});
