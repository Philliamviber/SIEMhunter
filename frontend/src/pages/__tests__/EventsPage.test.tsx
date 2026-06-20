/**
 * EventsPage tests — render, filter controls, and URL-param seeding (FR #11).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
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

function wrapperWithUrl(initialUrl: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return function W({ children }: { children: React.ReactNode }) {
    return (
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={[initialUrl]}>{children}</MemoryRouter>
      </QueryClientProvider>
    );
  };
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
    expect(screen.queryByText(/Failed to load events/i)).toBeNull();
  });

  // ── FR #11 — URL param seeding ───────────────────────────────────────────────

  it('seeds hostname filter from URL param on mount', () => {
    render(<EventsPage />, { wrapper: wrapperWithUrl('/events?hostname=dc01.corp.local') });
    const input = screen.getByPlaceholderText('dc01') as HTMLInputElement;
    expect(input.value).toBe('dc01.corp.local');
  });

  it('seeds subject_user_name filter from URL param on mount', () => {
    render(<EventsPage />, { wrapper: wrapperWithUrl('/events?subject_user_name=jdoe') });
    const input = screen.getByPlaceholderText('SYSTEM') as HTMLInputElement;
    expect(input.value).toBe('jdoe');
  });

  it('seeds src_ip_addr filter from URL param on mount', () => {
    render(<EventsPage />, { wrapper: wrapperWithUrl('/events?src_ip_addr=10.0.0.5') });
    const input = screen.getByPlaceholderText('192.168.1.1') as HTMLInputElement;
    expect(input.value).toBe('10.0.0.5');
  });

  it('seeds event_id filter from URL param on mount', () => {
    render(<EventsPage />, { wrapper: wrapperWithUrl('/events?event_id=4624') });
    const input = screen.getByPlaceholderText('4624') as HTMLInputElement;
    expect(input.value).toBe('4624');
  });

  it('starts empty when no URL params are present', () => {
    render(<EventsPage />, { wrapper: wrapperWithUrl('/events') });
    const hostnameInput = screen.getByPlaceholderText('dc01') as HTMLInputElement;
    expect(hostnameInput.value).toBe('');
  });

  it('clears all filter inputs when Clear is clicked', async () => {
    render(<EventsPage />, { wrapper: wrapperWithUrl('/events?hostname=dc01') });
    const hostnameInput = screen.getByPlaceholderText('dc01') as HTMLInputElement;
    expect(hostnameInput.value).toBe('dc01');
    await userEvent.click(screen.getByText('Clear'));
    expect(hostnameInput.value).toBe('');
  });
});
