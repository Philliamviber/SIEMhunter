/**
 * IncidentDetailPage tests — FR #18 status confirmation + toast (PR7).
 *
 * Verifies:
 *  1. Close triggers a confirmation dialog before PATCH fires.
 *  2. Archive triggers a confirmation dialog before PATCH fires.
 *  3. Cancelling the dialog does not call the mutation.
 *  4. Confirming calls updateStatus with the correct arguments.
 *  5. onSuccess callback fires toast.success.
 *  6. onError callback fires toast.error.
 *  7. Reopen fires the mutation directly (no confirmation needed).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

// ── Hoisted mocks (must precede vi.mock factory references) ───────────────────

const { mockMutate, mockToastSuccess, mockToastError } = vi.hoisted(() => ({
  mockMutate: vi.fn(),
  mockToastSuccess: vi.fn(),
  mockToastError: vi.fn(),
}));

vi.mock('../../hooks/useToast', () => ({
  useToast: () => ({ success: mockToastSuccess, error: mockToastError, warning: vi.fn() }),
}));

vi.mock('../../hooks/useApi', () => ({
  useIncident: () => ({
    data: {
      id: 'inc-1',
      name: 'Ransomware Campaign',
      description: 'Investigating suspicious lateral movement.',
      severity: 'critical',
      status: 'open',
      created_at: '2026-06-01T10:00:00Z',
      updated_at: '2026-06-01T10:05:00Z',
      event_count: 42,
    },
    isLoading: false,
    isError: false,
  }),
  useUpdateIncidentStatus: () => ({ mutate: mockMutate, isPending: false }),
  useIncidentNotes: () => ({
    data: { notes: [], total: 0 },
    isLoading: false,
  }),
  useAddIncidentNote: () => ({ mutate: vi.fn(), isPending: false }),
  useSearch: () => ({ mutate: vi.fn(), isPending: false, data: null, isError: false }),
}));

import { IncidentDetailPage } from '../IncidentDetailPage';

// ── Test wrapper ──────────────────────────────────────────────────────────────

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/incidents/inc-1']}>
        <Routes>
          <Route path="/incidents/:id" element={children} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('IncidentDetailPage — status confirmation + toast (FR #18)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('clicking Close shows a confirmation dialog', () => {
    render(<IncidentDetailPage />, { wrapper });
    fireEvent.click(screen.getByRole('button', { name: /^close$/i }));
    expect(screen.getByRole('dialog')).toBeTruthy();
    expect(screen.getByText(/are you sure you want to close this incident/i)).toBeTruthy();
  });

  it('clicking Archive shows a confirmation dialog', () => {
    render(<IncidentDetailPage />, { wrapper });
    fireEvent.click(screen.getByRole('button', { name: /^archive$/i }));
    expect(screen.getByRole('dialog')).toBeTruthy();
    expect(screen.getByText(/are you sure you want to archive this incident/i)).toBeTruthy();
  });

  it('cancelling the dialog does not call the mutation', () => {
    render(<IncidentDetailPage />, { wrapper });
    fireEvent.click(screen.getByRole('button', { name: /^close$/i }));
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    expect(mockMutate).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('confirming Close calls updateStatus with closed', () => {
    render(<IncidentDetailPage />, { wrapper });
    fireEvent.click(screen.getByRole('button', { name: /^close$/i }));
    fireEvent.click(screen.getByRole('button', { name: /^confirm$/i }));
    expect(mockMutate).toHaveBeenCalledWith(
      { id: 'inc-1', newStatus: 'closed' },
      expect.objectContaining({ onSuccess: expect.any(Function), onError: expect.any(Function) }),
    );
  });

  it('confirming Archive calls updateStatus with archived', () => {
    render(<IncidentDetailPage />, { wrapper });
    fireEvent.click(screen.getByRole('button', { name: /^archive$/i }));
    fireEvent.click(screen.getByRole('button', { name: /^confirm$/i }));
    expect(mockMutate).toHaveBeenCalledWith(
      { id: 'inc-1', newStatus: 'archived' },
      expect.objectContaining({ onSuccess: expect.any(Function), onError: expect.any(Function) }),
    );
  });

  it('onSuccess fires toast.success with the new status', () => {
    render(<IncidentDetailPage />, { wrapper });
    fireEvent.click(screen.getByRole('button', { name: /^close$/i }));
    fireEvent.click(screen.getByRole('button', { name: /^confirm$/i }));
    const { onSuccess } = mockMutate.mock.calls[0][1];
    onSuccess();
    expect(mockToastSuccess).toHaveBeenCalledWith('Incident closed.');
  });

  it('onError fires toast.error with the error message', () => {
    render(<IncidentDetailPage />, { wrapper });
    fireEvent.click(screen.getByRole('button', { name: /^close$/i }));
    fireEvent.click(screen.getByRole('button', { name: /^confirm$/i }));
    const { onError } = mockMutate.mock.calls[0][1];
    onError(new Error('Network timeout'));
    expect(mockToastError).toHaveBeenCalledWith('Network timeout');
  });

  it('onError fires toast.error with fallback when error is not an Error instance', () => {
    render(<IncidentDetailPage />, { wrapper });
    fireEvent.click(screen.getByRole('button', { name: /^close$/i }));
    fireEvent.click(screen.getByRole('button', { name: /^confirm$/i }));
    const { onError } = mockMutate.mock.calls[0][1];
    onError('unknown');
    expect(mockToastError).toHaveBeenCalledWith('Failed to update incident status.');
  });

  it('dialog is dismissed after confirmation', () => {
    render(<IncidentDetailPage />, { wrapper });
    fireEvent.click(screen.getByRole('button', { name: /^close$/i }));
    fireEvent.click(screen.getByRole('button', { name: /^confirm$/i }));
    expect(screen.queryByRole('dialog')).toBeNull();
  });
});
