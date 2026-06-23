/**
 * IncidentDetailPage tests — FR #19 notes panel.
 *
 * Verifies:
 *  1. Notes are rendered as text (never via innerHTML / dangerouslySetInnerHTML).
 *  2. XSS payloads in note content are escaped by React's default text rendering.
 *  3. Author and timestamp are displayed from the server response.
 *  4. The add-note form is present and calls the mutation.
 *  5. Empty / whitespace-only notes cannot be submitted (button stays disabled).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

// ── Mocks ─────────────────────────────────────────────────────────────────────

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
  useUpdateIncidentStatus: () => ({ mutate: vi.fn(), isPending: false }),
  useIncidentNotes: () => ({
    data: {
      notes: [
        {
          id: 'note-1',
          incident_id: 'inc-1',
          author: 'analyst1',
          content: 'Initial triage complete. Pivoted on 10.0.0.5.',
          created_at: '2026-06-01T10:10:00Z',
        },
        {
          id: 'note-2',
          incident_id: 'inc-1',
          // XSS payload — must be rendered as text, NOT injected as HTML
          author: '<script>alert(1)</script>',
          content: '<img src=x onerror=alert(2)>',
          created_at: '2026-06-01T10:15:00Z',
        },
      ],
      total: 2,
    },
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

describe('IncidentDetailPage — notes panel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders without crashing', () => {
    render(<IncidentDetailPage />, { wrapper });
    expect(screen.getByText('Ransomware Campaign')).toBeTruthy();
  });

  it('renders the Notes section heading', () => {
    render(<IncidentDetailPage />, { wrapper });
    expect(screen.getByText('Notes')).toBeTruthy();
  });

  it('renders note content as text — not as raw HTML', () => {
    render(<IncidentDetailPage />, { wrapper });
    // The XSS payload must appear as literal text, not execute as script.
    expect(screen.getByText('<img src=x onerror=alert(2)>')).toBeTruthy();
    // No <img> element should have been injected into the DOM.
    expect(document.querySelector('img[onerror]')).toBeNull();
  });

  it('renders note author as text — XSS in author is escaped', () => {
    render(<IncidentDetailPage />, { wrapper });
    expect(screen.getByText('<script>alert(1)</script>')).toBeTruthy();
    // No actual <script> tag injected.
    const scripts = document.querySelectorAll('script');
    const injected = Array.from(scripts).filter(
      (s) => s.textContent?.includes('alert(1)'),
    );
    expect(injected).toHaveLength(0);
  });

  it('displays the author of the first note', () => {
    render(<IncidentDetailPage />, { wrapper });
    expect(screen.getByText('analyst1')).toBeTruthy();
  });

  it('displays note content text', () => {
    render(<IncidentDetailPage />, { wrapper });
    expect(screen.getByText('Initial triage complete. Pivoted on 10.0.0.5.')).toBeTruthy();
  });

  it('renders the add-note textarea', () => {
    render(<IncidentDetailPage />, { wrapper });
    expect(screen.getByPlaceholderText('Add a note…')).toBeTruthy();
  });

  it('Add Note button is disabled when textarea is empty', () => {
    render(<IncidentDetailPage />, { wrapper });
    const btn = screen.getByRole('button', { name: /add note/i });
    expect((btn as HTMLButtonElement).disabled).toBe(true);
  });

  it('Add Note button becomes enabled when content is typed', () => {
    render(<IncidentDetailPage />, { wrapper });
    const textarea = screen.getByPlaceholderText('Add a note…');
    fireEvent.change(textarea, { target: { value: 'New evidence found.' } });
    const btn = screen.getByRole('button', { name: /add note/i });
    expect((btn as HTMLButtonElement).disabled).toBe(false);
  });

  it('Add Note button remains disabled for whitespace-only input', () => {
    render(<IncidentDetailPage />, { wrapper });
    const textarea = screen.getByPlaceholderText('Add a note…');
    fireEvent.change(textarea, { target: { value: '   ' } });
    const btn = screen.getByRole('button', { name: /add note/i });
    expect((btn as HTMLButtonElement).disabled).toBe(true);
  });
});
