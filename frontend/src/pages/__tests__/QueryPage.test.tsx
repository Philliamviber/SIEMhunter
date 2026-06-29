/**
 * QueryPage tests — render, query submission, history re-run, and saved views.
 *
 * QueryPage uses the api object directly (not via hooks), so we mock
 * the api/client module.  ApiClientError is also imported by QueryPage.
 * useQueryHistory, useAddQueryHistory, and SavedViewsPanel are mocked so
 * this test is not coupled to their internals.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

// ── API client mock ───────────────────────────────────────────────────────────

const mockApiQuery = vi.fn().mockResolvedValue({
  rows: [],
  row_count: 0,
  truncated: false,
  execution_time_ms: 42,
});

vi.mock('../../api/client', () => ({
  api: {
    query: (...args: unknown[]) => mockApiQuery(...args),
  },
  ApiClientError: class ApiClientError extends Error {
    code: string;
    status: number;
    constructor(status: number, code: string, message: string) {
      super(message);
      this.status = status;
      this.code = code;
    }
  },
  getCsrfToken: vi.fn().mockReturnValue(null),
  setCsrfToken: vi.fn(),
  clearCsrfToken: vi.fn(),
}));

// ── Mock hooks that QueryPage now uses ────────────────────────────────────────

const mockAddHistoryMutate = vi.fn();
let mockHistoryEntries: Array<{ sql: string; run_at: string }> = [];

vi.mock('../../hooks/useApi', () => ({
  useQueryHistory: () => ({ data: { entries: mockHistoryEntries } }),
  useAddQueryHistory: () => ({ mutate: mockAddHistoryMutate }),
  // SavedViewsPanel's hooks are mocked separately at the component level.
  useSavedViews: () => ({ data: { views: [] }, isLoading: false }),
  useUpsertSavedView: () => ({ mutate: vi.fn(), isPending: false }),
  useDeleteSavedView: () => ({ mutate: vi.fn(), isPending: false }),
}));

// ── Mock sub-components ───────────────────────────────────────────────────────

vi.mock('../../components/QueryResult', () => ({
  QueryResult: ({ result }: { result: unknown }) => (
    <div data-testid="query-result">{JSON.stringify(result)}</div>
  ),
}));

vi.mock('../../components/SavedViewsPanel', () => ({
  SavedViewsPanel: ({ onLoad }: { onLoad: (f: Record<string, unknown>) => void }) => (
    <div data-testid="saved-views-panel">
      <button onClick={() => onLoad({ sql: 'SELECT saved FROM test' })}>
        Load saved
      </button>
    </div>
  ),
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

import { QueryPage } from '../QueryPage';

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('QueryPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockHistoryEntries = [];
  });

  it('renders without crashing', () => {
    render(<QueryPage />, { wrapper });
    expect(screen.getByText('Query Console')).toBeTruthy();
  });

  it('renders the SQL textarea', () => {
    render(<QueryPage />, { wrapper });
    expect(screen.getByPlaceholderText(/SELECT TimeGenerated/i)).toBeTruthy();
  });

  it('renders the Run Query button', () => {
    render(<QueryPage />, { wrapper });
    expect(screen.getByText('Run Query')).toBeTruthy();
  });

  it('renders the security note about SELECT-only queries', () => {
    render(<QueryPage />, { wrapper });
    expect(screen.getByText(/SELECT-only queries are allowed/i)).toBeTruthy();
  });

  it('renders query templates', () => {
    render(<QueryPage />, { wrapper });
    expect(screen.getByText('Recent events — last hour')).toBeTruthy();
    expect(screen.getByText('Top rule hits — last 24h')).toBeTruthy();
  });

  it('Run Query button is disabled when SQL textarea is empty', () => {
    render(<QueryPage />, { wrapper });
    const btn = screen.getByText('Run Query').closest('button');
    expect(btn?.disabled).toBe(true);
  });

  it('does not render result panel before a query is run', () => {
    render(<QueryPage />, { wrapper });
    expect(screen.queryByTestId('query-result')).toBeNull();
  });

  it('renders the saved-views panel', () => {
    render(<QueryPage />, { wrapper });
    expect(screen.getByTestId('saved-views-panel')).toBeTruthy();
  });

  it('renders "No history yet" when history is empty', () => {
    render(<QueryPage />, { wrapper });
    expect(screen.getByText('No history yet')).toBeTruthy();
  });

  it('renders history entries when they exist', () => {
    mockHistoryEntries = [
      { sql: 'SELECT 1 FROM test', run_at: '2026-01-01T00:00:00Z' },
    ];
    render(<QueryPage />, { wrapper });
    expect(screen.getByText(/SELECT 1 FROM test/)).toBeTruthy();
  });

  it('re-running a history entry calls api.query with the recorded SQL', async () => {
    const historySql = 'SELECT EventID FROM siemhunter.security_events LIMIT 5';
    mockHistoryEntries = [{ sql: historySql, run_at: '2026-01-01T00:00:00Z' }];
    render(<QueryPage />, { wrapper });
    const rerunBtn = screen.getByLabelText(`Re-run: ${historySql.slice(0, 60)}`);
    await userEvent.click(rerunBtn);
    await waitFor(() => {
      expect(mockApiQuery).toHaveBeenCalledWith({ sql: historySql });
    });
  });

  it('re-running a history entry records it in history', async () => {
    const historySql = 'SELECT 42';
    mockHistoryEntries = [{ sql: historySql, run_at: '2026-01-01T00:00:00Z' }];
    render(<QueryPage />, { wrapper });
    const rerunBtn = screen.getByLabelText(`Re-run: ${historySql.slice(0, 60)}`);
    await userEvent.click(rerunBtn);
    await waitFor(() => {
      expect(mockAddHistoryMutate).toHaveBeenCalledWith(historySql);
    });
  });

  it('loading a saved view populates the SQL editor', async () => {
    render(<QueryPage />, { wrapper });
    await userEvent.click(screen.getByText('Load saved'));
    const textarea = screen.getByPlaceholderText(/SELECT TimeGenerated/i) as HTMLTextAreaElement;
    expect(textarea.value).toBe('SELECT saved FROM test');
  });

  it('records query history after a successful run', async () => {
    render(<QueryPage />, { wrapper });
    const textarea = screen.getByPlaceholderText(/SELECT TimeGenerated/i);
    await userEvent.type(textarea, 'SELECT 1');
    const runBtn = screen.getByText('Run Query');
    await userEvent.click(runBtn);
    await waitFor(() => {
      expect(mockAddHistoryMutate).toHaveBeenCalledWith('SELECT 1');
    });
  });
});
