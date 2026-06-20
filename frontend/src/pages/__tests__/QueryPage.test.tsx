/**
 * QueryPage render test.
 *
 * QueryPage uses the api object directly (not via hooks), so we mock
 * the api/client module.  ApiClientError is also imported by QueryPage.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

// Mock the API client — QueryPage calls api.query() directly
vi.mock('../../api/client', () => ({
  api: {
    query: vi.fn().mockResolvedValue({
      rows: [],
      row_count: 0,
      truncated: false,
      execution_time_ms: 0,
    }),
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
  // v3 auth client surface (the old getToken/setToken/clearToken were removed).
  getCsrfToken: vi.fn().mockReturnValue(null),
  setCsrfToken: vi.fn(),
  clearCsrfToken: vi.fn(),
}));

// Mock QueryResult component to avoid deep rendering
vi.mock('../../components/QueryResult', () => ({
  QueryResult: ({ result }: { result: unknown }) => (
    <div data-testid="query-result">{JSON.stringify(result)}</div>
  ),
}));

import { QueryPage } from '../QueryPage';

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

describe('QueryPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders without crashing', () => {
    render(<QueryPage />, { wrapper });
    expect(screen.getByText('Query Console')).toBeTruthy();
  });

  it('renders the SQL textarea', () => {
    render(<QueryPage />, { wrapper });
    expect(
      screen.getByPlaceholderText(/SELECT TimeGenerated/i)
    ).toBeTruthy();
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
    expect(btn).toBeDefined();
    expect(btn?.disabled).toBe(true);
  });

  it('does not render result panel before a query is run', () => {
    render(<QueryPage />, { wrapper });
    expect(screen.queryByTestId('query-result')).toBeNull();
  });
});
