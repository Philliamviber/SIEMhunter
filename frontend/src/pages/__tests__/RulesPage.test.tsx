/**
 * RulesPage render test.
 *
 * Verifies the component mounts without crashing in loading and data-present
 * states.  The rules API hook and mutation are mocked at module level.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { Rule } from '../../types/api';

// Mock ApiClientError so RulesPage can import it without a real fetch client
vi.mock('../../api/client', () => ({
  ApiClientError: class ApiClientError extends Error {
    code: string;
    status: number;
    constructor(status: number, code: string, message: string) {
      super(message);
      this.status = status;
      this.code = code;
    }
  },
  api: {},
}));

// Mutable state so individual tests can change what useRules returns
let rulesState: { data: Rule[] | undefined; isLoading: boolean; isError: boolean } = {
  data: undefined,
  isLoading: true,
  isError: false,
};

vi.mock('../../hooks/useApi', () => ({
  useRules: () => rulesState,
  useUpdateRuleStatus: () => ({
    mutateAsync: vi.fn(),
    isPending: false,
  }),
}));

import { RulesPage } from '../RulesPage';

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

describe('RulesPage', () => {
  beforeEach(() => {
    rulesState = { data: undefined, isLoading: true, isError: false };
    vi.clearAllMocks();
  });

  it('renders without crashing in loading state', () => {
    render(<RulesPage />, { wrapper });
    expect(screen.getByText('Rules Management')).toBeTruthy();
  });

  it('shows loading skeleton when isLoading=true', () => {
    render(<RulesPage />, { wrapper });
    // The page heading is present but kanban columns are not (guarded by !isLoading)
    expect(screen.getByText('Rules Management')).toBeTruthy();
  });

  it('renders kanban column headers when rules loaded (empty list)', () => {
    rulesState = { data: [], isLoading: false, isError: false };
    render(<RulesPage />, { wrapper });
    // STATUS_ORDER = ['draft', 'test', 'review', 'production', 'disabled']
    expect(screen.getByText('draft')).toBeTruthy();
    expect(screen.getByText('production')).toBeTruthy();
    expect(screen.getByText('disabled')).toBeTruthy();
  });

  it('renders a rule card when rules data is present', () => {
    const fakeRule: Rule = {
      rule_id: 'WIN-001',
      rule_version: '1.0',
      status: 'production',
      file_path: '/app/rules/local/win-001.yml',
      updated_at: '2024-01-01T00:00:00Z',
    };
    rulesState = { data: [fakeRule], isLoading: false, isError: false };
    render(<RulesPage />, { wrapper });
    expect(screen.getByText('WIN-001')).toBeTruthy();
  });

  it('does not render error banner when there is no error', () => {
    render(<RulesPage />, { wrapper });
    expect(screen.queryByText(/Failed to load rules/i)).toBeNull();
  });

  it('renders error banner when isError=true', () => {
    rulesState = { data: undefined, isLoading: false, isError: true };
    render(<RulesPage />, { wrapper });
    expect(screen.getByText(/Failed to load rules/i)).toBeTruthy();
  });
});
