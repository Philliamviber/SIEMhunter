/**
 * SigmaAuthorPage tests.
 *
 * Verifies the page renders correctly and that compile / dry-run actions
 * invoke the correct hooks and display results or errors.
 *
 * useSigmaCompile and useSigmaDryRun are mocked at module level.
 * ApiClientError is mocked so the page can import it without a real fetch client.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

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

// Mutable state so individual tests can configure hook behaviour.
let compileState: { mutateAsync: ReturnType<typeof vi.fn>; isPending: boolean };
let dryRunState: { mutateAsync: ReturnType<typeof vi.fn>; isPending: boolean };

vi.mock('../../hooks/useApi', () => ({
  useSigmaCompile: () => compileState,
  useSigmaDryRun: () => dryRunState,
}));

import { SigmaAuthorPage } from '../SigmaAuthorPage';

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

beforeEach(() => {
  compileState = { mutateAsync: vi.fn(), isPending: false };
  dryRunState = { mutateAsync: vi.fn(), isPending: false };
});

// ── Rendering ─────────────────────────────────────────────────────────────────

describe('SigmaAuthorPage rendering', () => {
  it('renders the page heading', () => {
    render(<SigmaAuthorPage />, { wrapper });
    expect(screen.getByText('Sigma Rule Author')).toBeTruthy();
  });

  it('renders the YAML editor textarea', () => {
    render(<SigmaAuthorPage />, { wrapper });
    expect(screen.getByTestId('sigma-editor')).toBeTruthy();
  });

  it('renders Compile and Dry-Run buttons', () => {
    render(<SigmaAuthorPage />, { wrapper });
    expect(screen.getByTestId('compile-btn')).toBeTruthy();
    expect(screen.getByTestId('dryrun-btn')).toBeTruthy();
  });

  it('pre-fills the editor with starter YAML', () => {
    render(<SigmaAuthorPage />, { wrapper });
    const editor = screen.getByTestId('sigma-editor') as HTMLTextAreaElement;
    expect(editor.value).toContain('Kerberoasting');
  });
});

// ── Compile action ────────────────────────────────────────────────────────────

describe('compile action', () => {
  it('calls useSigmaCompile.mutateAsync with the editor content on click', async () => {
    compileState.mutateAsync = vi.fn().mockResolvedValue({
      sql: 'SELECT * FROM security_events WHERE EventID = 4769',
      title: 'Test Rule',
      rule_id: 'test-001',
    });

    render(<SigmaAuthorPage />, { wrapper });
    fireEvent.click(screen.getByTestId('compile-btn'));

    await waitFor(() => {
      expect(compileState.mutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({ sigma_yaml: expect.stringContaining('Kerberoasting') }),
      );
    });
  });

  it('displays compiled SQL on success', async () => {
    compileState.mutateAsync = vi.fn().mockResolvedValue({
      sql: 'SELECT * FROM security_events WHERE EventID = 4769',
      title: 'My Rule',
      rule_id: 'my-001',
    });

    render(<SigmaAuthorPage />, { wrapper });
    fireEvent.click(screen.getByTestId('compile-btn'));

    await waitFor(() => {
      expect(screen.getByText(/SELECT \* FROM security_events/)).toBeTruthy();
    });
  });

  it('displays compile error message on failure', async () => {
    const { ApiClientError } = await import('../../api/client');
    compileState.mutateAsync = vi.fn().mockRejectedValue(
      new ApiClientError(422, 'SIGMA_COMPILE_ERROR', 'Sigma compile error: unknown field BadField'),
    );

    render(<SigmaAuthorPage />, { wrapper });
    fireEvent.click(screen.getByTestId('compile-btn'));

    await waitFor(() => {
      expect(screen.getByText(/unknown field BadField/)).toBeTruthy();
    });
  });
});

// ── Dry-run action ────────────────────────────────────────────────────────────

describe('dry-run action', () => {
  it('calls useSigmaDryRun.mutateAsync with sigma_yaml on click', async () => {
    dryRunState.mutateAsync = vi.fn().mockResolvedValue({
      sql: 'SELECT * FROM security_events WHERE EventID = 4769',
      sample_rows: [],
      sampled_count: 0,
      execution_time_ms: 42.5,
    });

    render(<SigmaAuthorPage />, { wrapper });
    fireEvent.click(screen.getByTestId('dryrun-btn'));

    await waitFor(() => {
      expect(dryRunState.mutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({ sigma_yaml: expect.any(String) }),
      );
    });
  });

  it('shows match count and zero-results message when no events match', async () => {
    dryRunState.mutateAsync = vi.fn().mockResolvedValue({
      sql: 'SELECT * FROM security_events WHERE EventID = 4769',
      sample_rows: [],
      sampled_count: 0,
      execution_time_ms: 12.3,
    });

    render(<SigmaAuthorPage />, { wrapper });
    fireEvent.click(screen.getByTestId('dryrun-btn'));

    await waitFor(() => {
      expect(screen.getByTestId('dryrun-match-count').textContent).toMatch(/0 match/);
      expect(screen.getByTestId('dryrun-no-results')).toBeTruthy();
    });
  });

  it('shows sample rows table when events match', async () => {
    dryRunState.mutateAsync = vi.fn().mockResolvedValue({
      sql: 'SELECT * FROM security_events WHERE EventID = 4769',
      sample_rows: [
        { EventID: 4769, HostName: 'dc01' },
        { EventID: 4769, HostName: 'dc02' },
      ],
      sampled_count: 2,
      execution_time_ms: 88.0,
    });

    render(<SigmaAuthorPage />, { wrapper });
    fireEvent.click(screen.getByTestId('dryrun-btn'));

    await waitFor(() => {
      expect(screen.getByTestId('dryrun-match-count').textContent).toMatch(/2 match/);
      expect(screen.getByText('dc01')).toBeTruthy();
      expect(screen.getByText('dc02')).toBeTruthy();
    });
  });

  it('shows error message when dry-run is rejected (e.g. FORBIDDEN_STATEMENT)', async () => {
    const { ApiClientError } = await import('../../api/client');
    dryRunState.mutateAsync = vi.fn().mockRejectedValue(
      new ApiClientError(400, 'FORBIDDEN_STATEMENT', 'Semicolons are not permitted in dry-run SQL'),
    );

    render(<SigmaAuthorPage />, { wrapper });
    fireEvent.click(screen.getByTestId('dryrun-btn'));

    await waitFor(() => {
      expect(screen.getByText(/Semicolons are not permitted/)).toBeTruthy();
    });
  });
});
