/**
 * HealthPage render test.
 *
 * HealthPage calls useHealthService(name) once per service inside a rendered
 * loop, and also calls useRules + useDetections inside SelfRuleRow children.
 * All hooks are mocked at module level.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

const IDLE = { data: undefined, isLoading: true, isError: false };

vi.mock('../../hooks/useApi', () => ({
  useStatus: () => IDLE,
  useHealthService: (_name: string) => IDLE,
  useRules: () => ({ data: [], isLoading: false, isError: false }),
  useDetections: () => ({ data: { hits: [], total_count: 0, timeline: [] }, isLoading: false, isError: false }),
}));

import { HealthPage } from '../HealthPage';

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

describe('HealthPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders without crashing', () => {
    render(<HealthPage />, { wrapper });
    expect(screen.getByText('Health')).toBeTruthy();
  });

  it('renders service status grid heading', () => {
    render(<HealthPage />, { wrapper });
    expect(screen.getByText('Service Status')).toBeTruthy();
  });

  it('renders all expected service tiles', () => {
    render(<HealthPage />, { wrapper });
    // SERVICE_NAMES = ['vector', 'clickhouse', 'normalization', 'detection', 'forwarder']
    for (const name of ['vector', 'clickhouse', 'normalization', 'detection', 'forwarder']) {
      expect(screen.getByText(name)).toBeTruthy();
    }
  });

  it('renders self-detection rules section', () => {
    render(<HealthPage />, { wrapper });
    expect(screen.getByText('Self-Detection Rules (SELF-001…005)')).toBeTruthy();
  });

  it('renders self-rule IDs', () => {
    render(<HealthPage />, { wrapper });
    for (const id of ['SELF-001', 'SELF-002', 'SELF-003', 'SELF-004', 'SELF-005']) {
      expect(screen.getByText(id)).toBeTruthy();
    }
  });

  it('renders auth and audit feed section', () => {
    render(<HealthPage />, { wrapper });
    expect(screen.getByText('Auth & Audit Feed')).toBeTruthy();
  });

  it('renders forward ledger section', () => {
    render(<HealthPage />, { wrapper });
    expect(screen.getByText('Forward Ledger')).toBeTruthy();
  });
});
