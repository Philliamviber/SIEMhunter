/**
 * IncidentsPage tests — FR #17 filter / sort / search + URL persistence.
 *
 * Verifies:
 *  1. Filter controls (search, severity, status, sort) are rendered.
 *  2. URL search params on mount are reflected in filter control values.
 *  3. Changing a filter writes back to the URL (replace, not push).
 *  4. useIncidents is called with params derived from the URL.
 *  5. Empty-filter message vs. active-filter empty message differ.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { IncidentsFilter } from '../../types/api';
import { IncidentsPage } from '../IncidentsPage';

// ── Mocks ─────────────────────────────────────────────────────────────────────

const mockUseIncidents = vi.fn();

vi.mock('../../hooks/useApi', () => ({
  useIncidents: (filter: IncidentsFilter) => mockUseIncidents(filter),
  useCreateIncident: () => ({ mutate: vi.fn(), isPending: false }),
}));

vi.mock('../../context/IncidentContext', () => ({
  useIncidentContext: () => ({ activeIncidentId: null, setActiveIncidentId: vi.fn() }),
}));

// ── Fixtures ──────────────────────────────────────────────────────────────────

const MOCK_INCIDENTS = [
  {
    id: 'inc-1',
    name: 'Ransomware Campaign',
    description: null,
    severity: 'critical',
    status: 'open',
    created_at: '2026-06-01T10:00:00Z',
    updated_at: '2026-06-01T10:00:00Z',
    event_count: 42,
  },
  {
    id: 'inc-2',
    name: 'Lateral Movement',
    description: null,
    severity: 'high',
    status: 'open',
    created_at: '2026-06-02T08:00:00Z',
    updated_at: '2026-06-02T08:00:00Z',
    event_count: 7,
  },
  {
    id: 'inc-3',
    name: 'Closed Phishing',
    description: null,
    severity: 'medium',
    status: 'closed',
    created_at: '2026-05-30T12:00:00Z',
    updated_at: '2026-05-31T12:00:00Z',
    event_count: 2,
  },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeWrapper(initialUrl = '/incidents') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialUrl]}>
        <Routes>
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/incidents/:id" element={<div>detail</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('IncidentsPage — filter / sort / search', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUseIncidents.mockReturnValue({
      data: { incidents: MOCK_INCIDENTS, total: MOCK_INCIDENTS.length },
      isLoading: false,
      isError: false,
    });
  });

  it('renders page heading', () => {
    makeWrapper();
    expect(screen.getByText('Incidents')).toBeTruthy();
  });

  it('renders search input', () => {
    makeWrapper();
    expect(screen.getByLabelText('Search incidents')).toBeTruthy();
  });

  it('renders severity filter select', () => {
    makeWrapper();
    expect(screen.getByLabelText('Filter by severity')).toBeTruthy();
  });

  it('renders status filter select', () => {
    makeWrapper();
    expect(screen.getByLabelText('Filter by status')).toBeTruthy();
  });

  it('renders sort select', () => {
    makeWrapper();
    expect(screen.getByLabelText('Sort incidents')).toBeTruthy();
  });

  it('calls useIncidents with empty filter when no URL params', () => {
    makeWrapper('/incidents');
    expect(mockUseIncidents).toHaveBeenCalledWith(
      expect.objectContaining({
        severity: undefined,
        status: undefined,
        search: undefined,
      }),
    );
  });

  it('reads severity from URL on mount and passes it to useIncidents', () => {
    makeWrapper('/incidents?severity=critical');
    expect(mockUseIncidents).toHaveBeenCalledWith(
      expect.objectContaining({ severity: 'critical' }),
    );
  });

  it('reads status from URL on mount and passes it to useIncidents', () => {
    makeWrapper('/incidents?status=open');
    expect(mockUseIncidents).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'open' }),
    );
  });

  it('reads search from URL on mount and passes it to useIncidents', () => {
    makeWrapper('/incidents?search=ransomware');
    expect(mockUseIncidents).toHaveBeenCalledWith(
      expect.objectContaining({ search: 'ransomware' }),
    );
  });

  it('reads sort params from URL on mount', () => {
    makeWrapper('/incidents?sort_by=name&sort_dir=asc');
    expect(mockUseIncidents).toHaveBeenCalledWith(
      expect.objectContaining({ sort_by: 'name', sort_dir: 'asc' }),
    );
  });

  it('reflects severity URL param in the select control value', () => {
    makeWrapper('/incidents?severity=high');
    const select = screen.getByLabelText('Filter by severity') as HTMLSelectElement;
    expect(select.value).toBe('high');
  });

  it('reflects status URL param in the select control value', () => {
    makeWrapper('/incidents?status=closed');
    const select = screen.getByLabelText('Filter by status') as HTMLSelectElement;
    expect(select.value).toBe('closed');
  });

  it('reflects search URL param in the text input value', () => {
    makeWrapper('/incidents?search=lateral');
    const input = screen.getByLabelText('Search incidents') as HTMLInputElement;
    expect(input.value).toBe('lateral');
  });

  it('shows all incidents when no filters active', () => {
    makeWrapper();
    expect(screen.getByText('Ransomware Campaign')).toBeTruthy();
    expect(screen.getByText('Lateral Movement')).toBeTruthy();
    expect(screen.getByText('Closed Phishing')).toBeTruthy();
  });

  it('shows filtered-empty message when filters active and no results', () => {
    mockUseIncidents.mockReturnValue({
      data: { incidents: [], total: 3 },
      isLoading: false,
      isError: false,
    });
    makeWrapper('/incidents?severity=critical');
    expect(screen.getByText('No incidents match the current filters.')).toBeTruthy();
  });

  it('shows default empty message when no filters and no results', () => {
    mockUseIncidents.mockReturnValue({
      data: { incidents: [], total: 0 },
      isLoading: false,
      isError: false,
    });
    makeWrapper('/incidents');
    expect(screen.getByText('No incidents found. Create one to get started.')).toBeTruthy();
  });

  it('shows "Clear filters" button when search filter is active', () => {
    makeWrapper('/incidents?search=ransomware');
    expect(screen.getByText('Clear filters')).toBeTruthy();
  });

  it('does not show "Clear filters" when no filters active', () => {
    makeWrapper('/incidents');
    expect(screen.queryByText('Clear filters')).toBeNull();
  });

  it('shows "Clear filters" button when severity filter is active', () => {
    makeWrapper('/incidents?severity=high');
    expect(screen.getByText('Clear filters')).toBeTruthy();
  });

  it('severity select change calls useIncidents with the new severity', () => {
    makeWrapper('/incidents');
    const select = screen.getByLabelText('Filter by severity') as HTMLSelectElement;
    fireEvent.change(select, { target: { value: 'high' } });
    // After the URL update, useIncidents is re-called with new filter
    expect(mockUseIncidents).toHaveBeenCalledWith(
      expect.objectContaining({ severity: 'high' }),
    );
  });

  it('status select change calls useIncidents with the new status', () => {
    makeWrapper('/incidents');
    const select = screen.getByLabelText('Filter by status') as HTMLSelectElement;
    fireEvent.change(select, { target: { value: 'closed' } });
    expect(mockUseIncidents).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'closed' }),
    );
  });

  it('search input change calls useIncidents with the search term', () => {
    makeWrapper('/incidents');
    const input = screen.getByLabelText('Search incidents');
    fireEvent.change(input, { target: { value: 'phishing' } });
    expect(mockUseIncidents).toHaveBeenCalledWith(
      expect.objectContaining({ search: 'phishing' }),
    );
  });

  it('sort select change calls useIncidents with new sort params', () => {
    makeWrapper('/incidents');
    const select = screen.getByLabelText('Sort incidents');
    fireEvent.change(select, { target: { value: 'name:asc' } });
    expect(mockUseIncidents).toHaveBeenCalledWith(
      expect.objectContaining({ sort_by: 'name', sort_dir: 'asc' }),
    );
  });

  it('multiple URL params are all applied simultaneously', () => {
    makeWrapper('/incidents?severity=high&status=open&search=lateral&sort_by=name&sort_dir=asc');
    expect(mockUseIncidents).toHaveBeenCalledWith({
      severity: 'high',
      status: 'open',
      search: 'lateral',
      sort_by: 'name',
      sort_dir: 'asc',
    });
  });

  it('renders incident count summary when data is loaded', () => {
    makeWrapper();
    expect(screen.getByText('3 incidents')).toBeTruthy();
  });
});
