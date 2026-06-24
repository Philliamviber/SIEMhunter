import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

// ── Mock ReactECharts — jsdom has no canvas support ──────────────────────────
// Captures the onEvents click handler so tests can simulate node clicks.
let capturedClickHandler: ((params: { dataType?: string; name?: string }) => void) | undefined;
vi.mock('echarts-for-react', () => ({
  default: ({
    onEvents,
  }: {
    onEvents?: Record<string, (p: { dataType?: string; name?: string }) => void>;
  }) => {
    capturedClickHandler = onEvents?.click;
    return <div data-testid="echarts-graph" />;
  },
}));

// ── Mock the api client so no real HTTP calls are made ───────────────────────
const mockQuery = vi.fn();
vi.mock('../../api/client', () => ({
  api: { query: (...args: unknown[]) => mockQuery(...args) },
  ApiClientError: class ApiClientError extends Error {
    status: number;
    code: string;
    constructor(status: number, code: string, message: string) {
      super(message);
      this.status = status;
      this.code = code;
    }
  },
}));

// ── Mock EventDetailPanel to keep tests focused on CorrelationPage logic ─────
vi.mock('../../components/EventDetailPanel', () => ({
  EventDetailPanel: ({ onClose }: { onClose: () => void }) => (
    <div data-testid="event-detail-panel">
      <button onClick={onClose}>close detail</button>
    </div>
  ),
}));

import { CorrelationPage } from '../CorrelationPage';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
}

function renderCorrelation() {
  return render(
    <QueryClientProvider client={makeQueryClient()}>
      <MemoryRouter>
        <CorrelationPage />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

// Build a mock API query result for the relationship rows query
// (the second api.query call in runQueries)
function makeRelResult(rows: Record<string, unknown>[] = []) {
  return { rows, row_count: rows.length, truncated: false, execution_time_ms: 5 };
}

// One typical event row (entity query result shape is the same)
function makeRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    TimeGenerated: '2026-06-20T14:00:00.000Z',
    HostName: 'dc01',
    SubjectUserName: 'jdoe',
    SrcIpAddr: '10.0.0.1',
    DstIpAddr: '10.0.0.2',
    ProcessImagePath: 'C:\\Windows\\explorer.exe',
    EventID: 4624,
    EventRecordID: 'rec-001',
    ChannelName: 'Security',
    ProviderName: 'Microsoft-Windows-Security-Auditing',
    SubjectUserSid: '',
    SubjectDomainName: 'CORP',
    TargetUserName: '',
    TargetUserSid: '',
    TargetDomainName: '',
    LogonType: 3,
    ServiceName: '',
    CommandLine: '',
    ParentProcessImagePath: '',
    ParentCommandLine: '',
    GrantedAccess: '',
    ObjectName: '',
    FileMD5: '',
    FileSHA256: '',
    RegistryKey: '',
    SrcPort: 0,
    DstPort: 445,
    NetworkProtocol: 'TCP',
    ProvenanceTag: 'wef:test',
    IngestTimestamp: '2026-06-20T14:00:05.000Z',
    UnmappedFields: '',
    ...overrides,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('CorrelationPage', () => {
  beforeEach(() => {
    mockQuery.mockReset();
    capturedClickHandler = undefined;
  });

  describe('initial render (before first load)', () => {
    it('shows the "Load Graph" prompt before the first query is executed', () => {
      renderCorrelation();
      expect(
        screen.getByText(/Select a time range and click Load Graph/i)
      ).toBeTruthy();
    });

    it('renders the "Load Graph" button', () => {
      renderCorrelation();
      expect(screen.getByRole('button', { name: /load graph/i })).toBeTruthy();
    });

    it('does not show the ECharts graph before the first load', () => {
      renderCorrelation();
      expect(screen.queryByTestId('echarts-graph')).toBeNull();
    });

    it('does not show the node-cap warning before load', () => {
      renderCorrelation();
      expect(screen.queryByText(/graph too large/i)).toBeNull();
    });

    it('does not show search or zoom controls before load', () => {
      renderCorrelation();
      expect(screen.queryByRole('searchbox', { name: /search graph nodes/i })).toBeNull();
      expect(screen.queryByRole('button', { name: /zoom in/i })).toBeNull();
      expect(screen.queryByRole('button', { name: /reset view/i })).toBeNull();
    });
  });

  describe('empty result after load', () => {
    it('shows "No entity data" message when rows are empty', async () => {
      // Both queries return empty rows
      mockQuery.mockResolvedValue(makeRelResult([]));
      renderCorrelation();

      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));

      await waitFor(() => {
        expect(
          screen.getByText(/No entity data in the selected time window/i)
        ).toBeTruthy();
      });
    });

    it('does not render the ECharts graph when rows are empty', async () => {
      mockQuery.mockResolvedValue(makeRelResult([]));
      renderCorrelation();
      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));
      await waitFor(() =>
        expect(screen.queryByTestId('echarts-graph')).toBeNull()
      );
    });

    it('does not show search or zoom controls when no nodes exist', async () => {
      mockQuery.mockResolvedValue(makeRelResult([]));
      renderCorrelation();
      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));
      await waitFor(() => {
        expect(screen.queryByRole('searchbox', { name: /search graph nodes/i })).toBeNull();
        expect(screen.queryByRole('button', { name: /zoom in/i })).toBeNull();
      });
    });
  });

  describe('node-cap warning', () => {
    it('shows the node-cap warning when node count exceeds 200', async () => {
      // Generate > 200 unique hosts to exceed NODE_CAP
      const rows = Array.from({ length: 210 }, (_, i) => makeRow({ HostName: `host-${i}`, SubjectUserName: '' }));
      // Both api.query calls return the same rows (entity + relationship)
      mockQuery.mockResolvedValue(makeRelResult(rows));
      renderCorrelation();

      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));

      await waitFor(() => {
        expect(screen.getByText(/graph too large/i)).toBeTruthy();
        expect(screen.getByText(/200 nodes/i)).toBeTruthy();
      });
    });

    it('does not show node-cap warning when node count is below 200', async () => {
      const rows = Array.from({ length: 5 }, (_, i) => makeRow({ HostName: `host-${i}`, SubjectUserName: '' }));
      mockQuery.mockResolvedValue(makeRelResult(rows));
      renderCorrelation();

      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));

      await waitFor(() => {
        expect(screen.queryByText(/graph too large/i)).toBeNull();
      });
    });
  });

  describe('successful load with data', () => {
    it('renders the ECharts graph when rows are returned', async () => {
      mockQuery.mockResolvedValue(makeRelResult([makeRow()]));
      renderCorrelation();

      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));

      await waitFor(() => {
        expect(screen.getByTestId('echarts-graph')).toBeTruthy();
      });
    });

    it('hides the "Load Graph" button after first load', async () => {
      mockQuery.mockResolvedValue(makeRelResult([makeRow()]));
      renderCorrelation();

      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));

      await waitFor(() => {
        // Once hasLoaded=true, the load button disappears
        expect(screen.queryByRole('button', { name: /load graph/i })).toBeNull();
      });
    });
  });

  describe('time preset controls', () => {
    it('renders all four time-range preset buttons', () => {
      renderCorrelation();
      expect(screen.getByRole('button', { name: /last 1h/i })).toBeTruthy();
      expect(screen.getByRole('button', { name: /last 6h/i })).toBeTruthy();
      expect(screen.getByRole('button', { name: /last 24h/i })).toBeTruthy();
      expect(screen.getByRole('button', { name: /last 7d/i })).toBeTruthy();
    });

    it('triggers a query when a preset button is clicked', async () => {
      mockQuery.mockResolvedValue(makeRelResult([]));
      renderCorrelation();

      await userEvent.click(screen.getByRole('button', { name: /last 1h/i }));

      await waitFor(() => {
        // Two api.query calls (entity + relationship) for the preset click
        expect(mockQuery).toHaveBeenCalled();
      });
    });
  });

  describe('error handling', () => {
    it('shows error text when the API call fails', async () => {
      const { ApiClientError } = await import('../../api/client');
      mockQuery.mockRejectedValue(new ApiClientError(500, 'QUERY_ERROR', 'ClickHouse offline'));
      renderCorrelation();

      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));

      await waitFor(() => {
        expect(screen.getByText(/QUERY_ERROR/)).toBeTruthy();
      });
    });

    it('shows a generic error for non-ApiClientError rejections', async () => {
      mockQuery.mockRejectedValue(new Error('Network failure'));
      renderCorrelation();

      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));

      await waitFor(() => {
        expect(screen.getByText(/Unexpected error/i)).toBeTruthy();
      });
    });
  });

  // ── FR #13: search and zoom/reset controls ────────────────────────────────

  describe('FR #13 — search input', () => {
    it('shows the search input after a load with data', async () => {
      mockQuery.mockResolvedValue(makeRelResult([makeRow()]));
      renderCorrelation();
      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));

      await waitFor(() => {
        expect(screen.getByRole('searchbox', { name: /search graph nodes/i })).toBeTruthy();
      });
    });

    it('accepts text in the search input', async () => {
      mockQuery.mockResolvedValue(makeRelResult([makeRow()]));
      renderCorrelation();
      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));

      await waitFor(() => screen.getByRole('searchbox', { name: /search graph nodes/i }));

      const searchInput = screen.getByRole('searchbox', { name: /search graph nodes/i });
      await userEvent.type(searchInput, 'dc01');
      expect((searchInput as HTMLInputElement).value).toBe('dc01');
    });

    it('shows a clear button when search term is entered', async () => {
      mockQuery.mockResolvedValue(makeRelResult([makeRow()]));
      renderCorrelation();
      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));

      await waitFor(() => screen.getByRole('searchbox', { name: /search graph nodes/i }));

      const searchInput = screen.getByRole('searchbox', { name: /search graph nodes/i });
      await userEvent.type(searchInput, 'dc01');

      expect(screen.getByRole('button', { name: /clear search/i })).toBeTruthy();
    });

    it('clears the search term when the clear button is clicked', async () => {
      mockQuery.mockResolvedValue(makeRelResult([makeRow()]));
      renderCorrelation();
      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));

      await waitFor(() => screen.getByRole('searchbox', { name: /search graph nodes/i }));

      const searchInput = screen.getByRole('searchbox', { name: /search graph nodes/i });
      await userEvent.type(searchInput, 'dc01');
      await userEvent.click(screen.getByRole('button', { name: /clear search/i }));

      expect((searchInput as HTMLInputElement).value).toBe('');
    });

    it('clears the search term when a new time range is loaded', async () => {
      mockQuery.mockResolvedValue(makeRelResult([makeRow()]));
      renderCorrelation();
      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));

      await waitFor(() => screen.getByRole('searchbox', { name: /search graph nodes/i }));

      const searchInput = screen.getByRole('searchbox', { name: /search graph nodes/i });
      await userEvent.type(searchInput, 'something');

      // Trigger a new preset (clears search)
      mockQuery.mockResolvedValue(makeRelResult([makeRow()]));
      await userEvent.click(screen.getByRole('button', { name: /last 1h/i }));

      await waitFor(() => {
        expect((searchInput as HTMLInputElement).value).toBe('');
      });
    });
  });

  describe('FR #13 — zoom and reset controls', () => {
    it('shows zoom-in, zoom-out, and reset buttons after a load with data', async () => {
      mockQuery.mockResolvedValue(makeRelResult([makeRow()]));
      renderCorrelation();
      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /zoom in/i })).toBeTruthy();
        expect(screen.getByRole('button', { name: /zoom out/i })).toBeTruthy();
        expect(screen.getByRole('button', { name: /reset view/i })).toBeTruthy();
      });
    });

    it('zoom and reset buttons are clickable without throwing', async () => {
      mockQuery.mockResolvedValue(makeRelResult([makeRow()]));
      renderCorrelation();
      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));

      await waitFor(() => screen.getByRole('button', { name: /zoom in/i }));

      // In jsdom, chartRef.current.getEchartsInstance() returns undefined (mocked component).
      // Buttons must handle that gracefully via optional chaining.
      await userEvent.click(screen.getByRole('button', { name: /zoom in/i }));
      await userEvent.click(screen.getByRole('button', { name: /zoom out/i }));
      await userEvent.click(screen.getByRole('button', { name: /reset view/i }));

      // Reset also clears the search term
      const searchInput = screen.getByRole('searchbox', { name: /search graph nodes/i });
      expect((searchInput as HTMLInputElement).value).toBe('');
    });
  });

  // ── FR #14: entity / event panel stacking ────────────────────────────────

  describe('FR #14 — entity panel and event detail panel stacking', () => {
    async function loadGraphAndClickNode() {
      mockQuery.mockResolvedValue(makeRelResult([makeRow()]));
      renderCorrelation();
      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));
      await waitFor(() => screen.getByTestId('echarts-graph'));

      // Simulate a node click via the captured ECharts event handler
      act(() => {
        capturedClickHandler?.({ dataType: 'node', name: 'dc01' });
      });

      await waitFor(() => screen.getByText('Entity Events'));
    }

    it('shows the entity panel when a graph node is clicked', async () => {
      await loadGraphAndClickNode();
      expect(screen.getByText('Entity Events')).toBeTruthy();
      // The entity name appears in the panel header — use getAllByText since it also appears in the table
      expect(screen.getAllByText('dc01').length).toBeGreaterThan(0);
    });

    it('entity panel stays visible when an event row is clicked (stacking)', async () => {
      await loadGraphAndClickNode();

      // Click an event row in the entity panel — EventDetailPanel opens
      const rows = screen.getAllByRole('row');
      // Skip header row, click first data row
      const dataRows = rows.filter(r => r.querySelector('td'));
      expect(dataRows.length).toBeGreaterThan(0);
      await userEvent.click(dataRows[0]);

      await waitFor(() => screen.getByTestId('event-detail-panel'));

      // Entity panel must still be mounted
      expect(screen.getByText('Entity Events')).toBeTruthy();
      expect(screen.getByTestId('event-detail-panel')).toBeTruthy();
    });

    it('closing the event detail panel returns to entity panel', async () => {
      await loadGraphAndClickNode();

      // Open event detail panel
      const rows = screen.getAllByRole('row');
      const dataRows = rows.filter(r => r.querySelector('td'));
      await userEvent.click(dataRows[0]);
      await waitFor(() => screen.getByTestId('event-detail-panel'));

      // Close event detail panel
      await userEvent.click(screen.getByRole('button', { name: /close detail/i }));

      await waitFor(() => {
        expect(screen.queryByTestId('event-detail-panel')).toBeNull();
        // Entity panel should still be present
        expect(screen.getByText('Entity Events')).toBeTruthy();
      });
    });

    it('closing the entity panel closes both panels', async () => {
      await loadGraphAndClickNode();

      // Open event detail too
      const rows = screen.getAllByRole('row');
      const dataRows = rows.filter(r => r.querySelector('td'));
      await userEvent.click(dataRows[0]);
      await waitFor(() => screen.getByTestId('event-detail-panel'));

      // Close entity panel via its X button
      await userEvent.click(screen.getByRole('button', { name: /close entity panel/i }));

      await waitFor(() => {
        expect(screen.queryByText('Entity Events')).toBeNull();
        expect(screen.queryByTestId('event-detail-panel')).toBeNull();
      });
    });

    it('does not show entity panel or event detail panel before a node is clicked', async () => {
      mockQuery.mockResolvedValue(makeRelResult([makeRow()]));
      renderCorrelation();
      await userEvent.click(screen.getByRole('button', { name: /load graph/i }));
      await waitFor(() => screen.getByTestId('echarts-graph'));

      expect(screen.queryByText('Entity Events')).toBeNull();
      expect(screen.queryByTestId('event-detail-panel')).toBeNull();
    });

    it('query reload clears both panels', async () => {
      await loadGraphAndClickNode();
      // Verify entity panel is open
      expect(screen.getByText('Entity Events')).toBeTruthy();

      // Trigger a new load (preset click)
      mockQuery.mockResolvedValue(makeRelResult([makeRow({ HostName: 'other' })]));
      await userEvent.click(screen.getByRole('button', { name: /last 1h/i }));

      await waitFor(() => {
        expect(screen.queryByText('Entity Events')).toBeNull();
      });
    });
  });
});
