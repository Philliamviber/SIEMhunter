/**
 * CategoryDashboardPage tests — FR #21
 * Covers:
 *   - Truncation banner ("showing X of N") when DRILL_LIMIT rows are returned
 *   - Refine in Query Builder CTA navigates to /query with SQL pre-filled
 *   - Load More CTA appends next page of results
 *   - Distinct empty state when no events match
 *   - Distinct error state with retry when the API fails
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

// ── Mock the api client ───────────────────────────────────────────────────────
const mockQuery = vi.fn();
vi.mock('../../api/client', () => ({
  api: { query: (...args: unknown[]) => mockQuery(...args) },
}));

// ── Mock EventDetailPanel ─────────────────────────────────────────────────────
vi.mock('../../components/EventDetailPanel', () => ({
  EventDetailPanel: ({ onClose }: { onClose: () => void }) => (
    <div data-testid="event-detail-panel">
      <button onClick={onClose}>close detail</button>
    </div>
  ),
}));

import { CategoryDashboardPage } from '../CategoryDashboardPage';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeQueryClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
}

// Renders CategoryDashboardPage inside a router that also has a /query stub
// so navigation assertions work.
let navigatedTo = '';
function renderPage() {
  navigatedTo = '';
  return render(
    <QueryClientProvider client={makeQueryClient()}>
      <MemoryRouter initialEntries={['/categories']}>
        <Routes>
          <Route path="/categories" element={<CategoryDashboardPage />} />
          <Route
            path="/query"
            element={
              <div
                data-testid="query-page-stub"
                data-url={window.location.href}
              />
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Build a mock API result with `count` rows. */
function makeRows(count: number, idOffset = 0): Record<string, unknown>[] {
  return Array.from({ length: count }, (_, i) => ({
    // Unique timestamp per row (millis offset) to avoid duplicate React keys
    TimeGenerated: `2026-06-20T00:00:${String((i + idOffset) % 60).padStart(2, '0')}.${String(i + idOffset).padStart(3, '0')}Z`,
    HostName: `host-${i + idOffset}`,
    EventID: 4624,
    EventRecordID: `rec-${i + idOffset}`,
    ChannelName: 'Security',
    SubjectUserName: 'jdoe',
    SrcIpAddr: '10.0.0.1',
    DstIpAddr: '10.0.0.2',
    CommandLine: '',
    ProvenanceTag: 'test',
    UnmappedFields: '',
    IngestTimestamp: `2026-06-20T${String(i % 24).padStart(2, '0')}:00:05.000Z`,
    ProviderName: '',
    SubjectUserSid: '',
    SubjectDomainName: '',
    TargetUserName: '',
    TargetUserSid: '',
    TargetDomainName: '',
    LogonType: 3,
    ServiceName: '',
    ProcessImagePath: '',
    ParentProcessImagePath: '',
    ParentCommandLine: '',
    GrantedAccess: '',
    ObjectName: '',
    FileMD5: '',
    FileSHA256: '',
    RegistryKey: '',
    SrcPort: 0,
    DstPort: 0,
    NetworkProtocol: '',
  }));
}

function makeQueryResult(rows: Record<string, unknown>[]) {
  return { rows, row_count: rows.length, truncated: false, execution_time_ms: 5 };
}

function makeCountResult(count: number) {
  return { rows: [{ cnt: count }], row_count: 1, truncated: false, execution_time_ms: 1 };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('CategoryDashboardPage', () => {
  beforeEach(() => {
    mockQuery.mockReset();
    navigatedTo = '';
  });

  describe('initial render', () => {
    it('renders the page heading', () => {
      // Counts return 0 for all categories so no drill-down starts
      mockQuery.mockResolvedValue(makeCountResult(0));
      renderPage();
      expect(screen.getByText('Category Dashboard')).toBeTruthy();
    });

    it('renders all six category cards', () => {
      mockQuery.mockResolvedValue(makeCountResult(0));
      renderPage();
      expect(screen.getByText('Active Directory')).toBeTruthy();
      expect(screen.getByText('Network')).toBeTruthy();
      expect(screen.getByText('DNS')).toBeTruthy();
      expect(screen.getByText('Network Analysis')).toBeTruthy();
      expect(screen.getByText('Malware Analysis')).toBeTruthy();
      expect(screen.getByText('Log Analysis')).toBeTruthy();
    });

    it('does not show a drill-down section before a card is clicked', () => {
      mockQuery.mockResolvedValue(makeCountResult(0));
      renderPage();
      expect(screen.queryByText(/Events$/)).toBeNull();
    });
  });

  describe('empty state', () => {
    it('shows the distinct empty state when no events match', async () => {
      // Count queries return some total; drill-down returns 0 rows
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(5));
        return Promise.resolve(makeQueryResult([]));
      });

      renderPage();

      // Click the Active Directory card
      await userEvent.click(screen.getByText('Active Directory'));

      await waitFor(() => {
        expect(screen.getByTestId('drill-empty-state')).toBeTruthy();
      });
    });

    it('shows "No events found" text in the empty state', async () => {
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(0));
        return Promise.resolve(makeQueryResult([]));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));

      await waitFor(() => {
        expect(screen.getByText('No events found')).toBeTruthy();
      });
    });

    it('does NOT show the truncation banner in the empty state', async () => {
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(0));
        return Promise.resolve(makeQueryResult([]));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));

      await waitFor(() => screen.getByTestId('drill-empty-state'));
      expect(screen.queryByTestId('truncation-banner')).toBeNull();
    });
  });

  describe('error state', () => {
    it('shows the distinct error state when the API call fails', async () => {
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(100));
        return Promise.reject(new Error('Network failure'));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));

      await waitFor(() => {
        expect(screen.getByTestId('drill-error-state')).toBeTruthy();
      });
    });

    it('shows "Failed to load events" text in the error state', async () => {
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(100));
        return Promise.reject(new Error('Network failure'));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));

      await waitFor(() => {
        expect(screen.getByText('Failed to load events')).toBeTruthy();
      });
    });

    it('has role="alert" on the error state element', async () => {
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(100));
        return Promise.reject(new Error('Network failure'));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));

      await waitFor(() => {
        const el = screen.getByTestId('drill-error-state');
        expect(el.getAttribute('role')).toBe('alert');
      });
    });

    it('shows a Retry button in the error state', async () => {
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(100));
        return Promise.reject(new Error('Network failure'));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));

      await waitFor(() => screen.getByTestId('drill-error-state'));
      expect(screen.getByRole('button', { name: /retry/i })).toBeTruthy();
    });

    it('retries the query when the Retry button is clicked', async () => {
      let callCount = 0;
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(100));
        callCount++;
        if (callCount === 1) return Promise.reject(new Error('Network failure'));
        return Promise.resolve(makeQueryResult(makeRows(5)));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));
      await waitFor(() => screen.getByTestId('drill-error-state'));

      await userEvent.click(screen.getByRole('button', { name: /retry/i }));

      await waitFor(() => {
        expect(screen.queryByTestId('drill-error-state')).toBeNull();
      });
    });

    it('does NOT show the truncation banner in the error state', async () => {
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(100));
        return Promise.reject(new Error('Network failure'));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));

      await waitFor(() => screen.getByTestId('drill-error-state'));
      expect(screen.queryByTestId('truncation-banner')).toBeNull();
    });
  });

  describe('truncation banner', () => {
    it('shows the truncation banner when exactly 500 rows are returned', async () => {
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(1200));
        return Promise.resolve(makeQueryResult(makeRows(500)));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));

      await waitFor(() => {
        expect(screen.getByTestId('truncation-banner')).toBeTruthy();
      });
    });

    it('shows "Showing 500" in the banner when 500 rows are returned', async () => {
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(1200));
        return Promise.resolve(makeQueryResult(makeRows(500)));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));

      await waitFor(() => {
        const banner = screen.getByTestId('truncation-banner');
        expect(banner.textContent).toMatch(/Showing.*500/);
      });
    });

    it('shows "of 1,200" in the banner when the total count is known', async () => {
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(1200));
        return Promise.resolve(makeQueryResult(makeRows(500)));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));

      await waitFor(() => {
        const banner = screen.getByTestId('truncation-banner');
        expect(banner.textContent).toMatch(/of.*1,200/);
      });
    });

    it('does NOT show the truncation banner when fewer than 500 rows are returned', async () => {
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(42));
        return Promise.resolve(makeQueryResult(makeRows(42)));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));

      await waitFor(() => screen.getByTestId('drill-row-count'));
      expect(screen.queryByTestId('truncation-banner')).toBeNull();
    });

    it('shows a "Refine in Query Builder" button in the banner', async () => {
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(1200));
        return Promise.resolve(makeQueryResult(makeRows(500)));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));

      await waitFor(() => screen.getByTestId('truncation-banner'));
      expect(screen.getByRole('button', { name: /refine in query builder/i })).toBeTruthy();
    });

    it('shows a "Load More" button in the banner', async () => {
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(1200));
        return Promise.resolve(makeQueryResult(makeRows(500)));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));

      await waitFor(() => screen.getByTestId('truncation-banner'));
      expect(screen.getByRole('button', { name: /load more events/i })).toBeTruthy();
    });
  });

  describe('load more', () => {
    it('appends rows when Load More is clicked', async () => {
      let drillCallCount = 0;
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(1200));
        drillCallCount++;
        if (drillCallCount === 1) {
          // First fetch: 500 rows (ids 0–499)
          return Promise.resolve(makeQueryResult(makeRows(500, 0)));
        }
        // Load more: 200 rows (ids 500–699 — unique keys after append)
        return Promise.resolve(makeQueryResult(makeRows(200, 500)));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));

      await waitFor(() => screen.getByTestId('truncation-banner'));
      expect(screen.getByTestId('drill-row-count').textContent).toMatch(/500/);

      await userEvent.click(screen.getByRole('button', { name: /load more events/i }));

      await waitFor(() => {
        // 500 + 200 = 700 rows shown
        expect(screen.getByTestId('drill-row-count').textContent).toMatch(/700/);
      });
    });

    it('hides the truncation banner after the last page is loaded', async () => {
      let drillCallCount = 0;
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(600));
        drillCallCount++;
        if (drillCallCount === 1) return Promise.resolve(makeQueryResult(makeRows(500, 0)));
        // Second fetch: only 100 rows — signals no more pages (ids 500–599)
        return Promise.resolve(makeQueryResult(makeRows(100, 500)));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));

      await waitFor(() => screen.getByTestId('truncation-banner'));
      await userEvent.click(screen.getByRole('button', { name: /load more events/i }));

      await waitFor(() => {
        expect(screen.queryByTestId('truncation-banner')).toBeNull();
      });
    });

    it('sends an OFFSET in the load-more SQL', async () => {
      const sqlArgs: string[] = [];
      let drillCall = 0;
      mockQuery.mockImplementation((args: { sql: string }) => {
        sqlArgs.push(args.sql);
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(1200));
        drillCall++;
        return Promise.resolve(makeQueryResult(makeRows(500, (drillCall - 1) * 500)));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));
      await waitFor(() => screen.getByTestId('truncation-banner'));

      await userEvent.click(screen.getByRole('button', { name: /load more events/i }));

      await waitFor(() => {
        const drillSqls = sqlArgs.filter((s) => !s.includes('COUNT(*)'));
        // Second drill SQL must include OFFSET
        expect(drillSqls.length).toBeGreaterThanOrEqual(2);
        expect(drillSqls[1]).toMatch(/OFFSET\s+500/i);
      });
    });
  });

  describe('refine in query builder', () => {
    it('navigates to /query when Refine is clicked', async () => {
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(1200));
        return Promise.resolve(makeQueryResult(makeRows(500)));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));
      await waitFor(() => screen.getByTestId('truncation-banner'));

      await userEvent.click(screen.getByRole('button', { name: /refine in query builder/i }));

      // After navigation the query-page stub should appear
      await waitFor(() => {
        expect(screen.getByTestId('query-page-stub')).toBeTruthy();
      });
    });
  });

  describe('card toggle', () => {
    it('collapses the drill-down when the selected card is clicked again', async () => {
      mockQuery.mockImplementation((args: { sql: string }) => {
        if (args.sql.includes('COUNT(*)')) return Promise.resolve(makeCountResult(5));
        return Promise.resolve(makeQueryResult(makeRows(5)));
      });

      renderPage();
      await userEvent.click(screen.getByText('Active Directory'));
      await waitFor(() => screen.getByText('Active Directory Events'));

      // Click the same card again to collapse
      await userEvent.click(screen.getByText('Active Directory'));
      await waitFor(() => {
        expect(screen.queryByText('Active Directory Events')).toBeNull();
      });
    });
  });
});
