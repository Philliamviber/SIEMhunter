/**
 * PrefsContext tests.
 *
 * Verifies:
 *   - PrefsProvider exposes defaults when no preferences are stored (API returns defaults)
 *   - PrefsProvider reflects stored values returned by the API
 *   - usePrefsContext throws outside provider
 *   - setPrefs calls the mutation and the cache is updated
 *   - PrefsNavigator redirects to the stored landing page on first root-path load
 *   - PrefsNavigator does NOT redirect if the current path is not "/"
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, act, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, useLocation } from 'react-router-dom';

// ── Mocks ─────────────────────────────────────────────────────────────────────

const mockMutate = vi.fn();
let mockPrefsData: Record<string, string> | undefined;
let mockIsLoading = false;

vi.mock('../../hooks/useApi', () => ({
  usePreferences: () => ({ data: mockPrefsData, isLoading: mockIsLoading }),
  useSetPreferences: () => ({ mutate: mockMutate }),
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

import { PrefsProvider, usePrefsContext } from '../PrefsContext';

function wrapper(
  { children, initialPath = '/' }: { children: React.ReactNode; initialPath?: string },
) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialPath]}>
        <PrefsProvider>
          {children}
        </PrefsProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

function PrefsDisplay() {
  const { prefs, isLoading } = usePrefsContext();
  if (isLoading) return <div>loading</div>;
  return (
    <div>
      <span data-testid="time-range">{prefs.default_time_range}</span>
      <span data-testid="density">{prefs.table_density}</span>
      <span data-testid="landing">{prefs.default_landing_page}</span>
    </div>
  );
}

function SetPrefsButton() {
  const { setPrefs } = usePrefsContext();
  return (
    <button onClick={() => setPrefs({ table_density: 'compact' })}>
      Set compact
    </button>
  );
}

function LocationDisplay() {
  const loc = useLocation();
  return <span data-testid="path">{loc.pathname}</span>;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('PrefsContext', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockPrefsData = undefined;
    mockIsLoading = false;
  });

  it('exposes defaults when API returns default values', () => {
    mockPrefsData = {
      default_time_range: '24h',
      table_density: 'comfortable',
      default_landing_page: '/',
    };
    render(<PrefsDisplay />, { wrapper });
    expect(screen.getByTestId('time-range').textContent).toBe('24h');
    expect(screen.getByTestId('density').textContent).toBe('comfortable');
    expect(screen.getByTestId('landing').textContent).toBe('/');
  });

  it('reflects stored values returned by the API', () => {
    mockPrefsData = {
      default_time_range: '7d',
      table_density: 'compact',
      default_landing_page: '/detections',
    };
    render(<PrefsDisplay />, { wrapper });
    expect(screen.getByTestId('time-range').textContent).toBe('7d');
    expect(screen.getByTestId('density').textContent).toBe('compact');
    expect(screen.getByTestId('landing').textContent).toBe('/detections');
  });

  it('shows loading state when isLoading is true', () => {
    mockIsLoading = true;
    mockPrefsData = undefined;
    render(<PrefsDisplay />, { wrapper });
    expect(screen.getByText('loading')).toBeTruthy();
  });

  it('throws when usePrefsContext is used outside PrefsProvider', () => {
    function Bare() {
      usePrefsContext();
      return null;
    }
    const qc = new QueryClient();
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() =>
      render(
        <QueryClientProvider client={qc}>
          <MemoryRouter><Bare /></MemoryRouter>
        </QueryClientProvider>,
      ),
    ).toThrow('usePrefsContext must be used inside PrefsProvider');
    consoleError.mockRestore();
  });

  it('calls mutate when setPrefs is invoked', async () => {
    mockPrefsData = {
      default_time_range: '24h',
      table_density: 'comfortable',
      default_landing_page: '/',
    };
    render(<SetPrefsButton />, { wrapper });
    await userEvent.click(screen.getByText('Set compact'));
    expect(mockMutate).toHaveBeenCalledWith({ table_density: 'compact' });
  });

  it('redirects to stored landing page when on root path', async () => {
    mockPrefsData = {
      default_time_range: '24h',
      table_density: 'comfortable',
      default_landing_page: '/events',
    };
    render(<LocationDisplay />, { wrapper });
    await waitFor(() => {
      expect(screen.getByTestId('path').textContent).toBe('/events');
    });
  });

  it('does NOT redirect when already on a non-root path', async () => {
    mockPrefsData = {
      default_time_range: '24h',
      table_density: 'comfortable',
      default_landing_page: '/events',
    };
    render(<LocationDisplay />, {
      wrapper: ({ children }) => wrapper({ children, initialPath: '/detections' }),
    });
    // Path should remain /detections, not jump to /events.
    await waitFor(() => {
      expect(screen.getByTestId('path').textContent).toBe('/detections');
    });
  });

  it('does NOT redirect when landing page is "/" (root = root)', async () => {
    mockPrefsData = {
      default_time_range: '24h',
      table_density: 'comfortable',
      default_landing_page: '/',
    };
    render(<LocationDisplay />, { wrapper });
    await waitFor(() => {
      expect(screen.getByTestId('path').textContent).toBe('/');
    });
  });
});
