/**
 * CommandPalette tests.
 *
 * Covers:
 *   - Renders nothing when closed
 *   - Renders search input when open
 *   - Fuzzy-filters items by query
 *   - ArrowDown / ArrowUp navigate the active item
 *   - Enter selects the active item and calls navigate
 *   - Escape closes the palette
 *   - Clicking an item selects it
 *   - Saved views from useSavedViews appear in results
 *   - No results message shown when filter matches nothing
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { SavedView } from '../../types/api';

// ── Mocks ─────────────────────────────────────────────────────────────────────

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => mockNavigate };
});

let mockViews: SavedView[] = [];
vi.mock('../../hooks/useApi', () => ({
  useSavedViews: () => ({ data: { views: mockViews } }),
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

import { CommandPalette } from '../CommandPalette';

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

const onClose = vi.fn();

function renderOpen(query?: { open?: boolean }) {
  return render(
    <CommandPalette open={query?.open ?? true} onClose={onClose} />,
    { wrapper },
  );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('CommandPalette', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockViews = [];
  });

  it('renders nothing when closed', () => {
    renderOpen({ open: false });
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('renders the dialog and search input when open', () => {
    renderOpen();
    expect(screen.getByRole('dialog')).toBeTruthy();
    expect(screen.getByLabelText('Command palette search')).toBeTruthy();
  });

  it('shows page destinations by default', () => {
    renderOpen();
    expect(screen.getByText('Overview')).toBeTruthy();
    expect(screen.getByText('Events')).toBeTruthy();
    expect(screen.getByText('Detections')).toBeTruthy();
  });

  it('shows quick actions', () => {
    renderOpen();
    expect(screen.getByText('Create Incident')).toBeTruthy();
    expect(screen.getByText('Export Current View')).toBeTruthy();
  });

  it('filters items by query', async () => {
    const user = userEvent.setup();
    renderOpen();
    await user.type(screen.getByLabelText('Command palette search'), 'det');
    expect(screen.getByText('Detections')).toBeTruthy();
    expect(screen.queryByText('Overview')).toBeNull();
  });

  it('shows "No results" when filter matches nothing', async () => {
    const user = userEvent.setup();
    renderOpen();
    await user.type(screen.getByLabelText('Command palette search'), 'zzz');
    expect(screen.getByText('No results')).toBeTruthy();
  });

  it('navigates to page on Enter', () => {
    renderOpen();
    // first item is Overview (index 0)
    const input = screen.getByLabelText('Command palette search');
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(mockNavigate).toHaveBeenCalledWith('/');
    expect(onClose).toHaveBeenCalled();
  });

  it('moves selection down with ArrowDown', () => {
    renderOpen();
    const input = screen.getByLabelText('Command palette search');
    const items = screen.getAllByRole('option');
    expect(items[0].getAttribute('aria-selected')).toBe('true');

    fireEvent.keyDown(input, { key: 'ArrowDown' });
    const updatedItems = screen.getAllByRole('option');
    expect(updatedItems[0].getAttribute('aria-selected')).toBe('false');
    expect(updatedItems[1].getAttribute('aria-selected')).toBe('true');
  });

  it('moves selection up with ArrowUp after ArrowDown', () => {
    renderOpen();
    const input = screen.getByLabelText('Command palette search');
    fireEvent.keyDown(input, { key: 'ArrowDown' });
    fireEvent.keyDown(input, { key: 'ArrowUp' });
    const items = screen.getAllByRole('option');
    expect(items[0].getAttribute('aria-selected')).toBe('true');
  });

  it('calls onClose on Escape', () => {
    renderOpen();
    const input = screen.getByLabelText('Command palette search');
    fireEvent.keyDown(input, { key: 'Escape' });
    expect(onClose).toHaveBeenCalled();
  });

  it('calls onClose when backdrop is clicked', async () => {
    const user = userEvent.setup();
    renderOpen();
    await user.click(screen.getByTestId('palette-backdrop'));
    expect(onClose).toHaveBeenCalled();
  });

  it('navigates when item is clicked', async () => {
    const user = userEvent.setup();
    renderOpen();
    await user.click(screen.getByText('Incidents'));
    expect(mockNavigate).toHaveBeenCalledWith('/incidents');
    expect(onClose).toHaveBeenCalled();
  });

  it('shows saved views from useSavedViews', () => {
    mockViews = [
      { name: 'High severity', page: 'detections', filters: { severity: 'high' } },
      { name: 'My query', page: 'query', filters: { sql: 'SELECT 1' } },
    ];
    renderOpen();
    expect(screen.getByText('High severity')).toBeTruthy();
    expect(screen.getByText('My query')).toBeTruthy();
  });

  it('navigates to the correct page when a saved view is selected', async () => {
    mockViews = [{ name: 'Crit view', page: 'detections', filters: {} }];
    const user = userEvent.setup();
    renderOpen();
    await user.click(screen.getByText('Crit view'));
    expect(mockNavigate).toHaveBeenCalledWith('/detections');
    expect(onClose).toHaveBeenCalled();
  });

  it('ArrowDown does not go past the last item', () => {
    renderOpen();
    const input = screen.getByLabelText('Command palette search');
    const items = screen.getAllByRole('option');
    // Press ArrowDown many times
    for (let i = 0; i < items.length + 5; i++) {
      fireEvent.keyDown(input, { key: 'ArrowDown' });
    }
    const updatedItems = screen.getAllByRole('option');
    expect(updatedItems[updatedItems.length - 1].getAttribute('aria-selected')).toBe('true');
  });

  it('ArrowUp does not go above the first item', () => {
    renderOpen();
    const input = screen.getByLabelText('Command palette search');
    fireEvent.keyDown(input, { key: 'ArrowUp' });
    const items = screen.getAllByRole('option');
    expect(items[0].getAttribute('aria-selected')).toBe('true');
  });

  it('uses role=listbox and role=option with aria-selected', () => {
    renderOpen();
    expect(screen.getByRole('listbox')).toBeTruthy();
    const options = screen.getAllByRole('option');
    expect(options.length).toBeGreaterThan(0);
    // Exactly one item is selected
    const selected = options.filter((o) => o.getAttribute('aria-selected') === 'true');
    expect(selected.length).toBe(1);
  });
});
