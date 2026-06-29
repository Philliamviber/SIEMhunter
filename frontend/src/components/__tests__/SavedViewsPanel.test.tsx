/**
 * SavedViewsPanel tests.
 *
 * Verifies:
 *   - Renders "No saved views" when empty
 *   - Renders saved view names from the API
 *   - "Save" button calls upsert mutation with the current filters
 *   - "Load" button calls onLoad with the view's filters
 *   - "Delete" button calls delete mutation
 *   - Save input becomes visible on "+ Save" click and hides on Cancel
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { SavedView } from '../../types/api';

// ── Mocks ─────────────────────────────────────────────────────────────────────

const mockUpsertMutate = vi.fn();
const mockDeleteMutate = vi.fn();
let mockViews: SavedView[] = [];
let mockIsLoading = false;

vi.mock('../../hooks/useApi', () => ({
  useSavedViews: () => ({
    data: { views: mockViews },
    isLoading: mockIsLoading,
  }),
  useUpsertSavedView: () => ({ mutate: mockUpsertMutate, isPending: false }),
  useDeleteSavedView: () => ({ mutate: mockDeleteMutate, isPending: false }),
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

import { SavedViewsPanel } from '../SavedViewsPanel';

const FILTERS = { severity: 'high', rule_id: 'RULE-001' };
const onLoad = vi.fn();

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

function renderPanel(overrideFilters = FILTERS) {
  return render(
    <SavedViewsPanel page="detections" currentFilters={overrideFilters} onLoad={onLoad} />,
    { wrapper },
  );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('SavedViewsPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockViews = [];
    mockIsLoading = false;
  });

  it('renders "No saved views" when the list is empty', () => {
    renderPanel();
    expect(screen.getByText('No saved views')).toBeTruthy();
  });

  it('shows loading state when isLoading is true', () => {
    mockIsLoading = true;
    renderPanel();
    expect(screen.getByText('Loading…')).toBeTruthy();
  });

  it('renders saved view names from the API', () => {
    mockViews = [
      { name: 'High severity', page: 'detections', filters: { severity: 'high' } },
      { name: 'Rule 001 only', page: 'detections', filters: { rule_id: 'RULE-001' } },
    ];
    renderPanel();
    expect(screen.getByText('High severity')).toBeTruthy();
    expect(screen.getByText('Rule 001 only')).toBeTruthy();
  });

  it('calls onLoad with view filters when a view name is clicked', async () => {
    const filters = { severity: 'critical' };
    mockViews = [{ name: 'Crit view', page: 'detections', filters }];
    renderPanel();
    await userEvent.click(screen.getByText('Crit view'));
    expect(onLoad).toHaveBeenCalledWith(filters);
  });

  it('shows save input when "+ Save" is clicked', async () => {
    renderPanel();
    await userEvent.click(screen.getByText('+ Save'));
    expect(screen.getByPlaceholderText('View name…')).toBeTruthy();
  });

  it('hides save input when "Cancel" is clicked', async () => {
    renderPanel();
    await userEvent.click(screen.getByText('+ Save'));
    await userEvent.click(screen.getByText('Cancel'));
    expect(screen.queryByPlaceholderText('View name…')).toBeNull();
  });

  it('calls upsert mutation with the correct payload on save', async () => {
    mockUpsertMutate.mockImplementation((_view, { onSuccess } = {}) => {
      onSuccess?.();
    });
    renderPanel();
    await userEvent.click(screen.getByText('+ Save'));
    await userEvent.type(screen.getByPlaceholderText('View name…'), 'My filter');
    await userEvent.click(screen.getByText('Save'));
    expect(mockUpsertMutate).toHaveBeenCalledWith(
      expect.objectContaining({
        name: 'My filter',
        page: 'detections',
        filters: FILTERS,
      }),
      expect.any(Object),
    );
  });

  it('clears save input and hides it after successful save', async () => {
    mockUpsertMutate.mockImplementation((_view, { onSuccess } = {}) => {
      onSuccess?.();
    });
    renderPanel();
    await userEvent.click(screen.getByText('+ Save'));
    await userEvent.type(screen.getByPlaceholderText('View name…'), 'Temp view');
    await userEvent.click(screen.getByText('Save'));
    await waitFor(() => {
      expect(screen.queryByPlaceholderText('View name…')).toBeNull();
    });
  });

  it('calls delete mutation when delete button is clicked', async () => {
    mockViews = [{ name: 'To delete', page: 'detections', filters: {} }];
    renderPanel();
    const deleteBtn = screen.getByLabelText('Delete saved view: To delete');
    await userEvent.click(deleteBtn);
    expect(mockDeleteMutate).toHaveBeenCalledWith({ page: 'detections', name: 'To delete' });
  });

  it('Save button is disabled when name input is empty', async () => {
    renderPanel();
    await userEvent.click(screen.getByText('+ Save'));
    const saveBtn = screen.getByText('Save').closest('button');
    expect(saveBtn?.disabled).toBe(true);
  });
});
