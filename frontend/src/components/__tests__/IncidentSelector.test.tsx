import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React from 'react';
import type { Incident } from '../../types/api';

// ── Mocks ─────────────────────────────────────────────────────────────────────

const mockSetActiveIncidentId = vi.fn();

const mockContextValue = vi.hoisted(() => ({
  activeIncidentId: null as string | null,
  activeIncident: null as Incident | null,
  setActiveIncidentId: vi.fn(),
}));

vi.mock('../../context/IncidentContext', () => ({
  useIncidentContext: () => mockContextValue,
}));

const mockUseIncidents = vi.hoisted(() => vi.fn());
vi.mock('../../hooks/useApi', () => ({
  useIncidents: () => mockUseIncidents(),
}));

// SeverityBadge renders a simple span — stub to avoid unrelated deps
vi.mock('../SeverityBadge', () => ({
  SeverityBadge: ({ severity }: { severity: string }) => (
    <span data-testid={`badge-${severity}`}>{severity}</span>
  ),
}));

import { IncidentSelector } from '../IncidentSelector';

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeIncident(overrides: Partial<Incident> = {}): Incident {
  return {
    id: 'inc-1',
    name: 'Ransomware Campaign',
    description: null,
    severity: 'critical',
    status: 'open',
    created_at: '2026-06-01T10:00:00Z',
    updated_at: '2026-06-01T10:05:00Z',
    event_count: 5,
    ...overrides,
  };
}

const INC_A = makeIncident({ id: 'inc-a', name: 'Alpha Incident', severity: 'high' });
const INC_B = makeIncident({ id: 'inc-b', name: 'Beta Incident', severity: 'medium' });
const INC_C = makeIncident({ id: 'inc-c', name: 'Gamma Incident', severity: 'low' });

// ── Helpers ───────────────────────────────────────────────────────────────────

function setup(contextOverrides?: Partial<typeof mockContextValue>) {
  Object.assign(mockContextValue, {
    activeIncidentId: null,
    activeIncident: null,
    setActiveIncidentId: mockSetActiveIncidentId,
    ...contextOverrides,
  });
  mockUseIncidents.mockReturnValue({
    data: { incidents: [INC_A, INC_B, INC_C] },
  });
  return userEvent.setup();
}

// ── ARIA attribute tests ───────────────────────────────────────────────────────

describe('IncidentSelector ARIA attributes', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockContextValue.setActiveIncidentId = mockSetActiveIncidentId;
  });

  it('renders with role=combobox, aria-haspopup=listbox, aria-expanded=false when closed', () => {
    setup();
    render(<IncidentSelector />);
    const combobox = screen.getByRole('combobox');
    expect(combobox).toBeTruthy();
    expect(combobox.getAttribute('aria-haspopup')).toBe('listbox');
    expect(combobox.getAttribute('aria-expanded')).toBe('false');
  });

  it('sets aria-expanded=true when open', async () => {
    const user = setup();
    render(<IncidentSelector />);
    const combobox = screen.getByRole('combobox');
    await user.click(combobox);
    expect(combobox.getAttribute('aria-expanded')).toBe('true');
  });

  it('renders listbox with role=listbox when open', async () => {
    const user = setup();
    render(<IncidentSelector />);
    await user.click(screen.getByRole('combobox'));
    expect(screen.getByRole('listbox')).toBeTruthy();
  });

  it('renders each option with role=option and aria-selected', async () => {
    const user = setup();
    render(<IncidentSelector />);
    await user.click(screen.getByRole('combobox'));
    const options = screen.getAllByRole('option');
    expect(options).toHaveLength(3);
    options.forEach((opt) => {
      expect(opt.hasAttribute('aria-selected')).toBe(true);
    });
  });

  it('aria-selected=true for the currently active incident', async () => {
    const user = setup({ activeIncidentId: 'inc-b', activeIncident: INC_B });
    render(<IncidentSelector />);
    await user.click(screen.getByRole('combobox'));
    const options = screen.getAllByRole('option');
    const selected = options.filter((o) => o.getAttribute('aria-selected') === 'true');
    expect(selected).toHaveLength(1);
    expect(selected[0].textContent).toContain('Beta Incident');
  });

  it('aria-controls points to the listbox id', async () => {
    const user = setup();
    render(<IncidentSelector />);
    const combobox = screen.getByRole('combobox');
    const controlsId = combobox.getAttribute('aria-controls');
    expect(controlsId).toBeTruthy();
    await user.click(combobox);
    const listbox = screen.getByRole('listbox');
    expect(listbox.id).toBe(controlsId);
  });

  it('aria-activedescendant points to first option id when opened with no selection', async () => {
    const user = setup();
    render(<IncidentSelector />);
    const combobox = screen.getByRole('combobox');
    await user.click(combobox);
    const activeDescendant = combobox.getAttribute('aria-activedescendant');
    const firstOption = screen.getAllByRole('option')[0];
    expect(activeDescendant).toBe(firstOption.id);
  });
});

// ── Keyboard navigation tests ─────────────────────────────────────────────────

describe('IncidentSelector keyboard navigation', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockContextValue.setActiveIncidentId = mockSetActiveIncidentId;
  });

  it('opens with ArrowDown when closed', async () => {
    const user = setup();
    render(<IncidentSelector />);
    const combobox = screen.getByRole('combobox');
    combobox.focus();
    await user.keyboard('{ArrowDown}');
    expect(screen.getByRole('listbox')).toBeTruthy();
  });

  it('opens with Enter when closed', async () => {
    const user = setup();
    render(<IncidentSelector />);
    const combobox = screen.getByRole('combobox');
    combobox.focus();
    await user.keyboard('{Enter}');
    expect(screen.getByRole('listbox')).toBeTruthy();
  });

  it('moves aria-activedescendant down with ArrowDown', async () => {
    const user = setup();
    render(<IncidentSelector />);
    const combobox = screen.getByRole('combobox');
    combobox.focus();
    await user.keyboard('{ArrowDown}'); // open, focus index 0
    await user.keyboard('{ArrowDown}'); // focus index 1
    const options = screen.getAllByRole('option');
    expect(combobox.getAttribute('aria-activedescendant')).toBe(options[1].id);
  });

  it('moves aria-activedescendant up with ArrowUp', async () => {
    const user = setup();
    render(<IncidentSelector />);
    const combobox = screen.getByRole('combobox');
    combobox.focus();
    await user.keyboard('{ArrowDown}'); // open, focus 0
    await user.keyboard('{ArrowDown}'); // focus 1
    await user.keyboard('{ArrowUp}');  // back to 0
    const options = screen.getAllByRole('option');
    expect(combobox.getAttribute('aria-activedescendant')).toBe(options[0].id);
  });

  it('does not move focus above index 0 (clamp at top)', async () => {
    const user = setup();
    render(<IncidentSelector />);
    const combobox = screen.getByRole('combobox');
    combobox.focus();
    await user.keyboard('{ArrowDown}'); // open, focus 0
    await user.keyboard('{ArrowUp}');  // clamp at 0
    const options = screen.getAllByRole('option');
    expect(combobox.getAttribute('aria-activedescendant')).toBe(options[0].id);
  });

  it('does not move focus below last index (clamp at bottom)', async () => {
    const user = setup();
    render(<IncidentSelector />);
    const combobox = screen.getByRole('combobox');
    combobox.focus();
    await user.keyboard('{ArrowDown}');
    await user.keyboard('{ArrowDown}');
    await user.keyboard('{ArrowDown}');
    await user.keyboard('{ArrowDown}'); // extra press beyond end
    const options = screen.getAllByRole('option');
    expect(combobox.getAttribute('aria-activedescendant')).toBe(options[2].id);
  });

  it('Home key moves focus to first option', async () => {
    const user = setup();
    render(<IncidentSelector />);
    const combobox = screen.getByRole('combobox');
    combobox.focus();
    await user.keyboard('{ArrowDown}');
    await user.keyboard('{ArrowDown}');
    await user.keyboard('{Home}');
    const options = screen.getAllByRole('option');
    expect(combobox.getAttribute('aria-activedescendant')).toBe(options[0].id);
  });

  it('End key moves focus to last option', async () => {
    const user = setup();
    render(<IncidentSelector />);
    const combobox = screen.getByRole('combobox');
    combobox.focus();
    await user.keyboard('{ArrowDown}'); // open, focus 0
    await user.keyboard('{End}');
    const options = screen.getAllByRole('option');
    expect(combobox.getAttribute('aria-activedescendant')).toBe(options[2].id);
  });

  it('Enter selects the focused option and closes the dropdown', async () => {
    const user = setup();
    render(<IncidentSelector />);
    const combobox = screen.getByRole('combobox');
    combobox.focus();
    await user.keyboard('{ArrowDown}'); // open, focus 0 (inc-a)
    await user.keyboard('{ArrowDown}'); // focus 1 (inc-b)
    await user.keyboard('{Enter}');
    expect(mockSetActiveIncidentId).toHaveBeenCalledWith('inc-b');
    expect(screen.queryByRole('listbox')).toBeNull();
  });

  it('Escape closes the dropdown without selecting', async () => {
    const user = setup();
    render(<IncidentSelector />);
    const combobox = screen.getByRole('combobox');
    combobox.focus();
    await user.keyboard('{ArrowDown}');
    await user.keyboard('{Escape}');
    expect(mockSetActiveIncidentId).not.toHaveBeenCalled();
    expect(screen.queryByRole('listbox')).toBeNull();
  });

  it('clicking an option selects it and closes the dropdown', async () => {
    const user = setup();
    render(<IncidentSelector />);
    await user.click(screen.getByRole('combobox'));
    const options = screen.getAllByRole('option');
    await user.click(options[1]);
    expect(mockSetActiveIncidentId).toHaveBeenCalledWith('inc-b');
    expect(screen.queryByRole('listbox')).toBeNull();
  });
});
