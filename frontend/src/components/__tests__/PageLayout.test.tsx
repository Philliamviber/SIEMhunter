import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

// Mock heavy child components so tests stay fast and focused on layout.
vi.mock('../IncidentSelector', () => ({
  IncidentSelector: () => <div data-testid="incident-selector" />,
}));
vi.mock('../GlobalSearchBar', () => ({
  GlobalSearchBar: () => <div data-testid="global-search-bar" />,
}));
vi.mock('../ClaudeChatbar', () => ({
  ClaudeChatbar: () => <div data-testid="claude-chatbar" />,
}));
vi.mock('../../api/client', () => ({
  logout: vi.fn().mockResolvedValue(undefined),
}));
vi.mock('../../context/IncidentContext', () => ({
  useIncidentContext: () => ({ activeIncidentId: null, activeIncident: null }),
}));

import { PageLayout } from '../PageLayout';

function renderLayout() {
  return render(
    <MemoryRouter>
      <PageLayout>
        <div data-testid="page-content">Content</div>
      </PageLayout>
    </MemoryRouter>,
  );
}

describe('PageLayout sidebar', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
  });

  it('renders expanded by default', () => {
    renderLayout();
    const sidebar = screen.getByTestId('sidebar');
    expect(sidebar.getAttribute('data-collapsed')).toBe('false');
    expect(screen.getByText('SIEMhunter')).toBeInTheDocument();
    expect(screen.getByText('Overview')).toBeInTheDocument();
  });

  it('collapses when toggle is clicked and hides labels', async () => {
    const user = userEvent.setup();
    renderLayout();

    await user.click(screen.getByRole('button', { name: /collapse sidebar/i }));

    const sidebar = screen.getByTestId('sidebar');
    expect(sidebar.getAttribute('data-collapsed')).toBe('true');
    // Nav labels hidden; icons still present via title attributes
    expect(screen.queryByText('SIEMhunter')).not.toBeInTheDocument();
    expect(screen.queryByText('Events')).not.toBeInTheDocument();
  });

  it('persists collapsed state to localStorage on toggle', async () => {
    const user = userEvent.setup();
    renderLayout();

    await user.click(screen.getByRole('button', { name: /collapse sidebar/i }));
    expect(localStorage.getItem('sidebar-collapsed')).toBe('true');

    await user.click(screen.getByRole('button', { name: /expand sidebar/i }));
    expect(localStorage.getItem('sidebar-collapsed')).toBe('false');
  });

  it('initialises collapsed from localStorage', () => {
    localStorage.setItem('sidebar-collapsed', 'true');
    renderLayout();
    const sidebar = screen.getByTestId('sidebar');
    expect(sidebar.getAttribute('data-collapsed')).toBe('true');
    expect(screen.queryByText('SIEMhunter')).not.toBeInTheDocument();
  });

  it('expands again after two toggles', async () => {
    const user = userEvent.setup();
    renderLayout();

    await user.click(screen.getByRole('button', { name: /collapse sidebar/i }));
    await user.click(screen.getByRole('button', { name: /expand sidebar/i }));

    const sidebar = screen.getByTestId('sidebar');
    expect(sidebar.getAttribute('data-collapsed')).toBe('false');
    expect(screen.getByText('SIEMhunter')).toBeInTheDocument();
  });

  it('renders nav links with title attributes when collapsed for accessibility', async () => {
    const user = userEvent.setup();
    renderLayout();

    await user.click(screen.getByRole('button', { name: /collapse sidebar/i }));

    // Nav links should have title= for tooltip accessibility in icon-only mode
    const overviewLink = screen.getByTitle('Overview');
    expect(overviewLink).toBeInTheDocument();
  });

  it('renders page content regardless of sidebar state', async () => {
    const user = userEvent.setup();
    renderLayout();

    expect(screen.getByTestId('page-content')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /collapse sidebar/i }));
    expect(screen.getByTestId('page-content')).toBeInTheDocument();
  });
});
