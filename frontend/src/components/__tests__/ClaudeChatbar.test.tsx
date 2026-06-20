import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

// ── Mock the useAiSummary hook ────────────────────────────────────────────────
// vi.hoisted ensures the variable is initialized before vi.mock hoisting runs.
const mockUseAiSummary = vi.hoisted(() => vi.fn());

vi.mock('../../hooks/useApi', () => ({
  useAiSummary: () => mockUseAiSummary(),
}));

// Import after the mock is set up
import { ClaudeChatbar } from '../ClaudeChatbar';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeData(overrides = {}) {
  return {
    narrative: 'No notable threats detected in the last hour.',
    notable_items: ['High-volume logon from dc01', 'Lateral movement from 10.0.0.5'],
    disclaimer: 'AI-generated. Verify independently.',
    source_window: 'last 1h',
    generated_at: '2026-06-20T14:32:05.000Z',
    ...overrides,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('ClaudeChatbar', () => {
  beforeEach(() => {
    // Reset sessionStorage between tests so collapse state doesn't bleed
    sessionStorage.clear();
    vi.resetAllMocks();
  });

  describe('toggle button', () => {
    it('renders the toggle button', () => {
      mockUseAiSummary.mockReturnValue({ data: null, isLoading: false, isError: false });
      render(<ClaudeChatbar />);
      expect(screen.getByRole('button', { name: /toggle ai analysis panel/i })).toBeTruthy();
    });

    it('starts collapsed by default (panel not visible)', () => {
      mockUseAiSummary.mockReturnValue({ data: null, isLoading: false, isError: false });
      render(<ClaudeChatbar />);
      // The panel body is only rendered when isOpen is true
      expect(screen.queryByText('AI Analysis', { selector: 'span.text-sm.font-semibold' })).toBeNull();
    });

    it('expands the panel when the toggle button is clicked', async () => {
      mockUseAiSummary.mockReturnValue({ data: null, isLoading: false, isError: false });
      render(<ClaudeChatbar />);
      await userEvent.click(screen.getByRole('button', { name: /toggle ai analysis panel/i }));
      // After expanding, the panel header text "AI Analysis" should be visible
      expect(screen.getAllByText('AI Analysis').length).toBeGreaterThan(0);
    });

    it('collapses the panel when the close chevron button is clicked', async () => {
      mockUseAiSummary.mockReturnValue({ data: null, isLoading: false, isError: false });
      render(<ClaudeChatbar />);
      // Open first
      await userEvent.click(screen.getByRole('button', { name: /toggle ai analysis panel/i }));
      // Then close using the in-panel close button
      await userEvent.click(screen.getByRole('button', { name: /close ai analysis panel/i }));
      // Panel header text should be gone
      expect(screen.queryByRole('button', { name: /close ai analysis panel/i })).toBeNull();
    });

    it('persists open state to sessionStorage', async () => {
      mockUseAiSummary.mockReturnValue({ data: null, isLoading: false, isError: false });
      render(<ClaudeChatbar />);
      await userEvent.click(screen.getByRole('button', { name: /toggle ai analysis panel/i }));
      expect(sessionStorage.getItem('siemhunter.chatbar.open')).toBe('true');
    });

    it('restores open state from sessionStorage on mount', () => {
      sessionStorage.setItem('siemhunter.chatbar.open', 'true');
      mockUseAiSummary.mockReturnValue({ data: null, isLoading: false, isError: false });
      render(<ClaudeChatbar />);
      // The panel should be open immediately
      expect(screen.getAllByText('AI Analysis').length).toBeGreaterThan(0);
    });
  });

  describe('"AI unavailable" state', () => {
    it('renders the unavailable message when isError is true and panel is open', async () => {
      mockUseAiSummary.mockReturnValue({ data: null, isLoading: false, isError: true });
      render(<ClaudeChatbar />);
      await userEvent.click(screen.getByRole('button', { name: /toggle ai analysis panel/i }));
      expect(
        screen.getByText(/AI analysis unavailable/i)
      ).toBeTruthy();
    });

    it('does not render the unavailable message when data is present', async () => {
      mockUseAiSummary.mockReturnValue({
        data: makeData(),
        isLoading: false,
        isError: false,
      });
      render(<ClaudeChatbar />);
      await userEvent.click(screen.getByRole('button', { name: /toggle ai analysis panel/i }));
      expect(screen.queryByText(/AI analysis unavailable/i)).toBeNull();
    });
  });

  describe('loading state', () => {
    it('shows loading spinner text when isLoading is true', async () => {
      mockUseAiSummary.mockReturnValue({ data: null, isLoading: true, isError: false });
      render(<ClaudeChatbar />);
      await userEvent.click(screen.getByRole('button', { name: /toggle ai analysis panel/i }));
      expect(screen.getByText('Loading analysis...')).toBeTruthy();
    });
  });

  describe('data rendering', () => {
    it('renders the narrative when data is available', async () => {
      mockUseAiSummary.mockReturnValue({
        data: makeData(),
        isLoading: false,
        isError: false,
      });
      render(<ClaudeChatbar />);
      await userEvent.click(screen.getByRole('button', { name: /toggle ai analysis panel/i }));
      expect(screen.getByText('No notable threats detected in the last hour.')).toBeTruthy();
    });

    it('renders notable_items as a bullet list', async () => {
      mockUseAiSummary.mockReturnValue({
        data: makeData(),
        isLoading: false,
        isError: false,
      });
      render(<ClaudeChatbar />);
      await userEvent.click(screen.getByRole('button', { name: /toggle ai analysis panel/i }));
      expect(screen.getByText('High-volume logon from dc01')).toBeTruthy();
      expect(screen.getByText('Lateral movement from 10.0.0.5')).toBeTruthy();
    });

    it('renders the disclaimer', async () => {
      mockUseAiSummary.mockReturnValue({
        data: makeData(),
        isLoading: false,
        isError: false,
      });
      render(<ClaudeChatbar />);
      await userEvent.click(screen.getByRole('button', { name: /toggle ai analysis panel/i }));
      expect(screen.getByText('AI-generated. Verify independently.')).toBeTruthy();
    });

    it('renders generated_at timestamp via formatTimestamp (contains UTC)', async () => {
      mockUseAiSummary.mockReturnValue({
        data: makeData({ generated_at: '2026-06-20T14:32:05.000Z' }),
        isLoading: false,
        isError: false,
      });
      render(<ClaudeChatbar />);
      await userEvent.click(screen.getByRole('button', { name: /toggle ai analysis panel/i }));
      // formatTimestamp produces a string like "2026-06-20 14:32:05 UTC (09:32:05 EST)"
      const generatedLine = screen.getByText(/Generated .* UTC/i);
      expect(generatedLine).toBeTruthy();
    });

    it('renders source_window alongside the generated timestamp', async () => {
      mockUseAiSummary.mockReturnValue({
        data: makeData({ source_window: 'last 1h' }),
        isLoading: false,
        isError: false,
      });
      render(<ClaudeChatbar />);
      await userEvent.click(screen.getByRole('button', { name: /toggle ai analysis panel/i }));
      expect(screen.getByText(/last 1h/)).toBeTruthy();
    });
  });
});
