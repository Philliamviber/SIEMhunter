/**
 * NotificationPoller tests (PR6).
 *
 * Covers the since-last-seen delta logic:
 *   - When has_new=true and new_count>0, exactly one warning toast is shown
 *   - When has_new=false (new_count=0), no toast is shown
 *   - Toast message includes the hit count (singular vs plural)
 *   - API failures are swallowed silently (no crash, no toast)
 *   - Polling re-fires on visibilitychange to visible
 *   - Only one toast raised per poll cycle (inflight guard)
 *
 * Note: fake timers are NOT used here because vi.runAllTimersAsync fires the
 * 15-min setInterval + ToastProvider 5-s dismiss timers in a loop.
 * The initial check() runs immediately on mount via the async mock, so
 * screen.findBy* / waitFor assertions are sufficient.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import { NotificationPoller } from '../NotificationPoller';
import { ToastProvider } from '../ToastProvider';
import * as clientModule from '../../api/client';

function renderPoller() {
  return render(
    <ToastProvider>
      <NotificationPoller />
    </ToastProvider>,
  );
}

describe('NotificationPoller — since-last-seen delta logic', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('shows one warning toast when has_new=true', async () => {
    vi.spyOn(clientModule.api, 'getNotifications').mockResolvedValue({
      new_count: 3,
      has_new: true,
      checked_at: new Date().toISOString(),
    });

    renderPoller();

    // findByText waits for the async state update caused by check() resolving
    await screen.findByText(/3 new high\/critical detections since/i);
  });

  it('shows singular form for a single new hit', async () => {
    vi.spyOn(clientModule.api, 'getNotifications').mockResolvedValue({
      new_count: 1,
      has_new: true,
      checked_at: new Date().toISOString(),
    });

    renderPoller();

    await screen.findByText(/1 new high\/critical detection since/i);
  });

  it('shows no toast when has_new=false', async () => {
    const mockGet = vi.spyOn(clientModule.api, 'getNotifications').mockResolvedValue({
      new_count: 0,
      has_new: false,
      checked_at: new Date().toISOString(),
    });

    renderPoller();

    // Wait for the API call to complete, then assert no toast
    await waitFor(() => expect(mockGet).toHaveBeenCalledOnce());
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });

  it('shows no toast and does not crash when the API call fails', async () => {
    const mockGet = vi.spyOn(clientModule.api, 'getNotifications').mockRejectedValue(
      new Error('network error'),
    );

    expect(() => renderPoller()).not.toThrow();

    await waitFor(() => expect(mockGet).toHaveBeenCalledOnce());
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });

  it('fires again on visibilitychange to visible', async () => {
    const mockGet = vi.spyOn(clientModule.api, 'getNotifications').mockResolvedValue({
      new_count: 0,
      has_new: false,
      checked_at: new Date().toISOString(),
    });

    renderPoller();

    // Wait for initial mount check
    await waitFor(() => expect(mockGet).toHaveBeenCalledOnce());
    const callsBefore = mockGet.mock.calls.length;

    await act(async () => {
      Object.defineProperty(document, 'visibilityState', {
        value: 'visible',
        writable: true,
      });
      document.dispatchEvent(new Event('visibilitychange'));
    });

    await waitFor(() => expect(mockGet.mock.calls.length).toBeGreaterThan(callsBefore));
  });

  it('raises exactly one toast per poll cycle even if new_count is large', async () => {
    vi.spyOn(clientModule.api, 'getNotifications').mockResolvedValue({
      new_count: 99,
      has_new: true,
      checked_at: new Date().toISOString(),
    });

    renderPoller();

    await screen.findByText(/99 new high\/critical detections since/i);

    // Only one toast element should exist for one poll cycle
    const statuses = screen.queryAllByRole('status');
    expect(statuses.length).toBe(1);
  });
});
