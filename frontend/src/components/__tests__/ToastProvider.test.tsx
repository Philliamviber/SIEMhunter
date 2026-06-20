import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { ToastProvider } from '../ToastProvider';
import { useToast, toastBridge } from '../../hooks/useToast';

// A tiny consumer that exposes the toast api via buttons.
function Harness() {
  const toast = useToast();
  return (
    <div>
      <button onClick={() => toast.success('saved ok')}>success</button>
      <button onClick={() => toast.error('boom')}>error</button>
      <button onClick={() => toast.warning('careful')}>warn</button>
    </div>
  );
}

describe('ToastProvider', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
  });

  it('shows a success toast when fired', () => {
    render(
      <ToastProvider>
        <Harness />
      </ToastProvider>,
    );
    act(() => {
      screen.getByText('success').click();
    });
    expect(screen.getByText(/saved ok/)).toBeInTheDocument();
  });

  it('auto-dismisses after 5 seconds', () => {
    render(
      <ToastProvider>
        <Harness />
      </ToastProvider>,
    );
    act(() => {
      screen.getByText('error').click();
    });
    expect(screen.getByText(/boom/)).toBeInTheDocument();
    act(() => {
      vi.advanceTimersByTime(5000);
    });
    expect(screen.queryByText(/boom/)).not.toBeInTheDocument();
  });

  it('caps the number of visible toasts at 3', () => {
    render(
      <ToastProvider>
        <Harness />
      </ToastProvider>,
    );
    act(() => {
      for (let i = 0; i < 5; i++) screen.getByText('warn').click();
    });
    // Only the 3 most recent remain.
    expect(screen.getAllByText(/careful/)).toHaveLength(3);
  });

  it('routes the imperative bridge (used by the 401 interceptor) to an error toast', () => {
    render(
      <ToastProvider>
        <Harness />
      </ToastProvider>,
    );
    act(() => {
      toastBridge.error('Session expired. Please log in again.');
    });
    expect(screen.getByText(/session expired/i)).toBeInTheDocument();
  });
});
