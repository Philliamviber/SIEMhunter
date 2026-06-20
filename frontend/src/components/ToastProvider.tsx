/**
 * ToastProvider — global toast/notification container (FR #23).
 *
 * Rendered once at the app root (inside QueryClientProvider, after the
 * LoginGate check). Provides the ToastApi via context and renders a fixed
 * container in the corner.
 *
 * Behaviour (per spec):
 *   - useToast().success / .error / .warning push a toast.
 *   - Auto-dismiss after 5 s.
 *   - At most 3 toasts visible (oldest dropped when a 4th arrives).
 *   - Also registers an imperative bridge so the api/client.ts 401 interceptor
 *     (a non-React module) can surface 'Session expired' before redirecting.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { ToastContext, toastBridge } from '../hooks/useToast';
import type { Toast, ToastApi, ToastKind } from '../hooks/useToast';

const AUTO_DISMISS_MS = 5000;
const MAX_VISIBLE = 3;

const KIND_STYLES: Record<ToastKind, string> = {
  success: 'bg-green-900/90 border-green-700 text-green-100',
  error: 'bg-red-900/90 border-red-700 text-red-100',
  warning: 'bg-amber-900/90 border-amber-700 text-amber-100',
};

const KIND_LABEL: Record<ToastKind, string> = {
  success: 'Success',
  error: 'Error',
  warning: 'Warning',
};

interface ToastProviderProps {
  children: ReactNode;
}

export function ToastProvider({ children }: ToastProviderProps) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);
  // Track timers so we can clear them on unmount / manual dismiss.
  const timers = useRef<Map<number, ReturnType<typeof setTimeout>>>(new Map());

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
    const timer = timers.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timers.current.delete(id);
    }
  }, []);

  const push = useCallback(
    (kind: ToastKind, message: string) => {
      const id = nextId.current++;
      setToasts((prev) => {
        const next = [...prev, { id, kind, message }];
        // Cap at MAX_VISIBLE — drop the oldest if we exceed it.
        return next.slice(-MAX_VISIBLE);
      });
      const timer = setTimeout(() => dismiss(id), AUTO_DISMISS_MS);
      timers.current.set(id, timer);
    },
    [dismiss],
  );

  const api = useMemo<ToastApi>(
    () => ({
      success: (m: string) => push('success', m),
      error: (m: string) => push('error', m),
      warning: (m: string) => push('warning', m),
    }),
    [push],
  );

  // Register the imperative bridge for non-React callers (401 interceptor).
  useEffect(() => {
    toastBridge.register((m) => push('error', m));
    return () => toastBridge.unregister();
  }, [push]);

  // Clear all pending timers on unmount.
  useEffect(() => {
    const map = timers.current;
    return () => {
      map.forEach((t) => clearTimeout(t));
      map.clear();
    };
  }, []);

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div
        className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 w-80 max-w-[calc(100vw-2rem)]"
        role="region"
        aria-label="Notifications"
        aria-live="polite"
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            role="status"
            className={`flex items-start gap-2 border rounded-lg px-3 py-2.5 shadow-lg text-sm ${KIND_STYLES[t.kind]}`}
          >
            <span className="flex-1 break-words">
              <span className="font-semibold mr-1">{KIND_LABEL[t.kind]}:</span>
              {t.message}
            </span>
            <button
              type="button"
              onClick={() => dismiss(t.id)}
              aria-label="Dismiss notification"
              className="text-current opacity-60 hover:opacity-100 leading-none text-base"
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
