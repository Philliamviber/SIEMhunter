/**
 * useToast — global toast/notification hook (FR #23).
 *
 * The provider lives in components/ToastProvider.tsx. This module defines the
 * shared context + the public hook so any component can fire a toast:
 *
 *   const toast = useToast();
 *   toast.success('Saved');
 *   toast.error('Something went wrong');
 *   toast.warning('Heads up');
 *
 * The 401 interceptor in api/client.ts uses the imperative bridge
 * (toastBridge.error) instead of the hook, because client.ts is a plain module
 * and cannot call React hooks.
 */
import { createContext, useContext } from 'react';

export type ToastKind = 'success' | 'error' | 'warning';

export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
}

export interface ToastApi {
  success: (message: string) => void;
  error: (message: string) => void;
  warning: (message: string) => void;
}

export const ToastContext = createContext<ToastApi | null>(null);

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error('useToast must be used within a <ToastProvider>');
  }
  return ctx;
}

/**
 * Imperative bridge for non-React modules (the api/client.ts 401 interceptor).
 *
 * ToastProvider registers its `error` handler here on mount. Modules outside
 * the React tree call `toastBridge.error(msg)` and it routes to the live
 * provider if one is mounted. No-ops safely before mount / after unmount.
 */
type BridgeHandler = (message: string) => void;

export const toastBridge: {
  _error: BridgeHandler | null;
  register: (handler: BridgeHandler) => void;
  unregister: () => void;
  error: (message: string) => void;
} = {
  _error: null,
  register(handler) {
    this._error = handler;
  },
  unregister() {
    this._error = null;
  },
  error(message) {
    if (this._error) this._error(message);
  },
};
