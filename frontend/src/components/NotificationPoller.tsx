/**
 * NotificationPoller — background poller for new high/critical detection hits.
 *
 * Fires on:
 *   - Component mount (first check on login / page load)
 *   - document visibilitychange → visible (analyst switches back to the tab)
 *   - A 15-minute interval (matches the detection batch cadence)
 *
 * Each call hits GET /v1/analyst/notifications, which atomically reads the
 * analyst's last-seen marker from the PR2 KV store, counts high/critical hits
 * since that marker, and advances the marker to now.  If the count is positive
 * exactly ONE warning toast is raised so the analyst is never flooded.
 *
 * All failures are swallowed silently — notification polling is best-effort
 * and must not surface false auth errors or crash the app.
 */
import { useEffect, useRef, useCallback } from 'react';
import { useToast } from '../hooks/useToast';
import { api } from '../api/client';

const POLL_INTERVAL_MS = 15 * 60 * 1000; // 15 min — matches detection batch cadence

export function NotificationPoller() {
  const toast = useToast();
  const inflight = useRef(false);

  const check = useCallback(async () => {
    if (inflight.current) return;
    inflight.current = true;
    try {
      const result = await api.getNotifications();
      if (result.has_new) {
        const label =
          result.new_count === 1
            ? '1 new high/critical detection since your last visit'
            : `${result.new_count} new high/critical detections since your last visit`;
        toast.warning(label);
      }
    } catch {
      // Silently ignore — notification polling is best-effort
    } finally {
      inflight.current = false;
    }
  }, [toast]);

  useEffect(() => {
    function onVisibilityChange() {
      if (document.visibilityState === 'visible') {
        void check();
      }
    }

    document.addEventListener('visibilitychange', onVisibilityChange);
    const interval = setInterval(() => void check(), POLL_INTERVAL_MS);
    void check(); // initial check on mount

    return () => {
      document.removeEventListener('visibilitychange', onVisibilityChange);
      clearInterval(interval);
    };
  }, [check]);

  return null;
}
