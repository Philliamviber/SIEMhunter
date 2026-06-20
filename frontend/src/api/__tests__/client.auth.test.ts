import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// We re-import the module fresh per test so the internal `redirecting` guard
// and activity timers reset between cases.
async function freshClient() {
  vi.resetModules();
  return import('../client');
}

describe('client auth interceptor (FR #10 / #23)', () => {
  let reloadSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers();
    sessionStorage.clear();
    reloadSpy = vi.fn();
    // jsdom's window.location.reload is read-only; redefine it.
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...window.location, reload: reloadSpy },
    });
  });

  afterEach(() => {
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('attaches X-CSRF-Token to state-changing requests', async () => {
    const client = await freshClient();
    client.setCsrfToken('csrf-abc');
    client.markSessionStart();

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({}),
    });
    vi.stubGlobal('fetch', fetchMock);

    await client.api.query({ ksql: 'SELECT 1' } as never).catch(() => {});

    const [, init] = fetchMock.mock.calls[0];
    expect(init.method).toBe('POST');
    expect(init.headers['X-CSRF-Token']).toBe('csrf-abc');
    expect(init.credentials).toBe('include');
  });

  it('does NOT attach a CSRF header to GET requests', async () => {
    const client = await freshClient();
    client.setCsrfToken('csrf-abc');
    client.markSessionStart();

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({}),
    });
    vi.stubGlobal('fetch', fetchMock);

    await client.api.metrics().catch(() => {});

    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers['X-CSRF-Token']).toBeUndefined();
    expect(init.credentials).toBe('include');
  });

  it('on a 401, clears the CSRF token and hard-reloads to the login gate', async () => {
    const client = await freshClient();
    client.setCsrfToken('csrf-abc');
    client.markSessionStart();

    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ detail: { code: 'AUTH_REQUIRED', error: 'nope' } }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(client.api.metrics()).rejects.toMatchObject({ status: 401 });

    // CSRF token cleared immediately.
    expect(client.getCsrfToken()).toBeNull();
    // Reload is scheduled behind a short delay; advance timers to fire it.
    vi.advanceTimersByTime(200);
    expect(reloadSpy).toHaveBeenCalled();
  });

  it('redirects before hitting the network once the idle timeout passes', async () => {
    const client = await freshClient();
    client.setCsrfToken('csrf-abc');
    client.markSessionStart();

    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    // Jump past the 30-minute idle window.
    vi.advanceTimersByTime(31 * 60 * 1000);

    await expect(client.api.metrics()).rejects.toMatchObject({ status: 401 });
    // No network call should have been made — we short-circuited.
    expect(fetchMock).not.toHaveBeenCalled();
    vi.advanceTimersByTime(200);
    expect(reloadSpy).toHaveBeenCalled();
  });
});
