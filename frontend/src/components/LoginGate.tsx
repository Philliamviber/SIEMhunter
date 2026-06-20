/**
 * LoginGate — per-analyst username/password login gate (FR #10).
 *
 * Replaces the old paste-the-token TokenGate. There is no token field and no
 * `siemhunter_token` storage anywhere (GATE B C7). On successful login:
 *   - the server sets an HttpOnly session cookie (the browser stores it; JS
 *     cannot read it),
 *   - the CSRF token is stored in sessionStorage `siemhunter_csrf` by the
 *     client.login() helper,
 *   - onAuthenticated() flips App.tsx into the authenticated tree.
 *
 * Like TokenGate, this component is rendered OUTSIDE QueryClientProvider and
 * BrowserRouter so no background queries fire before the analyst is in.
 */
import { useState } from 'react';
import { login, ApiClientError } from '../api/client';

interface LoginGateProps {
  onAuthenticated: () => void;
}

export function LoginGate({ onAuthenticated }: LoginGateProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError('Username and password are required');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      await login(username.trim(), password);
      onAuthenticated();
    } catch (err) {
      // Identical generic message regardless of cause (no enumeration leak).
      const msg =
        err instanceof ApiClientError
          ? err.message
          : 'Login failed. Please try again.';
      setError(msg);
      setPassword('');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-gray-900 border border-gray-800 rounded-xl p-8">
        {/* Logo */}
        <div className="flex items-center gap-3 mb-6">
          <span className="text-red-500">
            <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </span>
          <div>
            <h1 className="text-white font-bold text-xl tracking-tight">SIEMhunter</h1>
            <p className="text-gray-500 text-xs">Security Console</p>
          </div>
        </div>

        <h2 className="text-white font-semibold text-lg mb-1">Analyst sign-in</h2>
        <p className="text-gray-400 text-sm mb-6">
          Sign in with your analyst username and password. Your session is held in
          a secure, HttpOnly cookie and ends when you log out or after inactivity.
        </p>

        <form onSubmit={handleSubmit} className="flex flex-col gap-3">
          <div>
            <label htmlFor="login-username" className="block text-sm font-medium text-gray-300 mb-1.5">
              Username
            </label>
            <input
              id="login-username"
              type="text"
              autoComplete="username"
              value={username}
              onChange={(e) => {
                setUsername(e.target.value);
                setError('');
              }}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2.5 text-white text-sm placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:border-red-500/50"
            />
          </div>
          <div>
            <label htmlFor="login-password" className="block text-sm font-medium text-gray-300 mb-1.5">
              Password
            </label>
            <input
              id="login-password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                setError('');
              }}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2.5 text-white text-sm placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:border-red-500/50"
            />
          </div>
          {error && (
            <p role="alert" className="text-red-400 text-xs">{error}</p>
          )}
          <button
            type="submit"
            disabled={submitting}
            className="w-full bg-red-600 hover:bg-red-700 disabled:opacity-60 disabled:cursor-not-allowed text-white font-medium py-2.5 rounded-lg text-sm transition-colors mt-1"
          >
            {submitting ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <p className="text-gray-600 text-xs mt-4 text-center">
          First-run setup requires an operator to seed an admin account.
        </p>
      </div>
    </div>
  );
}
