import { useState } from 'react';
import { setToken } from '../api/client';

interface TokenGateProps {
  onAuthenticated: () => void;
}

export function TokenGate({ onAuthenticated }: TokenGateProps) {
  const [value, setValue] = useState('');
  const [error, setError] = useState('');

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const token = value.trim();
    if (!token) {
      setError('Token cannot be empty');
      return;
    }
    setToken(token);
    onAuthenticated();
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

        <h2 className="text-white font-semibold text-lg mb-1">Authentication required</h2>
        <p className="text-gray-400 text-sm mb-6">
          Paste your API bearer token to access the console. The token is stored in your
          browser session only and cleared when you close this tab.
        </p>

        <form onSubmit={handleSubmit} className="flex flex-col gap-3">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">
              API Token
            </label>
            <input
              type="password"
              value={value}
              onChange={(e) => {
                setValue(e.target.value);
                setError('');
              }}
              placeholder="Paste token from secrets/api_auth_token.txt"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2.5 text-white text-sm font-mono placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:border-red-500/50"
            />
            {error && (
              <p className="mt-1.5 text-red-400 text-xs">{error}</p>
            )}
          </div>
          <button
            type="submit"
            className="w-full bg-red-600 hover:bg-red-700 text-white font-medium py-2.5 rounded-lg text-sm transition-colors mt-1"
          >
            Access Console
          </button>
        </form>

        <p className="text-gray-600 text-xs mt-4 text-center">
          Token stored in sessionStorage only — auto-cleared on tab close
        </p>
      </div>
    </div>
  );
}
