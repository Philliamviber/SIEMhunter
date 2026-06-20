import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

// Mock the client login() so we control success/failure without a network call.
const mockLogin = vi.fn();
vi.mock('../../api/client', () => ({
  login: (u: string, p: string) => mockLogin(u, p),
  // LoginGate imports ApiClientError for instanceof checks.
  ApiClientError: class ApiClientError extends Error {
    status: number;
    code: string;
    constructor(status: number, code: string, message: string) {
      super(message);
      this.status = status;
      this.code = code;
    }
  },
}));

import { LoginGate } from '../LoginGate';

describe('LoginGate', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders username and password fields and no token field', () => {
    render(<LoginGate onAuthenticated={() => {}} />);
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    // No "API Token" paste field anymore (C7).
    expect(screen.queryByText(/api token/i)).not.toBeInTheDocument();
  });

  it('submits username and password and calls onAuthenticated on success', async () => {
    mockLogin.mockResolvedValueOnce({
      username: 'admin',
      csrf_token: 'csrf123',
      expires_at: '2026-06-20T20:00:00Z',
    });
    const onAuth = vi.fn();
    render(<LoginGate onAuthenticated={onAuth} />);

    await userEvent.type(screen.getByLabelText(/username/i), 'admin');
    await userEvent.type(screen.getByLabelText(/password/i), 'hunter2pw');
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));

    expect(mockLogin).toHaveBeenCalledWith('admin', 'hunter2pw');
    expect(onAuth).toHaveBeenCalledTimes(1);
  });

  it('shows an error and does not authenticate on failed login', async () => {
    const { ApiClientError } = await import('../../api/client');
    mockLogin.mockRejectedValueOnce(
      new (ApiClientError as unknown as typeof Error & {
        new (s: number, c: string, m: string): Error;
      })(401, 'AUTH_FAILED', 'Invalid username or password'),
    );
    const onAuth = vi.fn();
    render(<LoginGate onAuthenticated={onAuth} />);

    await userEvent.type(screen.getByLabelText(/username/i), 'admin');
    await userEvent.type(screen.getByLabelText(/password/i), 'wrong');
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/invalid username or password/i);
    expect(onAuth).not.toHaveBeenCalled();
  });

  it('does not submit when fields are empty', async () => {
    render(<LoginGate onAuthenticated={() => {}} />);
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));
    expect(mockLogin).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent(/required/i);
  });
});
