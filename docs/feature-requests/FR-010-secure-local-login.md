# FR #10 — Replace paste-the-token TokenGate with a secure local username/password login gate

**Priority:** P1 · **Size:** L · **Labels:** security, auth, ux, enhancement

## Problem / motivation
Current auth (`TokenGate.tsx` + `client.ts`) requires the analyst to paste a long-lived
API bearer token (read from `secrets/api_auth_token.txt`) into a password field; it is
stored in `sessionStorage` and sent as `Authorization: Bearer`. Problems:

- There is no real login — anyone with the shared static token has full access. The token
  is a file on disk, copy-pasted around, never rotated, and identical for every analyst
  (no per-user identity, no audit attribution).
- There is **no logout** anywhere in the app. `clearToken()` exists in `client.ts` but is
  never called by any component.
- `sessionStorage` is readable by any injected script and persists for the whole tab
  lifetime with no idle timeout.
- For a SIEM, lack of per-analyst identity undermines audit and accountability.

## Proposed solution
Add a genuine local login gate in front of the entire SPA. It does not need enterprise
SSO — this is a self-hosted tool — but it must be real security, not theater:

- Server stores credentials as a salted hash (**argon2id** preferred, bcrypt acceptable).
  No plaintext, ever, anywhere (config, logs, responses).
- Login endpoint exchanges username+password for a short-lived, server-signed session
  (HttpOnly + Secure + SameSite=Strict cookie preferred; if a bearer token is retained for
  the existing API client, it must be short-lived with refresh).
- Failed-attempt rate limiting and temporary lockout (exponential backoff / lock after N
  fails per username+IP), enforced server-side.
- `TokenGate` is replaced by a `LoginGate` rendered before any console route (same
  outside-Router placement `App.tsx` already uses).
- Explicit **Logout** control in the sidebar/header that clears the session both client-
  and server-side.
- Idle/session timeout that returns the user to login.

## Acceptance criteria
1. Given no valid session, when I visit any route (including deep links like
   `/incidents/abc`), then I see only the login screen — no console chrome or data renders.
2. Given valid username+password, when I submit, then the server verifies against a stored
   argon2id/bcrypt hash and issues a signed, expiring session; the raw password is never
   persisted client-side.
3. Given an invalid password, when I submit, then I get a generic "Invalid username or
   password" (no user-enumeration hint), and the attempt is counted.
4. Given N consecutive failures (configurable, default 5) for an account, when I try again,
   then I am locked out for a cooldown window and told to wait; lockout is enforced
   server-side, not just in the UI.
5. Credentials/hashes never appear in API responses, logs, or client storage; grepping the
   bundle and network tab shows no plaintext password.
6. Given I am logged in, when I click Logout, then the session is invalidated server-side,
   client storage/cookie is cleared, and I am returned to login; the back button does not
   restore the console.
7. Given I am idle past the configured timeout, when the timer elapses, then I am logged
   out and must re-authenticate.
8. Given a valid session, when the SPA calls the API, then requests carry the session
   credential automatically and a 401 redirects to login (not a silent failure).
9. First-run/bootstrap: there is a documented, secure way to set the initial admin
   credential (env-seeded one-time setup or CLI), **not** a default password baked into the
   image.

## Notes
Pairs with FR #23 (route 401s to login) and FR #19 (per-analyst note attribution depends
on the identity this introduces).
