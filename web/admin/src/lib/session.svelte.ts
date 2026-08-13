// Who is logged in, as reactive state.
//
// The token itself lives in sessionStorage (see api.ts); this is the
// view-model around it.

import * as api from './api';

export const session = $state({
  token: api.storedToken(),
  userId: null as string | null,
  /// Set when the server answered 403 to an admin call: the account is
  /// real but not an administrator, which deserves a clear page rather
  /// than a broken console.
  forbidden: false,
});

export async function signIn(user: string, password: string): Promise<void> {
  const result = await api.login(user, password);
  api.storeToken(result.access_token);
  session.token = result.access_token;
  session.userId = result.user_id;
  session.forbidden = false;
}

/// Recover who we are after a reload: the token survives in
/// sessionStorage but the identity behind it does not.
export async function restore(): Promise<void> {
  if (session.token === null || session.userId !== null) return;
  try {
    session.userId = (await api.whoami()).user_id;
  } catch (e) {
    handle(e);
  }
}

export async function signOut(): Promise<void> {
  // Best effort: the local session is dropped either way, so a server
  // that refuses the logout must not strand the operator in the console.
  try {
    await api.logout();
  } catch {
    /* ignore */
  }
  api.storeToken(null);
  session.token = null;
  session.userId = null;
  session.forbidden = false;
}

/// Route an API failure to the right global state. Returns the message to
/// show inline, or `null` when the failure has been handled globally (the
/// session ended, or this account is not an administrator).
export function handle(error: unknown): string | null {
  if (error instanceof api.ApiError) {
    if (error.status === 401) {
      api.storeToken(null);
      session.token = null;
      return null;
    }
    if (error.status === 403 && error.errcode === 'M_FORBIDDEN') {
      session.forbidden = true;
      return null;
    }
    return error.message;
  }
  return error instanceof Error ? error.message : String(error);
}
