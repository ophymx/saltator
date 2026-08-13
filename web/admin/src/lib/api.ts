// The admin API client.
//
// The console is "just a Matrix client": it logs in through
// `/_matrix/client/v3/login`, holds the bearer token, and calls
// `/_saltator/admin/v1`. There is no admin-specific auth mechanism — a
// dividend of the API design making admin a property of an ordinary
// account, resolved through one function server-side.
//
// Two rules this file exists to keep:
//   * the token travels in an `Authorization` header, never in the
//     deprecated `?access_token=` query form, which would leak through
//     logs and `Referer`;
//   * it lives in sessionStorage, not localStorage, so an admin token
//     does not outlive the tab.

const ADMIN = '/_saltator/admin/v1';
const CLIENT = '/_matrix/client/v3';
const TOKEN_KEY = 'saltator.admin.token';

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly errcode: string,
    message: string,
  ) {
    super(message);
  }
}

export function storedToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function storeToken(token: string | null): void {
  if (token === null) sessionStorage.removeItem(TOKEN_KEY);
  else sessionStorage.setItem(TOKEN_KEY, token);
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  auth = true,
): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (auth) {
    const token = storedToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
  }
  const resp = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    // No cookies anywhere in this app, so there is no CSRF surface.
    credentials: 'omit',
  });
  const text = await resp.text();
  const data: unknown = text ? JSON.parse(text) : null;
  if (!resp.ok) {
    const err = (data ?? {}) as { errcode?: string; error?: string };
    throw new ApiError(
      resp.status,
      err.errcode ?? 'M_UNKNOWN',
      err.error ?? `${method} ${path} failed with ${resp.status}`,
    );
  }
  return data as T;
}

// -- session --------------------------------------------------------------

export interface LoginResult {
  user_id: string;
  access_token: string;
}

export function login(user: string, password: string): Promise<LoginResult> {
  return request<LoginResult>(
    'POST',
    `${CLIENT}/login`,
    {
      type: 'm.login.password',
      identifier: { type: 'm.id.user', user },
      password,
      initial_device_display_name: 'saltator admin console',
    },
    false,
  );
}

export function whoami(): Promise<{ user_id: string }> {
  return request<{ user_id: string }>('GET', `${CLIENT}/account/whoami`);
}

export function logout(): Promise<unknown> {
  return request('POST', `${CLIENT}/logout`, {});
}

// -- accounts -------------------------------------------------------------

export type AccountState = 'active' | 'locked' | 'deactivated';

export interface UserSummary {
  user_id: string;
  displayname: string | null;
  admin: boolean;
  state: AccountState;
  erased: boolean;
  created_ts: number;
}

export interface DeviceSummary {
  device_id: string;
  display_name: string | null;
  created_ts: number;
}

export interface ExternalId {
  auth_provider: string;
  external_id: string;
}

export interface UserDetail extends UserSummary {
  avatar_url: string | null;
  has_password: boolean;
  devices: DeviceSummary[];
  external_ids: ExternalId[];
}

export interface UserList {
  users: UserSummary[];
  next_from?: string;
}

export function listUsers(from: string | null, limit: number): Promise<UserList> {
  const q = new URLSearchParams({ limit: String(limit) });
  if (from) q.set('from', from);
  return request<UserList>('GET', `${ADMIN}/users?${q}`);
}

const user = (id: string) => `${ADMIN}/users/${encodeURIComponent(id)}`;

export function getUser(id: string): Promise<UserDetail> {
  return request<UserDetail>('GET', user(id));
}

export function setLocked(id: string, locked: boolean): Promise<UserDetail> {
  return request<UserDetail>('POST', `${user(id)}/${locked ? 'lock' : 'unlock'}`);
}

export function deactivate(id: string, erase: boolean): Promise<UserDetail> {
  return request<UserDetail>('POST', `${user(id)}/deactivate`, { erase });
}

export function resetPassword(
  id: string,
  new_password: string,
  logout_devices: boolean,
): Promise<UserDetail> {
  return request<UserDetail>('POST', `${user(id)}/reset_password`, {
    new_password,
    logout_devices,
  });
}

export function setAdmin(id: string, admin: boolean): Promise<UserDetail> {
  return request<UserDetail>('PUT', `${user(id)}/admin`, { admin });
}

export function deleteDevice(id: string, device?: string): Promise<UserDetail> {
  const path = device
    ? `${user(id)}/devices/${encodeURIComponent(device)}`
    : `${user(id)}/devices`;
  return request<UserDetail>('DELETE', path);
}

export function linkExternalId(
  id: string,
  provider: string,
  external_id: string,
): Promise<UserDetail> {
  return request<UserDetail>(
    'PUT',
    `${user(id)}/external_ids/${encodeURIComponent(provider)}`,
    { external_id },
  );
}

export function unlinkExternalId(id: string, provider: string): Promise<UserDetail> {
  return request<UserDetail>(
    'DELETE',
    `${user(id)}/external_ids/${encodeURIComponent(provider)}`,
  );
}

export interface NoticeSent {
  room_id: string;
  event_id: string;
}

export function sendNotice(id: string, body: string): Promise<NoticeSent> {
  return request<NoticeSent>('POST', `${user(id)}/notice`, {
    content: { msgtype: 'm.text', body },
  });
}

// -- registration tokens --------------------------------------------------

export interface RegToken {
  token: string;
  uses_allowed: number | null;
  used: number;
  expiry_ts: number | null;
  created_ts: number;
  valid: boolean;
}

export function listTokens(): Promise<{ registration_tokens: RegToken[] }> {
  return request('GET', `${ADMIN}/registration_tokens`);
}

export function createToken(body: {
  token?: string;
  uses_allowed?: number;
  expiry_ts?: number;
}): Promise<RegToken> {
  return request<RegToken>('POST', `${ADMIN}/registration_tokens`, body);
}

export function deleteToken(token: string): Promise<unknown> {
  return request('DELETE', `${ADMIN}/registration_tokens/${encodeURIComponent(token)}`);
}

// -- rooms ----------------------------------------------------------------

export interface BlockInfo {
  by: string;
  ts: number;
}

export interface RoomRow {
  room_id: string;
  name: string | null;
  canonical_alias: string | null;
  version: string;
  join_rule: string;
  joined_members: number;
  local_joined_members: number;
  is_space: boolean;
  blocked?: BlockInfo;
}

export interface RoomDetail extends RoomRow {
  topic: string | null;
  avatar_url: string | null;
  creator: string | null;
  world_readable: boolean;
  local_members: string[];
  local_members_truncated: boolean;
}

export interface RoomList {
  rooms: RoomRow[];
  next_from?: string;
}

export interface BlockedRoom {
  room_id: string;
  by: string;
  ts: number;
  hosted: boolean;
}

export interface ShutdownReport {
  room_id: string;
  kicked: string[];
  failed: { user_id: string; error: string }[];
  blocked: boolean;
}

export function listRooms(from: string | null, limit: number): Promise<RoomList> {
  const q = new URLSearchParams({ limit: String(limit) });
  if (from) q.set('from', from);
  return request<RoomList>('GET', `${ADMIN}/rooms?${q}`);
}

export function getRoom(id: string): Promise<RoomDetail> {
  return request<RoomDetail>('GET', `${ADMIN}/rooms/${encodeURIComponent(id)}`);
}

export function shutdownRoom(
  id: string,
  block: boolean,
  reason: string | null,
): Promise<ShutdownReport> {
  return request<ShutdownReport>('DELETE', `${ADMIN}/rooms/${encodeURIComponent(id)}`, {
    block,
    reason,
  });
}

export function setRoomBlocked(id: string, blocked: boolean): Promise<unknown> {
  return request('PUT', `${ADMIN}/rooms/${encodeURIComponent(id)}/block`, { blocked });
}

export function listBlockedRooms(): Promise<{ blocked_rooms: BlockedRoom[] }> {
  return request('GET', `${ADMIN}/blocked_rooms`);
}

// -- cluster --------------------------------------------------------------

export interface ClusterNode {
  node_id: number;
  advertise_addr: string;
  status: 'active' | 'draining';
  groups: string[];
  metadata_voter: boolean;
}

export interface NodeList {
  view_from: number;
  leader: number | null;
  nodes: ClusterNode[];
}

export function listNodes(): Promise<NodeList> {
  return request<NodeList>('GET', `${ADMIN}/cluster/nodes`);
}

export function drainNode(id: number, drain: boolean): Promise<NodeList> {
  return request<NodeList>(
    'POST',
    `${ADMIN}/cluster/nodes/${id}/${drain ? 'drain' : 'undrain'}`,
  );
}

export function removeNode(id: number): Promise<NodeList> {
  return request<NodeList>('DELETE', `${ADMIN}/cluster/nodes/${id}`);
}
