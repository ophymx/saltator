//! User-shard storage records and the state-machine command set
//! (spec.md §5.5, §6 `saltator-userserver`).
//!
//! Everything secret enters the state machine pre-hashed: passwords as
//! argon2 PHC strings, tokens as blake3 digests (spec.md §10). Hashing and
//! randomness happen at the gateway so `apply` stays deterministic.

use serde::{Deserialize, Serialize};

use saltator_shard::APP_TABLE_FIRST;

/// `user_id → Account`.
pub const T_ACCOUNT: u8 = APP_TABLE_FIRST;
/// `token_hash (32 bytes) → TokenEntry` — access and refresh tokens.
pub const T_TOKEN: u8 = APP_TABLE_FIRST + 1;
/// `user_id ++ 0x00 ++ device_id → Device`.
pub const T_DEVICE: u8 = APP_TABLE_FIRST + 2;
/// `user_id → Profile`.
pub const T_PROFILE: u8 = APP_TABLE_FIRST + 3;
/// `user_id ++ 0x00 ++ room_id ++ 0x00 ++ type → AccountDataEntry`
/// (`room_id` empty = global account data).
pub const T_ACCOUNT_DATA: u8 = APP_TABLE_FIRST + 4;
/// `user_id ++ 0x00 ++ filter_id → filter JSON`.
pub const T_FILTER: u8 = APP_TABLE_FIRST + 5;
/// `user_id ++ 0x00 ++ room_id → MembershipEntry` — the membership
/// projection over the room keyspace (spec.md §4.1, §9: eventually
/// consistent, monotonic per source shard).
pub const T_MEMBERSHIP: u8 = APP_TABLE_FIRST + 6;
/// `source (e.g. "room/0") → u64 BE` — projection cursors.
pub const T_CURSOR: u8 = APP_TABLE_FIRST + 7;
/// `alias → AliasEntry`.
pub const T_ALIAS: u8 = APP_TABLE_FIRST + 8;
/// `media_id → MediaMeta`.
pub const T_MEDIA: u8 = APP_TABLE_FIRST + 9;
/// `room_id → [1]` — rooms published to the public directory. Presence in
/// the table is the fact; the value is a placeholder.
pub const T_DIRECTORY: u8 = APP_TABLE_FIRST + 10;
/// `user_id ++ 0x00 ++ room_id → Vec<Vec<u8>>` — stripped-state events for
/// a pending invite to a room we don't host (received over federation).
/// `/sync` renders these as the invite's `invite_state`.
pub const T_INVITE_STATE: u8 = APP_TABLE_FIRST + 11;
/// `user_id ++ 0x00 ++ device_id → device_keys JSON` — a device's published
/// identity keys for E2EE (`/keys/upload`, spec.md §5.5).
pub const T_DEVICE_KEYS: u8 = APP_TABLE_FIRST + 12;
/// `user_id ++ 0x00 ++ device_id ++ 0x00 ++ key_id → one-time-key JSON`.
/// Claiming one is a Raft-serialized delete, so an OTK is never handed out
/// twice (spec.md §5.5, §9).
pub const T_ONE_TIME_KEY: u8 = APP_TABLE_FIRST + 13;
/// `user_id ++ 0x00 ++ device_id ++ 0x00 ++ seq (u64 BE) → to-device event
/// JSON` — the durable per-device to-device inbox, drained by `/sync`
/// (spec.md §5.5). `seq` is the user-shard seq at which the message was
/// queued; sync windows on it like account data.
pub const T_TO_DEVICE: u8 = APP_TABLE_FIRST + 14;
/// `seq (u64 BE) → KeyChangeEntry` — the device-list change log: one row
/// whenever a user's E2EE device list changes (identity keys published,
/// device deleted) or their room-sharing visibility changes (join/leave).
/// `/sync` and `/keys/changes` window it to compute `changed`/`left`.
/// Tiny rows, unbounded growth; pruning is a hardening brick.
pub const T_KEY_CHANGE: u8 = APP_TABLE_FIRST + 15;
/// `user_id ++ 0x00 ++ device_id ++ 0x00 ++ app_id ++ 0x00 ++ pushkey →
/// pusher JSON` — push notification targets (`/pushers`). Device-scoped:
/// a pusher dies with the session that created it (which is what makes
/// password-change logout drop other sessions' pushers).
pub const T_PUSHER: u8 = APP_TABLE_FIRST + 16;
/// `user_id ++ 0x00 ++ version (u64 BE) → BackupVersionMeta` — E2EE
/// key-backup versions (`/room_keys/version`). Versions count up per
/// user; deleted ones keep a tombstoned row so the counter never reuses
/// a version.
pub const T_BACKUP_VERSION: u8 = APP_TABLE_FIRST + 17;
/// `user_id ++ 0x00 ++ version (u64 BE) ++ 0x00 ++ room_id ++ 0x00 ++
/// session_id → KeyBackupData JSON` — the backed-up room keys.
pub const T_BACKUP_KEY: u8 = APP_TABLE_FIRST + 18;
/// `user_id ++ 0x00 ++ device_id ++ 0x00 ++ algorithm → FallbackEntry` —
/// one fallback key per device+algorithm, served by `/keys/claim` when
/// the one-time keys run dry (spec 1.2 / MSC2732). Never deleted by a
/// claim, only replaced by upload.
pub const T_FALLBACK_KEY: u8 = APP_TABLE_FIRST + 19;
/// `user_id ++ 0x00 ++ kind → raw key JSON` — cross-signing keys, kind ∈
/// `master` | `self_signing` | `user_signing`.
pub const T_CROSS_SIGNING: u8 = APP_TABLE_FIRST + 20;
/// `destination ++ 0x00 ++ seq (u64 BE) → EDU JSON` — the durable outbound
/// EDU outbox. To-device messages and device-list updates queue here (the
/// spec gives them no receiver-side recovery, so the *sender* owns
/// delivery); the federation EDU sender drains per destination with
/// retry/backoff, acking on success. Survives restarts — unlike typing/
/// presence, which stay fire-and-forget. `seq` is the user-shard seq.
pub const T_EDU_OUTBOX: u8 = APP_TABLE_FIRST + 21;
/// `origin ++ 0x00 ++ message_id → postcard(u64 ts_ms)` — federation
/// to-device dedupe: EDU `message_id`s already applied. Replicated and
/// written atomically with the inbox insert, so dedupe survives OUR
/// restart — which is exactly when a sender's redelivery arrives
/// (at-least-once, docs/design-federation-out.md decision 3).
pub const T_TO_DEVICE_SEEN: u8 = APP_TABLE_FIRST + 22;
/// `ts_ms (u64 BE) ++ origin ++ 0x00 ++ message_id → ()` — time index
/// over [`T_TO_DEVICE_SEEN`] so the horizon prune is a range delete.
pub const T_TO_DEVICE_SEEN_IDX: u8 = APP_TABLE_FIRST + 23;
/// `session_id → UiaSession` — user-interactive auth sessions
/// (docs/design-admin-identity.md slice 3).
pub const T_UIA_SESSION: u8 = APP_TABLE_FIRST + 24;
/// `created_ts (u64 BE) ++ session_id → ()` — time index over
/// [`T_UIA_SESSION`] so the expiry sweep is a bounded range scan rather
/// than a full table walk on every stage completion.
pub const T_UIA_SESSION_IDX: u8 = APP_TABLE_FIRST + 25;
/// `token → RegToken` — registration tokens.
pub const T_REG_TOKEN: u8 = APP_TABLE_FIRST + 26;
/// `auth_provider ++ 0x00 ++ external_id → user_id` — the identity link
/// table (docs/design-admin-identity.md slice 4). Uniqueness is on the
/// key: one subject at one provider maps to exactly one account.
///
/// `auth_provider` is a stable opaque key, never a display name — Synapse
/// carries a grandfathered `oidc-` prefix precisely because renaming a
/// provider would otherwise orphan every linked account.
pub const T_EXTERNAL_ID: u8 = APP_TABLE_FIRST + 27;
/// `user_id ++ 0x00 ++ auth_provider → external_id` — the reverse index
/// over [`T_EXTERNAL_ID`], so "what is this account linked to" and
/// "unlink this provider" are lookups rather than table scans. Synapse
/// bolted its equivalent on later as a background update; ours is written
/// in the same batch as the forward row, so the two cannot drift.
pub const T_EXTERNAL_ID_USER: u8 = APP_TABLE_FIRST + 28;

/// `user_id ++ 0x00 ++ rest` — user IDs cannot contain NUL.
pub(crate) fn user_key(user_id: &str, rest: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(user_id.len() + rest.len() + 1);
    k.extend_from_slice(user_id.as_bytes());
    k.push(0);
    k.extend_from_slice(rest.as_bytes());
    k
}

/// Forward link key: `auth_provider ++ 0x00 ++ external_id`. The provider
/// goes first because it is the half with a bounded vocabulary, and
/// because it is NUL-free (validated at the admin boundary) the first NUL
/// is unambiguously the separator — two different pairs cannot encode to
/// the same key.
pub(crate) fn external_key(auth_provider: &str, external_id: &str) -> Vec<u8> {
    user_key(auth_provider, external_id)
}

/// Device-scoped key: `user_id ++ 0x00 ++ device_id ++ 0x00 ++ rest`
/// (device IDs, like user IDs, cannot contain NUL).
pub(crate) fn device_scoped_key(user_id: &str, device_id: &str, rest: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(user_id.len() + device_id.len() + rest.len() + 2);
    k.extend_from_slice(user_id.as_bytes());
    k.push(0);
    k.extend_from_slice(device_id.as_bytes());
    k.push(0);
    k.extend_from_slice(rest.as_bytes());
    k
}

/// The lexicographic upper bound for a prefix scan (`[prefix, prefix_end)`):
/// increment the last non-`0xff` byte, dropping trailing `0xff`s.
pub(crate) fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    while let Some(&last) = end.last() {
        if last < 0xff {
            *end.last_mut().expect("non-empty") = last + 1;
            break;
        }
        end.pop();
    }
    end
}

/// To-device inbox key: `user_id ++ 0x00 ++ device_id ++ 0x00 ++ seq BE`.
/// Big-endian seq keeps the inbox in queue order under lexicographic scan.
pub(crate) fn to_device_key(user_id: &str, device_id: &str, seq: u64) -> Vec<u8> {
    let mut k = device_scoped_key(user_id, device_id, "");
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

/// Account-data key: `user_id ++ 0x00 ++ room_id ++ 0x00 ++ type`.
pub(crate) fn account_data_key(user_id: &str, room_id: &str, data_type: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(user_id.len() + room_id.len() + data_type.len() + 2);
    k.extend_from_slice(user_id.as_bytes());
    k.push(0);
    k.extend_from_slice(room_id.as_bytes());
    k.push(0);
    k.extend_from_slice(data_type.as_bytes());
    k
}

/// Account lifecycle (docs/design-admin-identity.md). Postcard encodes
/// the variant index, so this is append-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountState {
    Active,
    /// Reversible auth kill-switch: tokens rejected, data and rooms
    /// untouched. Nothing sets this until the lifecycle slice; the
    /// authentication check already honours it.
    Locked,
    /// Irreversible teardown: password cleared, every device deleted.
    Deactivated,
}

impl AccountState {
    /// Whether an account in this state may authenticate. Anything but
    /// `Active` is refused, so new states are closed by default.
    pub fn can_authenticate(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Argon2 PHC string; `None` for passwordless accounts (appservices,
    /// later login types). Means "no local credential" and nothing else —
    /// never infer the account's kind or state from it.
    pub password_hash: Option<String>,
    pub created_ts: u64,
    pub state: AccountState,
    /// Server administrator. Never read this at a call site: authorization
    /// resolves through one function (`CsState::is_admin`) so it can grow
    /// a token-scope arm later.
    pub admin: bool,
    /// GDPR erasure — a modifier on `Deactivated`, not a state of its own.
    pub erased: bool,
}

/// The v2 shape of [`Account`], read only by the v3 migration.
///
/// `Serialize` is derived purely so tests can mint a genuine v2 blob and
/// assert the encoding contract; nothing in the server ever writes one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AccountV2 {
    pub password_hash: Option<String>,
    pub created_ts: u64,
    pub deactivated: bool,
}

/// An in-progress user-interactive authentication.
///
/// The session is bound to the request that started it: `request_hash`
/// covers the body with `auth` removed. Without that, a client could
/// satisfy a password stage for a harmless request and replay the
/// completed session against a destructive one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiaSession {
    pub request_hash: [u8; 32],
    /// Stage types completed so far, in completion order.
    pub completed: Vec<String>,
    /// The registration token presented to the token stage, remembered
    /// because a later stage in the same flow arrives in a different
    /// request that no longer carries it.
    pub registration_token: Option<String>,
    pub created_ts: u64,
}

/// A registration token: an invite code that authorises `/register` when
/// the server is otherwise closed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegToken {
    /// `None` = unlimited.
    pub uses_allowed: Option<u64>,
    /// Registrations actually completed with this token. There is no
    /// separate "pending" count: the token is consumed inside the
    /// register command itself, so a claim cannot be stranded by an
    /// abandoned session.
    pub used: u64,
    /// `None` = never expires (ms since epoch).
    pub expiry_ts: Option<u64>,
    pub created_ts: u64,
}

impl RegToken {
    /// Whether the token may still authorise a registration at `now`.
    pub fn usable(&self, now: u64) -> bool {
        self.expiry_ts.is_none_or(|e| now < e)
            && self.uses_allowed.is_none_or(|allowed| self.used < allowed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenKind {
    Access,
    Refresh,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    pub user_id: String,
    pub device_id: String,
    pub kind: TokenKind,
    pub created_ts: u64,
    /// Access tokens issued alongside a refresh token expire (ms since
    /// epoch); plain access tokens do not.
    pub expires_ts: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub display_name: Option<String>,
    pub created_ts: u64,
    /// Hashes of the device's live tokens, so session replacement /
    /// logout can invalidate them without a table scan.
    pub access_token_hash: Option<[u8; 32]>,
    pub refresh_token_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Profile {
    pub displayname: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountDataEntry {
    /// The event `content` as raw JSON.
    pub json: Vec<u8>,
    /// User-shard seq at which this was written (sync windowing).
    pub seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipEntry {
    /// `join`, `invite`, `leave`, `ban`, `knock`.
    pub membership: String,
    pub event_id: String,
    pub sender: String,
    /// Position of the member event in its room shard.
    pub room_seq: u64,
    /// User-shard seq at which the projection recorded it.
    pub seq: u64,
    /// The user forgot this room (`/forget`): history reads are denied and
    /// the room is dropped from fresh syncs. Any later membership change
    /// overwrites the row, clearing the flag.
    pub forgotten: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasEntry {
    pub room_id: String,
    pub creator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaMeta {
    pub owner: String,
    pub content_type: Option<String>,
    pub filename: Option<String>,
    pub size: u64,
    pub created_ts: u64,
    /// Async upload (MSC2246): the ID is reserved but the content hasn't
    /// arrived yet.
    #[serde(default)]
    pub pending: bool,
    /// The content-addressed blob this media ID points at. `None` means
    /// the media ID *is* the blob ID (async uploads, URL-preview caches,
    /// and media stored before upload IDs became unique per upload).
    #[serde(default)]
    pub blob: Option<String>,
}

/// One membership change extracted from the room change stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipChange {
    pub user_id: String,
    pub room_id: String,
    pub membership: String,
    pub event_id: String,
    pub sender: String,
    pub room_seq: u64,
}

/// A new session's credentials, pre-hashed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCmd {
    pub user_id: String,
    pub device_id: String,
    pub display_name: Option<String>,
    pub token_hash: [u8; 32],
    pub refresh_hash: Option<[u8; 32]>,
    pub expires_ts: Option<u64>,
    pub ts: u64,
}

/// Commands applied to the user state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserCommand {
    /// Reserve a username and (unless `inhibit_login`) create the first
    /// session atomically (linearizable, spec.md §9).
    Register {
        user_id: String,
        password_hash: Option<String>,
        ts: u64,
        session: Option<SessionCmd>,
    },
    /// Log in: create a session on an existing account. Replaces the
    /// device's previous tokens if the device already exists.
    CreateSession(SessionCmd),
    /// Rotate a session's tokens (`/refresh`). `old_refresh_hash` must be
    /// the device's current refresh token.
    RefreshSession {
        old_refresh_hash: [u8; 32],
        session: SessionCmd,
    },
    /// Invalidate one device and its tokens (`/logout`, device delete).
    DeleteDevice {
        user_id: String,
        device_id: String,
    },
    /// Invalidate every device and token of a user (`/logout/all`).
    DeleteAllDevices {
        user_id: String,
    },
    SetDeviceName {
        user_id: String,
        device_id: String,
        display_name: Option<String>,
    },
    /// `None` = leave unchanged; `Some(None)` = unset.
    SetProfile {
        user_id: String,
        displayname: Option<Option<String>>,
        avatar_url: Option<Option<String>>,
    },
    PutAccountData {
        user_id: String,
        /// Empty = global.
        room_id: String,
        data_type: String,
        json: Vec<u8>,
    },
    PutFilter {
        user_id: String,
        filter_id: String,
        json: Vec<u8>,
    },
    /// Projection batch from a room shard: monotonic per source, replayed
    /// idempotently after restart (spec.md §9).
    ApplyRoomChanges {
        source: String,
        upto_seq: u64,
        changes: Vec<MembershipChange>,
    },
    CreateAlias {
        alias: String,
        room_id: String,
        creator: String,
    },
    DeleteAlias {
        alias: String,
    },
    PutMedia {
        media_id: String,
        meta: MediaMeta,
    },
    /// Publish to / withdraw from the public room directory.
    SetRoomVisibility {
        room_id: String,
        public: bool,
    },
    /// Record a pending invite to a remote room (received over
    /// federation). Writes an `invite` membership plus its stripped state
    /// so `/sync` surfaces it, and wakes the user's sync.
    RecordRemoteInvite {
        user_id: String,
        room_id: String,
        sender: String,
        event_id: String,
        /// Stripped-state event JSON, one entry per event.
        stripped_state: Vec<Vec<u8>>,
    },
    /// Record a pending knock on a remote room (received back over the
    /// `/send_knock` response). Writes a `knock` membership plus the
    /// stripped `knock_room_state` so `/sync` surfaces it, and wakes the
    /// user's sync.
    RecordRemoteKnock {
        user_id: String,
        room_id: String,
        sender: String,
        event_id: String,
        /// Stripped-state event JSON, one entry per event.
        stripped_state: Vec<Vec<u8>>,
    },
    /// Reject/leave a remote room: set `leave` membership and clear the
    /// pending-invite stripped state.
    RecordRemoteLeave {
        user_id: String,
        room_id: String,
    },
    /// Mark a departed room as forgotten (`/forget`). No-op when the user
    /// has no membership row; the flag survives until a membership change
    /// rewrites the row.
    ForgetRoom {
        user_id: String,
        room_id: String,
    },
    /// Publish a device's E2EE keys: its identity `device_keys` (when
    /// present) and any new one-time keys. Returns the resulting one-time-key
    /// counts per algorithm (`/keys/upload`).
    UploadKeys {
        user_id: String,
        device_id: String,
        /// Raw JSON of the signed `device_keys` object; `None` to leave the
        /// stored identity keys unchanged.
        device_keys: Option<Vec<u8>>,
        /// `(key_id, raw JSON)` one-time keys to add, e.g.
        /// `("signed_curve25519:AAAAAQ", {...})`.
        one_time_keys: Vec<(String, Vec<u8>)>,
        /// `(key_id, raw JSON)` fallback keys — one kept per algorithm; a
        /// changed key replaces the old one and resets its used flag.
        fallback_keys: Vec<(String, Vec<u8>)>,
    },
    /// Claim one one-time key per requested `(user, device, algorithm)`,
    /// removing it so it is never claimed twice (`/keys/claim`).
    ClaimKeys {
        claims: Vec<ClaimRequest>,
    },
    /// Store the user's cross-signing identity
    /// (`/keys/device_signing/upload`): each present key replaces the
    /// stored one. Logs a key change — peers must re-query.
    SetCrossSigningKeys {
        user_id: String,
        master: Option<Vec<u8>>,
        self_signing: Option<Vec<u8>>,
        user_signing: Option<Vec<u8>>,
    },
    /// Merge uploaded signatures (`/keys/signatures/upload`) into the
    /// user's own stored device keys or cross-signing keys. Each target is
    /// `(device id or cross-signing public key id, signatures object)`.
    AddSignatures {
        user_id: String,
        targets: Vec<(String, Vec<u8>)>,
    },
    /// Queue to-device events into recipients' inboxes (`/sendToDevice`,
    /// later the `m.direct_to_device` federation EDU). Wakes each
    /// recipient's sync.
    SendToDevice {
        messages: Vec<ToDeviceMessage>,
    },
    /// Drop delivered to-device messages: everything at inbox seq
    /// `<= up_to` for the device, once a sync past them acknowledged
    /// delivery.
    AckToDevice {
        user_id: String,
        device_id: String,
        up_to: u64,
    },
    /// Log a device-list change without touching key material — a remote
    /// user's `m.device_list_update` EDU, so local syncs surface them in
    /// `device_lists.changed` and clients re-query over federation.
    RecordKeyChange {
        user_id: String,
    },
    /// Queue outbound federation EDUs into the durable per-destination
    /// outbox (to-device messages, device-list updates). The EDU sender
    /// drains and acks them; queueing through the state machine makes the
    /// pending set survive restarts and replicate with the shard.
    QueueOutboundEdus {
        entries: Vec<OutboundEdu>,
    },
    /// Drop delivered outbox EDUs: everything at outbox seq `<= up_to`
    /// for the destination, once a `/send` transaction carrying them
    /// succeeded.
    AckOutboundEdus {
        destination: String,
        up_to: u64,
    },
    /// Replace the account password (`/account/password`) and, when
    /// `logout_others`, delete every device except `keep_device` — the
    /// session that made the change survives.
    ChangePassword {
        user_id: String,
        password_hash: String,
        logout_others: bool,
        keep_device: String,
    },
    /// Deactivate the account (`/account/deactivate`): permanent — blocks
    /// future logins and deletes every device and session.
    Deactivate {
        user_id: String,
    },
    /// Create/replace (`json` present) or delete (`None`) the pusher
    /// identified by `(app_id, pushkey)`. A replace moves the pusher to
    /// `device_id`'s scope regardless of which session created it.
    SetPusher {
        user_id: String,
        device_id: String,
        app_id: String,
        pushkey: String,
        json: Option<Vec<u8>>,
    },
    /// Create the next key-backup version (`POST /room_keys/version`).
    /// Returns [`UserResponse::BackupVersion`].
    CreateBackupVersion {
        user_id: String,
        algorithm: String,
        /// Raw `auth_data` JSON.
        auth_data: Vec<u8>,
    },
    /// Update a version's algorithm/auth_data in place
    /// (`PUT /room_keys/version/{version}`).
    UpdateBackupVersion {
        user_id: String,
        version: u64,
        algorithm: String,
        auth_data: Vec<u8>,
    },
    /// Tombstone a version and drop its keys
    /// (`DELETE /room_keys/version/{version}`).
    DeleteBackupVersion {
        user_id: String,
        version: u64,
    },
    /// Store room keys into a backup version, applying the spec's replace
    /// rules per session (verified wins; then lower first_message_index;
    /// then lower forwarded_count). Returns
    /// [`UserResponse::BackupStatus`].
    PutBackupKeys {
        user_id: String,
        version: u64,
        /// `(room_id, session_id, KeyBackupData JSON)`.
        keys: Vec<(String, String, Vec<u8>)>,
    },
    /// Delete backed-up keys: everything in the version, one room's, or
    /// one session's. Returns [`UserResponse::BackupStatus`].
    DeleteBackupKeys {
        user_id: String,
        version: u64,
        room_id: Option<String>,
        session_id: Option<String>,
    },
    /// Federation to-device delivery with `message_id` dedupe
    /// (append-only variant; the plain `SendToDevice` remains for local
    /// sends, which dedupe via client txn ids). If `(origin,
    /// message_id)` was already applied, the whole EDU's messages are
    /// dropped — the redelivered duplicate a client must never see.
    /// `ts_ms` is stamped by the receiving node at propose time and
    /// drives the deterministic horizon prune.
    SendToDeviceDeduped {
        origin: String,
        message_id: String,
        ts_ms: u64,
        messages: Vec<ToDeviceMessage>,
    },
    /// Admin: lock or unlock an account (docs/design-admin-identity.md).
    /// Reversible and non-destructive — sessions stay on disk and start
    /// working again on unlock, because the refusal lives in the
    /// authentication check rather than in a teardown. Refuses to touch a
    /// `Deactivated` account: that state is terminal.
    SetLocked {
        user_id: String,
        locked: bool,
    },
    /// Admin: grant or revoke the server-administrator flag.
    SetAdmin {
        user_id: String,
        admin: bool,
    },
    /// Admin password reset. Distinct from [`UserCommand::ChangePassword`]
    /// because there is no device to keep: the administrator is not on one
    /// of the target's sessions.
    AdminSetPassword {
        user_id: String,
        password_hash: String,
        logout_devices: bool,
    },
    /// Admin: mark an account erased and clear its profile. Only the
    /// marker and the profile — message redaction is not implemented, so
    /// this is not yet a complete erasure.
    SetErased {
        user_id: String,
    },
    /// Record one completed UIA stage, creating the session if this is the
    /// first (a single-stage flow legitimately completes in one request,
    /// with no session id from the client).
    ///
    /// `now_ts` also drives the expiry sweep: apply must not read a clock,
    /// so the gateway stamps the time and the prune happens here.
    CompleteUiaStage {
        session_id: String,
        request_hash: [u8; 32],
        stage: String,
        /// Set when the stage being completed is the registration-token
        /// one; remembered on the session for the eventual register.
        registration_token: Option<String>,
        now_ts: u64,
        /// Sessions created before this are swept in the same batch.
        expire_before_ts: u64,
    },
    /// Register, atomically consuming a registration token when one is
    /// given. Supersedes [`UserCommand::Register`], which stays for log
    /// replay: consuming the token in the same batch as the username
    /// reservation is what makes a one-use token actually one-use under
    /// concurrent registrations.
    RegisterWithToken {
        user_id: String,
        password_hash: Option<String>,
        ts: u64,
        session: Option<SessionCmd>,
        registration_token: Option<String>,
    },
    CreateRegistrationToken {
        token: String,
        uses_allowed: Option<u64>,
        expiry_ts: Option<u64>,
        ts: u64,
    },
    DeleteRegistrationToken {
        token: String,
    },
    /// Link an account to its subject at an external identity provider
    /// (docs/design-admin-identity.md slice 4). Writes both index rows in
    /// one batch.
    ///
    /// Deliberately writable before any provider is configured: an
    /// operator pre-links accounts, *then* turns the IdP on, which is the
    /// migration path that avoids a flag day. Nothing reads these rows
    /// until the OIDC slice.
    ///
    /// Relinking the same `(user, provider)` to a new subject replaces the
    /// link, forward row included. Claiming a subject another account
    /// already holds is refused ([`UserResponse::ExternalIdInUse`]).
    LinkExternalId {
        user_id: String,
        auth_provider: String,
        external_id: String,
    },
    /// Drop the link between an account and one provider.
    UnlinkExternalId {
        user_id: String,
        auth_provider: String,
    },
}

/// A stored one-time key ([`T_ONE_TIME_KEY`]) with its upload slot:
/// claims hand keys out in upload order (MSC4225), not key-ID order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtkEntry {
    pub order: u64,
    /// Raw one-time-key JSON.
    pub json: Vec<u8>,
}

/// A stored fallback key ([`T_FALLBACK_KEY`]): the device's key of last
/// resort for one algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackEntry {
    /// Full key id (`algorithm:id`).
    pub key_id: String,
    /// Raw key JSON.
    pub json: Vec<u8>,
    /// Set once a claim has served it; cleared when a new key replaces
    /// this one (feeds sync's `device_unused_fallback_key_types`).
    pub used: bool,
}

/// One key-backup version's metadata ([`T_BACKUP_VERSION`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupVersionMeta {
    pub algorithm: String,
    /// Raw `auth_data` JSON.
    pub auth_data: Vec<u8>,
    /// Stored session count (kept in step with [`T_BACKUP_KEY`] rows).
    pub count: u64,
    /// Bumped on every change to the version's keys.
    pub etag: u64,
    /// Deleted versions stay tombstoned so version numbers never recur.
    pub deleted: bool,
}

/// One to-device message: the full event JSON (`type`, `sender`,
/// `content`) bound for a recipient device. A `device_id` of `"*"` fans
/// out to every device the user has registered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToDeviceMessage {
    pub user_id: String,
    pub device_id: String,
    pub json: Vec<u8>,
}

/// One outbound federation EDU headed for the durable outbox
/// ([`T_EDU_OUTBOX`]): the complete EDU object (`edu_type` + `content`)
/// as raw JSON, and the server it must reach.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundEdu {
    pub destination: String,
    pub json: Vec<u8>,
}

/// One row of the device-list change log ([`T_KEY_CHANGE`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyChangeEntry {
    pub user_id: String,
    /// `None` = the device list itself changed (keys published, device
    /// deleted). `Some((room_id, joined))` = a visibility change: the user
    /// joined (`true`) or left (`false`) `room_id`, so peers in that room
    /// start or stop tracking their devices.
    pub membership: Option<(String, bool)>,
}

/// One `(user, device, algorithm)` one-time-key claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRequest {
    pub user_id: String,
    pub device_id: String,
    pub algorithm: String,
}

/// A one-time key handed out by a claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimedKey {
    pub user_id: String,
    pub device_id: String,
    pub key_id: String,
    /// Raw JSON of the one-time-key object.
    pub key_json: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserResponse {
    Ok,
    /// Username already reserved.
    UserExists,
    /// Alias already points at a room.
    AliasExists,
    /// Refresh token unknown or superseded.
    InvalidGrant,
    /// Target (account, device, alias) not found.
    NotFound,
    /// Projection batch at or behind the stored cursor; nothing applied.
    Stale,
    /// One-time-key counts per algorithm after an `UploadKeys`.
    OneTimeKeyCounts(std::collections::BTreeMap<String, u64>),
    /// The keys handed out by a `ClaimKeys`.
    ClaimedKeys(Vec<ClaimedKey>),
    /// The version number minted by a `CreateBackupVersion`.
    BackupVersion(u64),
    /// A backup version's key count and etag after a keys mutation.
    BackupStatus {
        count: u64,
        etag: u64,
    },
    /// The account exists but its lifecycle state forbids the operation
    /// (unlocking a deactivated account, say). Distinct from `NotFound`,
    /// which would tell an operator the wrong thing.
    ///
    /// Appended, like every variant here: responses cross nodes via the
    /// leader-forwarding `Propose` RPC, and postcard encodes the variant
    /// index — inserting one mid-enum would make a rolling upgrade decode
    /// every later variant as its neighbour.
    InvalidState,
    /// A UIA session exists but was started for a different request, so
    /// its completed stages must not be honoured here.
    UiaRequestMismatch,
    /// The stages completed so far on this session, and the registration
    /// token it remembers (if any).
    UiaCompleted {
        completed: Vec<String>,
        registration_token: Option<String>,
    },
    /// The registration token is unknown, expired, or exhausted.
    InvalidToken,
    /// A registration token with this value already exists.
    TokenExists,
    /// The `(auth_provider, external_id)` pair is already linked to a
    /// different account. Carries the owner so an operator is told which
    /// one without a second lookup — they are already privileged enough
    /// to enumerate every account.
    ExternalIdInUse(String),
}

/// Change-stream payload of the user shard: something about `user_id`
/// changed that `/sync` may need to report (account data, membership).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserChangePayload {
    User { user_id: String },
}
