//! User-shard storage records and the state-machine command set
//! (spec.md §5.5, §6 `saltator-userserver`).
//!
//! Everything secret enters the state machine pre-hashed: passwords as
//! argon2 PHC strings, tokens as blake3 digests (spec.md §10). Hashing and
//! randomness happen at the gateway so `apply` stays deterministic.

use serde::{Deserialize, Serialize};

use saltator_shard::APP_TABLE_MIN;

/// `user_id → Account`.
pub const T_ACCOUNT: u8 = APP_TABLE_MIN;
/// `token_hash (32 bytes) → TokenEntry` — access and refresh tokens.
pub const T_TOKEN: u8 = APP_TABLE_MIN + 1;
/// `user_id ++ 0x00 ++ device_id → Device`.
pub const T_DEVICE: u8 = APP_TABLE_MIN + 2;
/// `user_id → Profile`.
pub const T_PROFILE: u8 = APP_TABLE_MIN + 3;
/// `user_id ++ 0x00 ++ room_id ++ 0x00 ++ type → AccountDataEntry`
/// (`room_id` empty = global account data).
pub const T_ACCOUNT_DATA: u8 = APP_TABLE_MIN + 4;
/// `user_id ++ 0x00 ++ filter_id → filter JSON`.
pub const T_FILTER: u8 = APP_TABLE_MIN + 5;
/// `user_id ++ 0x00 ++ room_id → MembershipEntry` — the membership
/// projection over the room keyspace (spec.md §4.1, §9: eventually
/// consistent, monotonic per source shard).
pub const T_MEMBERSHIP: u8 = APP_TABLE_MIN + 6;
/// `source (e.g. "room/0") → u64 BE` — projection cursors.
pub const T_CURSOR: u8 = APP_TABLE_MIN + 7;
/// `alias → AliasEntry`.
pub const T_ALIAS: u8 = APP_TABLE_MIN + 8;
/// `media_id → MediaMeta`.
pub const T_MEDIA: u8 = APP_TABLE_MIN + 9;
/// `room_id → [1]` — rooms published to the public directory. Presence in
/// the table is the fact; the value is a placeholder.
pub const T_DIRECTORY: u8 = APP_TABLE_MIN + 10;
/// `user_id ++ 0x00 ++ room_id → Vec<Vec<u8>>` — stripped-state events for
/// a pending invite to a room we don't host (received over federation).
/// `/sync` renders these as the invite's `invite_state`.
pub const T_INVITE_STATE: u8 = APP_TABLE_MIN + 11;

/// `user_id ++ 0x00 ++ rest` — user IDs cannot contain NUL.
pub(crate) fn user_key(user_id: &str, rest: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(user_id.len() + rest.len() + 1);
    k.extend_from_slice(user_id.as_bytes());
    k.push(0);
    k.extend_from_slice(rest.as_bytes());
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Argon2 PHC string; `None` for passwordless accounts (appservices,
    /// later login types).
    pub password_hash: Option<String>,
    pub created_ts: u64,
    pub deactivated: bool,
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
    /// Reject/leave a remote room: set `leave` membership and clear the
    /// pending-invite stripped state.
    RecordRemoteLeave {
        user_id: String,
        room_id: String,
    },
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
}

/// Change-stream payload of the user shard: something about `user_id`
/// changed that `/sync` may need to report (account data, membership).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserChangePayload {
    User { user_id: String },
}
