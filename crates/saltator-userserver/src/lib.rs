//! The user server: accounts, sessions, profiles, account data, aliases,
//! media metadata, and the membership projection — the user keyspace
//! state machine on the generic shard runtime (spec.md §5.5, §6).
//!
//! Secrets never enter the state machine raw: passwords are argon2
//! PHC strings, tokens random 256-bit values stored as blake3 hashes
//! (spec.md §10). All hashing/randomness happens here at the gateway
//! layer so the deterministic apply only ever sees digests.

mod machine;
mod types;

use std::sync::Arc;
use std::time::Duration;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::Engine as _;
use openraft::network::RaftNetworkFactory;
use rand::RngCore;
use ruma::{OwnedServerName, OwnedUserId, UserId};
use tokio::sync::broadcast;

use saltator_roomserver::{RoomServer, SeqEntry};
use saltator_shard::{ChangeRecord, NodeId, ShardHandle, ShardId, ShardRegistry, TypeConfig};
use saltator_store::Keyspace;

pub use machine::{UserApp, UserStore};
pub use types::{
    Account, AccountDataEntry, AliasEntry, BackupVersionMeta, ClaimRequest, ClaimedKey, Device,
    KeyChangeEntry, MediaMeta, MembershipChange, MembershipEntry, OutboundEdu, Profile, SessionCmd,
    ToDeviceMessage, TokenEntry, TokenKind, UserChangePayload, UserCommand, UserResponse,
};

/// M2 runs a single user shard; the fixed shard count and placement land
/// with clustering (M4).
/// This binary's schema version for this shard app — bump together with
/// a `migrate` arm (see docs/design-schema-migrations.md).
///
/// v2 (step 4): the outbound EDU outbox moved to the fed-out shard; the
/// migration drops the orphaned `T_EDU_OUTBOX`. Gated in the daemon on
/// the fed-out drain marker covering every remaining row
/// (docs/design-federation-out.md §drain).
pub const SCHEMA_VERSION: u32 = 2;

pub const USER_SHARD: ShardId = ShardId::new(Keyspace::User, 0);

/// Access tokens issued alongside a refresh token expire after this long.
pub const ACCESS_TOKEN_LIFETIME_MS: u64 = 60 * 60 * 1000;

/// Cursor key of the room/0 → user/0 membership projection.
const ROOM_SOURCE: &str = "room/0";

#[derive(Debug, thiserror::Error)]
pub enum UserError {
    #[error("username already taken")]
    UserExists,
    #[error("invalid username: {0}")]
    InvalidUsername(String),
    #[error("invalid password: {0}")]
    InvalidPassword(String),
    #[error("bad credentials")]
    Forbidden,
    #[error("unknown or superseded refresh token")]
    InvalidGrant,
    #[error("not found")]
    NotFound,
    #[error("alias already exists")]
    AliasExists,
    #[error("shard: {0}")]
    Shard(#[from] saltator_shard::ShardError),
    #[error("storage: {0}")]
    Storage(String),
    #[error("codec: {0}")]
    Codec(String),
    #[error("{0}")]
    Internal(String),
}

type Result<T> = std::result::Result<T, UserError>;

fn storage_err(e: impl std::fmt::Display) -> UserError {
    UserError::Storage(e.to_string())
}

/// A freshly created session's credentials (the only moment the raw
/// tokens exist server-side).
#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: OwnedUserId,
    pub device_id: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Milliseconds until the access token expires (refresh flow only).
    pub expires_in_ms: Option<u64>,
}

pub struct UserServer {
    handle: ShardHandle,
    server_name: OwnedServerName,
}

impl UserServer {
    pub async fn start(
        node_id: NodeId,
        stores: impl Into<saltator_store::Stores>,
        server_name: OwnedServerName,
        network: impl RaftNetworkFactory<TypeConfig>,
        bootstrap_addr: Option<String>,
        registry: Option<&ShardRegistry>,
    ) -> Result<Arc<Self>> {
        let handle = ShardHandle::start(
            USER_SHARD,
            node_id,
            stores,
            Arc::new(UserApp),
            network,
            bootstrap_addr,
            registry,
        )
        .await?;
        Ok(Arc::new(Self {
            handle,
            server_name,
        }))
    }

    pub fn shard_handle(&self) -> &ShardHandle {
        &self.handle
    }

    pub fn server_name(&self) -> &ruma::ServerName {
        &self.server_name
    }

    pub fn store(&self) -> UserStore {
        UserStore::new(self.handle.read_ctx())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ChangeRecord> {
        self.handle.subscribe()
    }

    pub fn decode_change(payload: &[u8]) -> Result<UserChangePayload> {
        postcard::from_bytes(payload).map_err(|e| UserError::Codec(e.to_string()))
    }

    pub async fn shutdown(&self) -> Result<()> {
        Ok(self.handle.shutdown().await?)
    }

    // -- sessions ---------------------------------------------------------

    /// Register a new account and (unless `inhibit_login`) its first
    /// session (linearizable username reservation, spec.md §9).
    pub async fn register(
        &self,
        localpart: &str,
        password: Option<&str>,
        device_id: Option<String>,
        display_name: Option<String>,
        want_refresh: bool,
        inhibit_login: bool,
    ) -> Result<(OwnedUserId, Option<Session>)> {
        let user_id = self.user_id_for(localpart)?;
        let password_hash = match password {
            Some(p) => Some(hash_password(p).await?),
            None => None,
        };
        let (session, cmd) = if inhibit_login {
            (None, None)
        } else {
            let (s, c) = new_session(user_id.clone(), device_id, display_name, want_refresh);
            (Some(s), Some(c))
        };
        match self
            .propose(&UserCommand::Register {
                user_id: user_id.to_string(),
                password_hash,
                ts: now_ms(),
                session: cmd,
            })
            .await?
        {
            UserResponse::Ok => {}
            UserResponse::UserExists => return Err(UserError::UserExists),
            other => return Err(unexpected(other)),
        }
        // Default displayname = localpart (what Synapse does; clients and
        // member events expect a name from the start).
        self.set_profile(&user_id, Some(Some(user_id.localpart().to_owned())), None)
            .await?;
        Ok((user_id, session))
    }

    /// Password login. `user` may be a full user ID or a localpart.
    pub async fn login_password(
        &self,
        user: &str,
        password: &str,
        device_id: Option<String>,
        display_name: Option<String>,
        want_refresh: bool,
    ) -> Result<Session> {
        let user_id = self.user_id_for(user)?;
        let account = self
            .store()
            .account(user_id.as_str())
            .map_err(storage_err)?
            .filter(|a| !a.deactivated);
        let Some(hash) = account.and_then(|a| a.password_hash) else {
            // No such account (or no password): still spend an Argon2 verify
            // so latency doesn't disclose account existence.
            dummy_verify().await;
            return Err(UserError::Forbidden);
        };
        if !verify_password(password.to_owned(), hash).await? {
            return Err(UserError::Forbidden);
        }
        let (session, cmd) = new_session(user_id, device_id, display_name, want_refresh);
        match self.propose(&UserCommand::CreateSession(cmd)).await? {
            UserResponse::Ok => Ok(session),
            UserResponse::NotFound => Err(UserError::Forbidden),
            other => Err(unexpected(other)),
        }
    }

    /// Check a user's password (UIA stages, device deletion).
    pub async fn verify_user_password(&self, user_id: &UserId, password: &str) -> Result<bool> {
        let account = self
            .store()
            .account(user_id.as_str())
            .map_err(storage_err)?
            .filter(|a| !a.deactivated);
        let Some(hash) = account.and_then(|a| a.password_hash) else {
            dummy_verify().await;
            return Ok(false);
        };
        verify_password(password.to_owned(), hash).await
    }

    /// Rotate a session's tokens (`/refresh`).
    pub async fn refresh(&self, refresh_token: &str) -> Result<Session> {
        let old_hash = token_hash(refresh_token);
        let entry = self
            .store()
            .token(&old_hash)
            .map_err(storage_err)?
            .filter(|e| e.kind == TokenKind::Refresh)
            .ok_or(UserError::InvalidGrant)?;
        let user_id = OwnedUserId::try_from(entry.user_id)
            .map_err(|e| UserError::Internal(format!("stored user id: {e}")))?;
        let (session, cmd) = new_session(user_id, Some(entry.device_id), None, true);
        match self
            .propose(&UserCommand::RefreshSession {
                old_refresh_hash: old_hash,
                session: cmd,
            })
            .await?
        {
            UserResponse::Ok => Ok(session),
            UserResponse::InvalidGrant => Err(UserError::InvalidGrant),
            other => Err(unexpected(other)),
        }
    }

    /// Resolve an access token to `(user_id, device_id)`.
    pub fn authenticate(&self, token: &str) -> Result<Option<(OwnedUserId, String)>> {
        let entry = self
            .store()
            .token(&token_hash(token))
            .map_err(storage_err)?;
        let Some(entry) = entry else {
            return Ok(None);
        };
        if entry.kind != TokenKind::Access {
            return Ok(None);
        }
        if entry.expires_ts.is_some_and(|t| t <= now_ms()) {
            return Ok(None);
        }
        let user_id = OwnedUserId::try_from(entry.user_id)
            .map_err(|e| UserError::Internal(format!("stored user id: {e}")))?;
        // Defence in depth: deactivation already deletes a user's tokens,
        // but never honour a token for a deactivated account even if one
        // survived (a missed deletion path, projection lag, a future
        // session command that skips the check).
        if self
            .store()
            .account(user_id.as_str())
            .map_err(storage_err)?
            .is_none_or(|a| a.deactivated)
        {
            return Ok(None);
        }
        Ok(Some((user_id, entry.device_id)))
    }

    /// Invalidate one device and its tokens (`/logout`, device delete).
    pub async fn delete_device(&self, user_id: &UserId, device_id: &str) -> Result<()> {
        match self
            .propose(&UserCommand::DeleteDevice {
                user_id: user_id.to_string(),
                device_id: device_id.to_owned(),
            })
            .await?
        {
            UserResponse::Ok => Ok(()),
            UserResponse::NotFound => Err(UserError::NotFound),
            other => Err(unexpected(other)),
        }
    }

    /// Invalidate all sessions of a user (`/logout/all`).
    pub async fn delete_all_devices(&self, user_id: &UserId) -> Result<()> {
        self.expect_ok(&UserCommand::DeleteAllDevices {
            user_id: user_id.to_string(),
        })
        .await
    }

    pub async fn set_device_name(
        &self,
        user_id: &UserId,
        device_id: &str,
        display_name: Option<String>,
    ) -> Result<()> {
        match self
            .propose(&UserCommand::SetDeviceName {
                user_id: user_id.to_string(),
                device_id: device_id.to_owned(),
                display_name,
            })
            .await?
        {
            UserResponse::Ok => Ok(()),
            UserResponse::NotFound => Err(UserError::NotFound),
            other => Err(unexpected(other)),
        }
    }

    /// Publish a device's E2EE keys (`/keys/upload`): store its identity
    /// `device_keys` (when present) and add `one_time_keys`; returns the
    /// resulting one-time-key counts per algorithm.
    pub async fn upload_keys(
        &self,
        user_id: &UserId,
        device_id: &str,
        device_keys: Option<Vec<u8>>,
        one_time_keys: Vec<(String, Vec<u8>)>,
        fallback_keys: Vec<(String, Vec<u8>)>,
    ) -> Result<std::collections::BTreeMap<String, u64>> {
        match self
            .propose(&UserCommand::UploadKeys {
                user_id: user_id.to_string(),
                device_id: device_id.to_owned(),
                device_keys,
                one_time_keys,
                fallback_keys,
            })
            .await?
        {
            UserResponse::OneTimeKeyCounts(counts) => Ok(counts),
            other => Err(unexpected(other)),
        }
    }

    /// Store the user's cross-signing keys (`/keys/device_signing/upload`).
    pub async fn set_cross_signing_keys(
        &self,
        user_id: &UserId,
        master: Option<Vec<u8>>,
        self_signing: Option<Vec<u8>>,
        user_signing: Option<Vec<u8>>,
    ) -> Result<()> {
        self.expect_ok(&UserCommand::SetCrossSigningKeys {
            user_id: user_id.to_string(),
            master,
            self_signing,
            user_signing,
        })
        .await
    }

    /// Merge uploaded signatures into the user's stored device or
    /// cross-signing keys (`/keys/signatures/upload`).
    pub async fn add_signatures(
        &self,
        user_id: &UserId,
        targets: Vec<(String, Vec<u8>)>,
    ) -> Result<()> {
        self.expect_ok(&UserCommand::AddSignatures {
            user_id: user_id.to_string(),
            targets,
        })
        .await
    }

    /// Claim one one-time key per request (`/keys/claim`) — a linearizable
    /// removal, so no key is claimed twice.
    pub async fn claim_keys(&self, claims: Vec<ClaimRequest>) -> Result<Vec<ClaimedKey>> {
        match self.propose(&UserCommand::ClaimKeys { claims }).await? {
            UserResponse::ClaimedKeys(keys) => Ok(keys),
            other => Err(unexpected(other)),
        }
    }

    /// Queue to-device messages into recipients' inboxes (`/sendToDevice`),
    /// waking their syncs. A `device_id` of `"*"` fans out to all of the
    /// user's devices.
    pub async fn send_to_device(&self, messages: Vec<ToDeviceMessage>) -> Result<()> {
        if messages.is_empty() {
            return Ok(());
        }
        self.expect_ok(&UserCommand::SendToDevice { messages })
            .await
    }

    /// Apply a projection batch of membership changes from a room shard
    /// (monotonic per `source`; stale batches are ignored).
    pub async fn apply_room_changes(
        &self,
        source: &str,
        upto_seq: u64,
        changes: Vec<MembershipChange>,
    ) -> Result<()> {
        match self
            .propose(&UserCommand::ApplyRoomChanges {
                source: source.to_owned(),
                upto_seq,
                changes,
            })
            .await?
        {
            UserResponse::Ok | UserResponse::Stale => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    /// Drop delivered to-device messages: everything at inbox seq
    /// `<= up_to` for the device.
    pub async fn ack_to_device(&self, user_id: &UserId, device_id: &str, up_to: u64) -> Result<()> {
        self.expect_ok(&UserCommand::AckToDevice {
            user_id: user_id.to_string(),
            device_id: device_id.to_owned(),
            up_to,
        })
        .await
    }

    /// Log a device-list change for a (typically remote) user without
    /// touching key material, waking syncs that track them
    /// (`m.device_list_update`).
    pub async fn record_key_change(&self, user_id: &str) -> Result<()> {
        self.expect_ok(&UserCommand::RecordKeyChange {
            user_id: user_id.to_owned(),
        })
        .await
    }

    /// Queue federation to-device messages with `(origin, message_id)`
    /// dedupe: a redelivered EDU (the sender is at-least-once) drops
    /// atomically inside apply, so clients never see duplicates — even
    /// across our own restart, since the seen-set is replicated state.
    pub async fn send_to_device_deduped(
        &self,
        origin: &str,
        message_id: &str,
        messages: Vec<ToDeviceMessage>,
    ) -> Result<()> {
        self.expect_ok(&UserCommand::SendToDeviceDeduped {
            origin: origin.to_owned(),
            message_id: message_id.to_owned(),
            ts_ms: now_ms(),
            messages,
        })
        .await
    }

    /// Queue outbound federation EDUs into the durable outbox — the EDU
    /// sender drains and acks them, so delivery survives destination
    /// downtime and our own restarts.
    pub async fn queue_outbound_edus(&self, entries: Vec<OutboundEdu>) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        self.expect_ok(&UserCommand::QueueOutboundEdus { entries })
            .await
    }

    /// Drop delivered outbox EDUs for `destination` at seq `<= up_to`.
    pub async fn ack_outbound_edus(&self, destination: &str, up_to: u64) -> Result<()> {
        self.expect_ok(&UserCommand::AckOutboundEdus {
            destination: destination.to_owned(),
            up_to,
        })
        .await
    }

    /// Change the account password (`/account/password`); when
    /// `logout_others`, every device except `keep_device` is deleted.
    pub async fn change_password(
        &self,
        user_id: &UserId,
        new_password: &str,
        logout_others: bool,
        keep_device: &str,
    ) -> Result<()> {
        let password_hash = hash_password(new_password).await?;
        match self
            .propose(&UserCommand::ChangePassword {
                user_id: user_id.to_string(),
                password_hash,
                logout_others,
                keep_device: keep_device.to_owned(),
            })
            .await?
        {
            UserResponse::Ok => Ok(()),
            UserResponse::NotFound => Err(UserError::NotFound),
            other => Err(unexpected(other)),
        }
    }

    // -- key backup --------------------------------------------------------

    /// Mint the next key-backup version (`POST /room_keys/version`).
    pub async fn create_backup_version(
        &self,
        user_id: &UserId,
        algorithm: &str,
        auth_data: Vec<u8>,
    ) -> Result<u64> {
        match self
            .propose(&UserCommand::CreateBackupVersion {
                user_id: user_id.to_string(),
                algorithm: algorithm.to_owned(),
                auth_data,
            })
            .await?
        {
            UserResponse::BackupVersion(v) => Ok(v),
            other => Err(unexpected(other)),
        }
    }

    /// Update a backup version's algorithm/auth_data in place.
    pub async fn update_backup_version(
        &self,
        user_id: &UserId,
        version: u64,
        algorithm: &str,
        auth_data: Vec<u8>,
    ) -> Result<()> {
        match self
            .propose(&UserCommand::UpdateBackupVersion {
                user_id: user_id.to_string(),
                version,
                algorithm: algorithm.to_owned(),
                auth_data,
            })
            .await?
        {
            UserResponse::Ok => Ok(()),
            UserResponse::NotFound => Err(UserError::NotFound),
            other => Err(unexpected(other)),
        }
    }

    /// Tombstone a backup version and drop its keys.
    pub async fn delete_backup_version(&self, user_id: &UserId, version: u64) -> Result<()> {
        match self
            .propose(&UserCommand::DeleteBackupVersion {
                user_id: user_id.to_string(),
                version,
            })
            .await?
        {
            UserResponse::Ok => Ok(()),
            UserResponse::NotFound => Err(UserError::NotFound),
            other => Err(unexpected(other)),
        }
    }

    /// Store keys into a backup version under the spec's replace rules;
    /// returns the resulting `(count, etag)`.
    pub async fn put_backup_keys(
        &self,
        user_id: &UserId,
        version: u64,
        keys: Vec<(String, String, Vec<u8>)>,
    ) -> Result<(u64, u64)> {
        match self
            .propose(&UserCommand::PutBackupKeys {
                user_id: user_id.to_string(),
                version,
                keys,
            })
            .await?
        {
            UserResponse::BackupStatus { count, etag } => Ok((count, etag)),
            UserResponse::NotFound => Err(UserError::NotFound),
            other => Err(unexpected(other)),
        }
    }

    /// Delete backed-up keys (whole version / one room / one session);
    /// returns the resulting `(count, etag)`.
    pub async fn delete_backup_keys(
        &self,
        user_id: &UserId,
        version: u64,
        room_id: Option<String>,
        session_id: Option<String>,
    ) -> Result<(u64, u64)> {
        match self
            .propose(&UserCommand::DeleteBackupKeys {
                user_id: user_id.to_string(),
                version,
                room_id,
                session_id,
            })
            .await?
        {
            UserResponse::BackupStatus { count, etag } => Ok((count, etag)),
            UserResponse::NotFound => Err(UserError::NotFound),
            other => Err(unexpected(other)),
        }
    }

    /// Create/replace (`json` present) or delete (`None`) the pusher
    /// identified by `(app_id, pushkey)` (`POST /pushers/set`).
    pub async fn set_pusher(
        &self,
        user_id: &UserId,
        device_id: &str,
        app_id: &str,
        pushkey: &str,
        json: Option<Vec<u8>>,
    ) -> Result<()> {
        self.expect_ok(&UserCommand::SetPusher {
            user_id: user_id.to_string(),
            device_id: device_id.to_owned(),
            app_id: app_id.to_owned(),
            pushkey: pushkey.to_owned(),
            json,
        })
        .await
    }

    /// Deactivate the account (`/account/deactivate`): permanent — blocks
    /// future logins and kills every session.
    pub async fn deactivate(&self, user_id: &UserId) -> Result<()> {
        match self
            .propose(&UserCommand::Deactivate {
                user_id: user_id.to_string(),
            })
            .await?
        {
            UserResponse::Ok => Ok(()),
            UserResponse::NotFound => Err(UserError::NotFound),
            other => Err(unexpected(other)),
        }
    }

    // -- profile / account data / filters / aliases / media ---------------

    /// `None` = leave unchanged; `Some(None)` = unset.
    pub async fn set_profile(
        &self,
        user_id: &UserId,
        displayname: Option<Option<String>>,
        avatar_url: Option<Option<String>>,
    ) -> Result<()> {
        self.expect_ok(&UserCommand::SetProfile {
            user_id: user_id.to_string(),
            displayname,
            avatar_url,
        })
        .await
    }

    /// `room_id` empty = global account data.
    pub async fn put_account_data(
        &self,
        user_id: &UserId,
        room_id: &str,
        data_type: &str,
        json: Vec<u8>,
    ) -> Result<()> {
        self.expect_ok(&UserCommand::PutAccountData {
            user_id: user_id.to_string(),
            room_id: room_id.to_owned(),
            data_type: data_type.to_owned(),
            json,
        })
        .await
    }

    /// Store a filter; the ID is derived from the content, so re-uploads
    /// are idempotent.
    pub async fn put_filter(&self, user_id: &UserId, json: Vec<u8>) -> Result<String> {
        let filter_id = hex_prefix(&blake3::hash(&json));
        self.expect_ok(&UserCommand::PutFilter {
            user_id: user_id.to_string(),
            filter_id: filter_id.clone(),
            json,
        })
        .await?;
        Ok(filter_id)
    }

    /// Publish to / withdraw from the public room directory.
    pub async fn set_room_visibility(&self, room_id: &str, public: bool) -> Result<()> {
        match self
            .propose(&UserCommand::SetRoomVisibility {
                room_id: room_id.to_owned(),
                public,
            })
            .await?
        {
            UserResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    pub async fn create_alias(&self, alias: &str, room_id: &str, creator: &UserId) -> Result<()> {
        match self
            .propose(&UserCommand::CreateAlias {
                alias: alias.to_owned(),
                room_id: room_id.to_owned(),
                creator: creator.to_string(),
            })
            .await?
        {
            UserResponse::Ok => Ok(()),
            UserResponse::AliasExists => Err(UserError::AliasExists),
            other => Err(unexpected(other)),
        }
    }

    pub async fn delete_alias(&self, alias: &str) -> Result<()> {
        match self
            .propose(&UserCommand::DeleteAlias {
                alias: alias.to_owned(),
            })
            .await?
        {
            UserResponse::Ok => Ok(()),
            UserResponse::NotFound => Err(UserError::NotFound),
            other => Err(unexpected(other)),
        }
    }

    pub async fn put_media(&self, media_id: &str, meta: MediaMeta) -> Result<()> {
        self.expect_ok(&UserCommand::PutMedia {
            media_id: media_id.to_owned(),
            meta,
        })
        .await
    }

    /// Record a pending invite to a remote room (received over federation)
    /// so it surfaces in the invited user's `/sync`.
    pub async fn record_remote_invite(
        &self,
        user_id: &str,
        room_id: &str,
        sender: &str,
        event_id: &str,
        stripped_state: Vec<Vec<u8>>,
    ) -> Result<()> {
        self.expect_ok(&UserCommand::RecordRemoteInvite {
            user_id: user_id.to_owned(),
            room_id: room_id.to_owned(),
            sender: sender.to_owned(),
            event_id: event_id.to_owned(),
            stripped_state,
        })
        .await
    }

    /// Record a pending knock on a remote room (from a `/send_knock`
    /// response) so it surfaces in the knocking user's `/sync`.
    pub async fn record_remote_knock(
        &self,
        user_id: &str,
        room_id: &str,
        sender: &str,
        event_id: &str,
        stripped_state: Vec<Vec<u8>>,
    ) -> Result<()> {
        self.expect_ok(&UserCommand::RecordRemoteKnock {
            user_id: user_id.to_owned(),
            room_id: room_id.to_owned(),
            sender: sender.to_owned(),
            event_id: event_id.to_owned(),
            stripped_state,
        })
        .await
    }

    /// Reject a pending remote invite (or leave a remote room): set `leave`
    /// membership and clear the stored invite state.
    pub async fn record_remote_leave(&self, user_id: &str, room_id: &str) -> Result<()> {
        self.expect_ok(&UserCommand::RecordRemoteLeave {
            user_id: user_id.to_owned(),
            room_id: room_id.to_owned(),
        })
        .await
    }

    /// Mark a departed room as forgotten (`/forget`).
    pub async fn forget_room(&self, user_id: &str, room_id: &str) -> Result<()> {
        self.expect_ok(&UserCommand::ForgetRoom {
            user_id: user_id.to_owned(),
            room_id: room_id.to_owned(),
        })
        .await
    }

    // -- internals ---------------------------------------------------------

    /// Canonicalize a localpart or full user ID for this server. Capitals
    /// are downcased first (registration downcases, login is
    /// case-insensitive — historical Matrix behavior).
    pub fn canonical_user_id(&self, user: &str) -> Result<OwnedUserId> {
        self.user_id_for(user)
    }

    fn user_id_for(&self, user: &str) -> Result<OwnedUserId> {
        let user = &user.to_lowercase();
        if user.starts_with('@') {
            let user_id = OwnedUserId::try_from(user.to_owned())
                .map_err(|e| UserError::InvalidUsername(e.to_string()))?;
            if user_id.server_name() != self.server_name {
                return Err(UserError::InvalidUsername(format!(
                    "wrong server name in {user}"
                )));
            }
            return Ok(user_id);
        }
        if user.is_empty()
            || !user
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._=-/+".contains(&b))
        {
            return Err(UserError::InvalidUsername(
                "localpart must match [a-z0-9._=/+-]+".into(),
            ));
        }
        OwnedUserId::try_from(format!("@{user}:{}", self.server_name))
            .map_err(|e| UserError::InvalidUsername(e.to_string()))
    }

    async fn propose(&self, cmd: &UserCommand) -> Result<UserResponse> {
        let bytes = postcard::to_stdvec(cmd).map_err(|e| UserError::Codec(e.to_string()))?;
        let resp = self.handle.propose(bytes).await?;
        postcard::from_bytes(&resp).map_err(|e| UserError::Codec(e.to_string()))
    }

    async fn expect_ok(&self, cmd: &UserCommand) -> Result<()> {
        match self.propose(cmd).await? {
            UserResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }
}

fn unexpected(resp: UserResponse) -> UserError {
    UserError::Internal(format!("unexpected user-shard response: {resp:?}"))
}

// ---------------------------------------------------------------------------
// Membership projection (room/0 → user/0)
// ---------------------------------------------------------------------------

/// Batch size for projection catch-up scans.
const PROJECTION_BATCH: usize = 512;

/// Drive the membership projection: consume the room shard's change
/// stream and index members' memberships (local and remote) in the user
/// shard. Replays from the persisted cursor on startup; ends when the
/// room shard's change stream closes (spec.md §9: eventually consistent,
/// monotonic per source shard).
pub fn spawn_membership_projection(
    users: Arc<UserServer>,
    rooms: Arc<RoomServer>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run_membership_projection(&users, &rooms).await {
            tracing::error!(error = %e, "membership projection stopped");
        }
    })
}

async fn run_membership_projection(users: &UserServer, rooms: &RoomServer) -> Result<()> {
    // Subscribe before catching up, so nothing lands unseen between scan
    // and subscription. Lag/overflow just triggers another catch-up.
    let mut changes = rooms.subscribe();
    loop {
        // Catch up from the persisted cursor.
        loop {
            let cursor = users.store().cursor(ROOM_SOURCE).map_err(storage_err)?;
            let batch = rooms
                .store()
                .timeline(cursor, PROJECTION_BATCH)
                .map_err(storage_err)?;
            let Some(&(upto_seq, _)) = batch.last() else {
                break;
            };
            let mut changes_out = Vec::new();
            for (room_seq, entry) in &batch {
                let SeqEntry::Event { room_id, event_id } = entry else {
                    continue;
                };
                if let Some(change) = membership_change(rooms, room_id, event_id, *room_seq)? {
                    changes_out.push(change);
                }
            }
            users
                .apply_room_changes(ROOM_SOURCE, upto_seq, changes_out)
                .await?;
        }
        // Wait for more.
        match changes.recv().await {
            Ok(_) => {}
            Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

/// Extract a membership change from one accepted room event. Remote
/// users' memberships are indexed too — `/sync` only reads the caller's
/// rows, but device-list and presence visibility ("do they share a
/// room?") need every member.
fn membership_change(
    rooms: &RoomServer,
    room_id: &str,
    event_id: &str,
    room_seq: u64,
) -> Result<Option<MembershipChange>> {
    let Some(stored) = rooms.store().event(event_id).map_err(storage_err)? else {
        return Ok(None);
    };
    let raw: serde_json::Value =
        serde_json::from_slice(&stored.raw).map_err(|e| UserError::Codec(e.to_string()))?;
    if raw.get("type").and_then(|v| v.as_str()) != Some("m.room.member") {
        return Ok(None);
    }
    let Some(state_key) = raw.get("state_key").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    if <&UserId>::try_from(state_key).is_err() {
        return Ok(None);
    }
    let Some(membership) = raw
        .get("content")
        .and_then(|c| c.get("membership"))
        .and_then(|v| v.as_str())
    else {
        return Ok(None);
    };
    let sender = raw
        .get("sender")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    Ok(Some(MembershipChange {
        user_id: state_key.to_owned(),
        room_id: room_id.to_owned(),
        membership: membership.to_owned(),
        event_id: event_id.to_owned(),
        sender: sender.to_owned(),
        room_seq,
    }))
}

/// Block until the projection cursor reaches `seq` (test/gateway helper
/// for read-your-writes over the eventually consistent index).
pub async fn wait_for_projection(users: &UserServer, seq: u64, timeout: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if users.store().cursor(ROOM_SOURCE).map_err(storage_err)? >= seq {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(UserError::Internal(format!(
                "projection did not reach seq {seq} in time"
            )));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

/// Random 256-bit token, URL-safe unpadded base64.
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Tokens are stored blake3-hashed (spec.md §10).
pub fn token_hash(token: &str) -> [u8; 32] {
    *blake3::hash(token.as_bytes()).as_bytes()
}

/// Random device ID in the conventional 10-char uppercase alphanumeric
/// shape.
pub fn generate_device_id() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..10)
        .map(|_| ALPHABET[(rng.next_u32() as usize) % ALPHABET.len()] as char)
        .collect()
}

/// Upper bound on password length before Argon2. Argon2 pre-hashes the
/// whole input with Blake2b, so an unbounded password is a CPU/memory
/// amplifier on the blocking pool; no legitimate password approaches this.
const MAX_PASSWORD_LEN: usize = 1024;

/// A real Argon2 verify against a throwaway hash, used on account-miss
/// paths so login/UIA latency doesn't reveal whether an account exists.
async fn dummy_verify() {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let phc = match DUMMY.get() {
        Some(p) => p.clone(),
        None => {
            let p = hash_password("saltator-timing-equalizer")
                .await
                .unwrap_or_default();
            let _ = DUMMY.set(p.clone());
            p
        }
    };
    if !phc.is_empty() {
        let _ = verify_password("saltator-timing-equalizer-miss".to_owned(), phc).await;
    }
}

async fn hash_password(password: &str) -> Result<String> {
    if password.len() > MAX_PASSWORD_LEN {
        return Err(UserError::InvalidPassword("password too long".into()));
    }
    let password = password.to_owned();
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut rand::thread_rng());
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| UserError::Internal(format!("argon2: {e}")))
    })
    .await
    .map_err(|e| UserError::Internal(format!("join: {e}")))?
}

async fn verify_password(password: String, phc: String) -> Result<bool> {
    // An over-length input can't match any stored hash (we cap at hash
    // time), so reject it without spending Argon2 on attacker-sized input.
    if password.len() > MAX_PASSWORD_LEN {
        return Ok(false);
    }
    tokio::task::spawn_blocking(move || {
        let parsed =
            PasswordHash::new(&phc).map_err(|e| UserError::Internal(format!("argon2: {e}")))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    })
    .await
    .map_err(|e| UserError::Internal(format!("join: {e}")))?
}

fn hex_prefix(hash: &blake3::Hash) -> String {
    hash.to_hex().as_str()[..16].to_owned()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_millis() as u64
}

/// Build a [`Session`] and its state-machine command.
fn new_session(
    user_id: OwnedUserId,
    device_id: Option<String>,
    display_name: Option<String>,
    want_refresh: bool,
) -> (Session, SessionCmd) {
    let device_id = device_id.unwrap_or_else(generate_device_id);
    let access_token = generate_token();
    let refresh_token = want_refresh.then(generate_token);
    let ts = now_ms();
    let expires_ts = refresh_token
        .as_ref()
        .map(|_| ts + ACCESS_TOKEN_LIFETIME_MS);
    let cmd = SessionCmd {
        user_id: user_id.to_string(),
        device_id: device_id.clone(),
        display_name,
        token_hash: token_hash(&access_token),
        refresh_hash: refresh_token.as_deref().map(token_hash),
        expires_ts,
        ts,
    };
    let session = Session {
        user_id,
        device_id,
        access_token,
        refresh_token,
        expires_in_ms: expires_ts.map(|_| ACCESS_TOKEN_LIFETIME_MS),
    };
    (session, cmd)
}
