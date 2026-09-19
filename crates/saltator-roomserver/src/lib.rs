//! The room server: the event pipeline and the room keyspace state
//! machine (spec.md §5.2), running on the generic shard runtime.
//!
//! Every event — local send or federated PDU — passes through one
//! pipeline at the room-shard leader:
//!
//! 1. **Validate** — schema/size checks, signature + content-hash
//!    verification (hash mismatch → redact, not reject).
//! 2. **Fetch** — resolve `auth_events`/`prev_events` from the shard;
//!    events not present locally surface as [`RoomError::MissingEvents`],
//!    which the healing path in [`heal`] resolves by fetching from the
//!    origin server before retrying.
//! 3. **Authorize** — structural auth-events checks, the state-dependent
//!    rules against the auth-event state, then against the state before
//!    the event.
//! 4. **Resolve** — if the event's `prev_events` (or the resulting
//!    extremity set) reveal a fork, run state resolution.
//! 5. **Persist** — one Raft proposal carrying the precomputed outcome;
//!    the state-machine apply is a single deterministic KV batch.
//! 6. **Emit** — the apply publishes to the shard change stream.
//!
//! The shard leader serializes all writes to a room (spec.md §4.1); here
//! that is a per-room async lock around steps 2–5, so reads of applied
//! state during precomputation are stable.

mod heal;
pub mod hierarchy;
mod machine;
pub mod remote;
mod shards;
mod signer;
mod types;

pub use heal::EventFetcher;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use openraft::network::RaftNetworkFactory;
use ruma::signatures::PublicKeyMap;
use ruma::{
    CanonicalJsonObject, CanonicalJsonValue, EventId, OwnedEventId, OwnedRoomId, OwnedUserId,
    UserId,
};
use tokio::sync::{broadcast, Mutex, OwnedMutexGuard};

use saltator_core::auth::{self, AuthEntry, StateMap};
use saltator_core::event::{self, EventFormatError, IdentifiedPdu, Pdu};
use saltator_core::power_levels::{PowerLevel, RoomPowerLevels};
use saltator_core::room_version::UnsupportedRoomVersion;
use saltator_core::state_res::{self, StateIds, StateResError};
use saltator_core::validation::{self, ValidationError, VerificationError, VerifyOutcome};
use saltator_core::{Event, RoomVersion};
use saltator_shard::{ChangeRecord, NodeId, ShardHandle, ShardId, ShardRegistry, TypeConfig};
use saltator_store::Keyspace;

pub use machine::{RoomApp, RoomPage, RoomStore};
pub use shards::{shard_of, RoomShards, ShardTail};
pub use signer::{ServerSigner, SignError};
pub use types::{
    AppendEvent, ChangePayload, ReceiptCmd, ReceiptRecord, Rejected, RoomCommand, RoomMeta,
    RoomResponse, SeqEntry, StateGroup, StoredEvent, MAX_GROUP_CHAIN,
};

/// This binary's schema version for this shard app — bump together with
/// a `migrate` arm (see docs/design-schema-migrations.md).
pub const SCHEMA_VERSION: u32 = 1;

/// Shard 0 of the room keyspace: the shard a single-group server starts,
/// and the id [`RoomServer::start`] uses. Multi-shard deployments route
/// through [`RoomShards`] instead and never name a shard directly.
pub const ROOM_SHARD: ShardId = ShardId::new(Keyspace::Room, 0);

#[derive(Debug, thiserror::Error)]
pub enum RoomError {
    #[error("unknown room {0}")]
    UnknownRoom(String),
    /// Referenced events are not present locally. For inbound federated
    /// events this is not terminal: [`heal`] fetches the gap from the
    /// origin and retries, and only a permanent hole stays an error.
    #[error("events required but not present locally: {0:?}")]
    MissingEvents(Vec<String>),
    /// The event's `auth_events` reference events not present locally,
    /// while every prev_event resolves. Distinct from
    /// [`RoomError::MissingEvents`] because the remedy differs: the named
    /// events are fetched directly as outliers (`/event`), never via
    /// `/get_missing_events` — that walk is for timeline gaps, and firing
    /// it on an auth-only miss trips Complement's
    /// TestInboundFederationRejectsEventsWithRejectedAuthEvents.
    #[error("auth events required but not present locally: {0:?}")]
    MissingAuthEvents(Vec<String>),
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Verification(#[from] VerificationError),
    #[error(transparent)]
    Format(#[from] EventFormatError),
    #[error(transparent)]
    Version(#[from] UnsupportedRoomVersion),
    #[error(transparent)]
    StateRes(#[from] StateResError),
    #[error(transparent)]
    Sign(#[from] SignError),
    #[error("malformed event: {0}")]
    Malformed(String),
    /// A restricted / `knock_restricted` join could not be authorised by
    /// this server. The federation layer maps the variant to the spec
    /// errcode (`M_FORBIDDEN` / `M_UNABLE_TO_AUTHORISE_JOIN` /
    /// `M_UNABLE_TO_GRANT_JOIN`).
    #[error("restricted join not authorised: {0:?}")]
    CannotAuthoriseJoin(RestrictedDenial),
    #[error("shard: {0}")]
    Shard(#[from] saltator_shard::ShardError),
    #[error("storage: {0}")]
    Storage(String),
    #[error("codec: {0}")]
    Codec(String),
}

/// Why a restricted join couldn't be authorised — chooses the federation
/// errcode (see [`RestrictedAuth`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RestrictedDenial {
    /// Fails all conditions → `403 M_FORBIDDEN`.
    Forbidden,
    /// Conditions un-evaluable here → `400 M_UNABLE_TO_AUTHORISE_JOIN`.
    CannotValidate,
    /// Condition met but no local authoriser → `400 M_UNABLE_TO_GRANT_JOIN`.
    CannotGrant,
}

type Result<T> = std::result::Result<T, RoomError>;

fn storage_err(e: impl std::fmt::Display) -> RoomError {
    RoomError::Storage(e.to_string())
}

/// Pipeline outcome for one event.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Outcome {
    Accepted {
        event_id: OwnedEventId,
        seq: u64,
    },
    Rejected {
        event_id: OwnedEventId,
        reason: String,
    },
    /// Already persisted; nothing changed.
    Duplicate {
        event_id: OwnedEventId,
    },
}

impl Outcome {
    pub fn event_id(&self) -> &EventId {
        match self {
            Outcome::Accepted { event_id, .. }
            | Outcome::Rejected { event_id, .. }
            | Outcome::Duplicate { event_id } => event_id,
        }
    }
}

/// The `PUT /send_join` response payload: the co-signed join event, the
/// room's current state, and the auth chain backing that state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SendJoinResult {
    pub event: CanonicalJsonObject,
    pub state: Vec<CanonicalJsonObject>,
    pub auth_chain: Vec<CanonicalJsonObject>,
}

/// The `PUT /send_knock` response payload: the stripped current room state
/// (`knock_room_state`) that lets the knocking server show the room to its
/// user while the knock is pending.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SendKnockResult {
    pub knock_room_state: Vec<serde_json::Value>,
}

/// Whether — and how — a restricted / `knock_restricted` join can be
/// authorised from this server's view of the room (MSC3083/MSC3787). Only
/// the authorising *decision*; the auth rules validate the resulting event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestrictedAuth {
    /// The room is not restricted, or the joiner is already joined/invited —
    /// build a plain join with no `join_authorised_via_users_server`.
    NotNeeded,
    /// The joiner meets an allow condition; stamp this local user (a joined
    /// member with invite power) as the authorising user.
    Authorised(OwnedUserId),
    /// The joiner meets none of the allow conditions we can fully evaluate
    /// → `403 M_FORBIDDEN` (fails all conditions).
    FailsConditions,
    /// An allow condition names a room we hold no state for, so we cannot
    /// tell → `400 M_UNABLE_TO_AUTHORISE_JOIN` (the caller should fail over
    /// to another resident).
    CannotValidate,
    /// A condition is met, but no local member can invite → `400
    /// M_UNABLE_TO_GRANT_JOIN` (the caller should fail over).
    CannotGrant,
}

/// Stripped-state event types served on a knock (mirrors invite stripped
/// state): enough to identify the room without leaking its contents.
const KNOCK_STATE_TYPES: &[&str] = &[
    "m.room.create",
    "m.room.join_rules",
    "m.room.canonical_alias",
    "m.room.name",
    "m.room.avatar",
    "m.room.topic",
    "m.room.encryption",
];

/// Event IDs referenced by an event's `auth_events` (v3+ list-of-strings
/// form; v1 tuple form is not produced by this server).
fn auth_event_ids(obj: &CanonicalJsonObject) -> Vec<String> {
    id_list(obj, "auth_events")
}

/// Event IDs in an event's `prev_events` (v3+ list-of-strings form).
pub(crate) fn prev_event_ids(obj: &CanonicalJsonObject) -> Vec<String> {
    id_list(obj, "prev_events")
}

fn id_list(obj: &CanonicalJsonObject, key: &str) -> Vec<String> {
    match obj.get(key) {
        Some(CanonicalJsonValue::Array(a)) => a
            .iter()
            .filter_map(|v| match v {
                CanonicalJsonValue::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Where this handle's shard lives: on this node (the full pipeline),
/// or on other nodes (reads via the remote store, writes as intents —
/// docs/design-room-sharding-phase2.md, 2a part 3).
enum RoomBackend {
    Hosted(ShardHandle),
    Remote(Arc<dyn saltator_shard::RemoteShardBackend>),
}

/// A room shard's change stream, backend-agnostic and gap-free: the
/// local half refills broadcast lag from seq-indexed replay; the remote
/// half is the Subscribe RPC's stream (which backfills server-side and
/// reconnects on its own). `None` means the shard shut down.
pub enum RoomChanges {
    Local {
        rx: broadcast::Receiver<ChangeRecord>,
        handle: ShardHandle,
        last: u64,
        buffer: std::collections::VecDeque<ChangeRecord>,
    },
    Remote(
        std::pin::Pin<
            Box<dyn futures_util::Stream<Item = saltator_shard::Result<ChangeRecord>> + Send>,
        >,
    ),
}

impl RoomChanges {
    /// The next change record at seq > the last one delivered.
    pub async fn recv(&mut self) -> Option<ChangeRecord> {
        use futures_util::StreamExt;
        match self {
            RoomChanges::Local {
                rx,
                handle,
                last,
                buffer,
            } => loop {
                if let Some(rec) = buffer.pop_front() {
                    *last = rec.seq;
                    return Some(rec);
                }
                match rx.recv().await {
                    Ok(rec) => {
                        if rec.seq <= *last {
                            continue;
                        }
                        if rec.seq > *last + 1 {
                            // The broadcast skipped seqs we have not seen
                            // (subscription raced emits): refill from
                            // applied state, then deliver in order.
                            if let Ok(batch) = handle.replay(*last, 256) {
                                buffer.extend(batch);
                                continue;
                            }
                        }
                        *last = rec.seq;
                        return Some(rec);
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        match handle.replay(*last, 256) {
                            Ok(batch) if !batch.is_empty() => buffer.extend(batch),
                            // Nothing replayable (or an app without
                            // replay): fall back to resubscribing; the
                            // consumer's own cursor covers the gap.
                            _ => *rx = handle.subscribe(),
                        }
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            },
            RoomChanges::Remote(stream) => match stream.next().await {
                Some(Ok(rec)) => Some(rec),
                Some(Err(e)) => {
                    tracing::warn!(error = %e, "remote change stream failed");
                    None
                }
                None => None,
            },
        }
    }
}

pub struct RoomServer {
    backend: RoomBackend,
    signer: Arc<ServerSigner>,
    /// Verification keys by entity, seeded with our own. Remote servers'
    /// keys are put here explicitly (see [`Self::trust_keys`]); the
    /// federation layer's key cache is what populates them in a running
    /// server.
    verify_keys: std::sync::RwLock<PublicKeyMap>,
    room_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl RoomServer {
    /// Start room shard 0 — the whole server, pre-M-scale. Tests and
    /// single-shard clusters live here; multi-shard boots call
    /// [`RoomServer::start_shard`] once per group.
    pub async fn start(
        node_id: NodeId,
        stores: impl Into<saltator_store::Stores>,
        signer: Arc<ServerSigner>,
        network: impl RaftNetworkFactory<TypeConfig>,
        bootstrap_addr: Option<String>,
        registry: Option<&ShardRegistry>,
    ) -> Result<Arc<Self>> {
        Self::start_shard(
            ROOM_SHARD,
            node_id,
            stores,
            signer,
            network,
            bootstrap_addr,
            registry,
        )
        .await
    }

    /// Start one room shard group on this node
    /// (docs/design-room-sharding.md): the same server, scoped to the
    /// rooms whose ids hash to `shard.index`.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_shard(
        shard: ShardId,
        node_id: NodeId,
        stores: impl Into<saltator_store::Stores>,
        signer: Arc<ServerSigner>,
        network: impl RaftNetworkFactory<TypeConfig>,
        bootstrap_addr: Option<String>,
        registry: Option<&ShardRegistry>,
    ) -> Result<Arc<Self>> {
        let handle = ShardHandle::start(
            shard,
            node_id,
            stores,
            Arc::new(RoomApp),
            network,
            bootstrap_addr,
            registry,
        )
        .await?;
        let verify_keys = std::sync::RwLock::new(signer.public_key_map());
        Ok(Arc::new(Self {
            backend: RoomBackend::Hosted(handle),
            signer,
            verify_keys,
            room_locks: Mutex::new(HashMap::new()),
        }))
    }

    /// A handle for a shard hosted ELSEWHERE: reads through the remote
    /// store, writes as intents at the hosting leader, subscription over
    /// the streaming RPC. No Raft group runs here.
    pub fn remote(
        backend: Arc<dyn saltator_shard::RemoteShardBackend>,
        signer: Arc<ServerSigner>,
    ) -> Arc<Self> {
        let verify_keys = std::sync::RwLock::new(signer.public_key_map());
        Arc::new(Self {
            backend: RoomBackend::Remote(backend),
            signer,
            verify_keys,
            room_locks: Mutex::new(HashMap::new()),
        })
    }

    /// Whether this node hosts the shard (runs its Raft group).
    pub fn is_hosted(&self) -> bool {
        matches!(self.backend, RoomBackend::Hosted(_))
    }

    /// The remote backend, when unhosted.
    fn remote_backend(&self) -> Option<&Arc<dyn saltator_shard::RemoteShardBackend>> {
        match &self.backend {
            RoomBackend::Hosted(_) => None,
            RoomBackend::Remote(r) => Some(r),
        }
    }

    /// The local shard handle. Panics on a remote handle: every caller
    /// is a hosted-only path (boot, metrics, reconciler, the pipeline) —
    /// reaching this on a remote room is a routing bug, not a state.
    pub fn shard_handle(&self) -> &ShardHandle {
        match &self.backend {
            RoomBackend::Hosted(h) => h,
            RoomBackend::Remote(_) => {
                panic!("shard_handle() on a remote room shard (hosted-only path)")
            }
        }
    }

    /// [`Self::shard_handle`] without the panic, for callers that
    /// legitimately skip remote shards (boot waits, metrics).
    pub fn hosted_handle(&self) -> Option<&ShardHandle> {
        match &self.backend {
            RoomBackend::Hosted(h) => Some(h),
            RoomBackend::Remote(_) => None,
        }
    }

    /// The placement moved this group's replicas: point the remote
    /// backend at the new address list (live streams pick it up on
    /// their next reconnect). No-op on a hosted shard.
    pub fn update_remote_replicas(&self, addrs: Vec<String>) {
        if let Some(r) = self.remote_backend() {
            r.set_replicas(addrs);
        }
    }

    /// Typed read access to the shard's applied state (local or remote).
    pub fn store(&self) -> RoomStore {
        match &self.backend {
            RoomBackend::Hosted(h) => RoomStore::new(h.read_ctx()),
            RoomBackend::Remote(r) => RoomStore::remote(r.clone()),
        }
    }

    /// Subscribe to the room shard's change stream (hosted shards only —
    /// use [`Self::changes`] for backend-agnostic tailing).
    pub fn subscribe(&self) -> broadcast::Receiver<ChangeRecord> {
        self.shard_handle().subscribe()
    }

    /// The shard's current sequence number — the anchor for
    /// [`Self::changes`] when a consumer wants "from now".
    pub async fn current_seq(&self) -> Result<u64> {
        match &self.backend {
            RoomBackend::Hosted(h) => Ok(h.seq()?),
            RoomBackend::Remote(r) => match r
                .read(saltator_shard::ReadOp::Seq)
                .await
                .map_err(RoomError::from)?
            {
                saltator_shard::ReadValue::Seq(s) => Ok(s),
                other => Err(RoomError::Codec(format!("seq read returned {other:?}"))),
            },
        }
    }

    /// The change stream from `from_seq` (exclusive), local or remote —
    /// the backend-agnostic form every tailing consumer uses.
    pub fn changes(&self, from_seq: u64) -> RoomChanges {
        match &self.backend {
            RoomBackend::Hosted(h) => RoomChanges::Local {
                rx: h.subscribe(),
                handle: h.clone(),
                last: from_seq,
                buffer: std::collections::VecDeque::new(),
            },
            RoomBackend::Remote(r) => RoomChanges::Remote(r.subscribe(from_seq)),
        }
    }

    /// Server names (other than `exclude`) of users currently joined to
    /// `room_id` — the destinations an outbound event must reach. Empty if
    /// the room is unknown.
    /// The `content` and `sender` of the state event that `event_id` replaced
    /// for its own `(type, state_key)` — i.e. `unsigned.prev_content` /
    /// `unsigned.prev_sender`. Found via the event's `auth_events`, which for a
    /// membership event include the target's prior membership (so a join's
    /// previous invite is available even in an imported room). `None` for a
    /// non-state event or when there is no prior entry.
    pub async fn prev_state_content(
        &self,
        event_id: &str,
    ) -> Result<Option<(serde_json::Value, String)>> {
        let store = self.store();
        let Some(stored) = store.event(event_id).await.map_err(storage_err)? else {
            return Ok(None);
        };
        let raw: serde_json::Value =
            serde_json::from_slice(&stored.raw).map_err(|e| RoomError::Codec(e.to_string()))?;
        let (Some(etype), Some(skey)) = (
            raw.get("type").and_then(|v| v.as_str()),
            raw.get("state_key").and_then(|v| v.as_str()),
        ) else {
            return Ok(None);
        };
        let auth_ids: Vec<&str> = raw
            .get("auth_events")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        for auth_id in auth_ids {
            let Some(ae) = store.event(auth_id).await.map_err(storage_err)? else {
                continue;
            };
            let aev: serde_json::Value =
                serde_json::from_slice(&ae.raw).map_err(|e| RoomError::Codec(e.to_string()))?;
            if aev.get("type").and_then(|v| v.as_str()) == Some(etype)
                && aev.get("state_key").and_then(|v| v.as_str()) == Some(skey)
            {
                let content = aev
                    .get("content")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let sender = aev
                    .get("sender")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned();
                return Ok(Some((content, sender)));
            }
        }
        Ok(None)
    }

    pub async fn remote_servers_in_room(
        &self,
        room_id: &str,
        exclude: &str,
    ) -> Result<Vec<String>> {
        let store = self.store();
        let Some(meta) = store
            .meta(room_id)
            .await
            .map_err(|e| RoomError::Storage(e.to_string()))?
        else {
            return Ok(Vec::new());
        };
        let state = store
            .resolve_group(room_id, meta.current_group)
            .await
            .map_err(|e| RoomError::Storage(e.to_string()))?;
        let mut servers = BTreeSet::new();
        for ((event_type, state_key), event_id) in &state {
            if event_type != "m.room.member" {
                continue;
            }
            let Some(stored) = store
                .event(event_id)
                .await
                .map_err(|e| RoomError::Storage(e.to_string()))?
            else {
                continue;
            };
            let raw: serde_json::Value =
                serde_json::from_slice(&stored.raw).map_err(|e| RoomError::Codec(e.to_string()))?;
            let joined = raw
                .get("content")
                .and_then(|c| c.get("membership"))
                .and_then(|m| m.as_str())
                == Some("join");
            if !joined {
                continue;
            }
            if let Ok(user) = UserId::parse(state_key.as_str()) {
                let server = user.server_name().as_str();
                if server != exclude {
                    servers.insert(server.to_owned());
                }
            }
        }
        Ok(servers.into_iter().collect())
    }

    /// Decode a change-stream payload.
    pub fn decode_change(payload: &[u8]) -> Result<ChangePayload> {
        postcard::from_bytes(payload).map_err(|e| RoomError::Codec(e.to_string()))
    }

    /// Trust verification keys for a remote entity outright.
    ///
    /// A test and static-configuration seam. The production path fetches
    /// and caches published keys instead (`saltator_federation::KeyCache`)
    /// rather than being told what to trust.
    pub async fn trust_keys(&self, entity: &str, keys: BTreeMap<String, ruma::serde::Base64>) {
        self.verify_keys
            .write()
            .expect("verify_keys lock poisoned")
            .insert(entity.to_owned(), keys.clone());
        // A remote shard verifies at its hosting node: the trust must
        // land THERE before any ingest intent that relies on it.
        if let Some(r) = self.remote_backend() {
            let intent = remote::RoomIntent::TrustKeys {
                entity: entity.to_owned(),
                keys,
            };
            if let Err(e) = remote::call(r, &intent).await {
                tracing::warn!(entity, error = %e, "remote trust_keys failed");
            }
        }
    }

    pub async fn shutdown(&self) -> Result<()> {
        match &self.backend {
            RoomBackend::Hosted(h) => Ok(h.shutdown().await?),
            RoomBackend::Remote(_) => Ok(()),
        }
    }

    // -- public pipeline entry points ------------------------------------

    /// Create a room: build, sign, and run the `m.room.create` event
    /// through the pipeline. `content` must not contain `room_version`
    /// (it is set from `version`).
    pub async fn create_room(
        &self,
        creator: &UserId,
        version: RoomVersion,
        content: serde_json::Map<String, serde_json::Value>,
    ) -> Result<(OwnedRoomId, Outcome)> {
        if let Some(r) = self.remote_backend() {
            let intent = remote::RoomIntent::CreateRoom {
                creator: creator.to_string(),
                version: version.as_str().to_owned(),
                content,
            };
            return match remote::call(r, &intent).await? {
                remote::RoomIntentOk::Created(id, outcome) => Ok((
                    OwnedRoomId::try_from(id).map_err(|e| RoomError::Malformed(e.to_string()))?,
                    outcome,
                )),
                other => Err(RoomError::Codec(format!("expected Created, got {other:?}"))),
            };
        }
        let (room_id, raw) = self.build_create(creator, version, content)?;
        let outcome = self.apply_create(&room_id, version, raw).await?;
        Ok((room_id, outcome))
    }

    /// Build and sign the create event, deriving the room id — shard-
    /// agnostic (only the shared signer is touched), so the router can
    /// build anywhere and apply on the hash home.
    pub fn build_create(
        &self,
        creator: &UserId,
        version: RoomVersion,
        content: serde_json::Map<String, serde_json::Value>,
    ) -> Result<(OwnedRoomId, CanonicalJsonObject)> {
        let mut content = content;
        content.insert("room_version".into(), version.as_str().into());
        // ≤v10: the create content names the creator (v11 removed it —
        // the sender is authoritative).
        if version.creator_in_create_content() {
            content.insert("creator".into(), creator.as_str().into());
        }

        let mut obj = serde_json::json!({
            "sender": creator.as_str(),
            "origin_server_ts": now_ms(),
            "type": "m.room.create",
            "state_key": "",
            "content": content,
            "auth_events": [],
            "prev_events": [],
            "depth": 1,
        });
        if !version.room_id_is_create_event_id() {
            let room_id = ruma::RoomId::new_v1(self.signer.server_name());
            obj["room_id"] = room_id.as_str().into();
        }
        let mut raw = canonicalize(obj)?;
        self.signer.hash_and_sign_event(&mut raw, version)?;

        let room_id = if version.room_id_is_create_event_id() {
            event::room_id_for_create(&raw, version)?
        } else {
            room_id_of(&raw)?
        };

        Ok((room_id, raw))
    }

    /// Apply a signed create event built by [`Self::build_create`] — the
    /// second half of room creation, run on the shard the derived room id
    /// hashes to (a v12 room's id comes from the event, so the shard is
    /// unknowable until the event exists).
    pub async fn apply_create(
        &self,
        room_id: &OwnedRoomId,
        version: RoomVersion,
        raw: CanonicalJsonObject,
    ) -> Result<Outcome> {
        if self.remote_backend().is_some() {
            // The create was built (and signed) HERE so the room id —
            // and with it the owning shard — could be derived; a signed
            // create is a complete PDU, so the hosting leader ingests it.
            return self.ingest_pdu(raw).await;
        }
        let _guard = self.lock_room(room_id.as_str()).await;
        self.process(raw, version, room_id, true, false).await
    }

    /// Build, sign, and send a local state event.
    pub async fn send_state(
        &self,
        room_id: &ruma::RoomId,
        sender: &UserId,
        event_type: &str,
        state_key: &str,
        content: serde_json::Value,
    ) -> Result<Outcome> {
        if let Some(r) = self.remote_backend() {
            let intent = remote::RoomIntent::SendState {
                room_id: room_id.to_string(),
                sender: sender.to_string(),
                event_type: event_type.to_owned(),
                state_key: state_key.to_owned(),
                content,
                ts: None,
            };
            return remote::want_outcome(remote::call(r, &intent).await?);
        }
        self.send_local(room_id, sender, event_type, Some(state_key), content, None)
            .await
    }

    /// [`send_state`](Self::send_state) with an appservice-supplied
    /// `origin_server_ts` (`?ts` timestamp massaging; DAG position is
    /// unaffected, exactly as for messages).
    pub async fn send_state_at(
        &self,
        room_id: &ruma::RoomId,
        sender: &UserId,
        event_type: &str,
        state_key: &str,
        content: serde_json::Value,
        ts: u64,
    ) -> Result<Outcome> {
        if let Some(r) = self.remote_backend() {
            let intent = remote::RoomIntent::SendState {
                room_id: room_id.to_string(),
                sender: sender.to_string(),
                event_type: event_type.to_owned(),
                state_key: state_key.to_owned(),
                content,
                ts: Some(ts),
            };
            return remote::want_outcome(remote::call(r, &intent).await?);
        }
        self.send_local(
            room_id,
            sender,
            event_type,
            Some(state_key),
            content,
            Some(ts),
        )
        .await
    }

    /// Build, sign, and send a local message (non-state) event.
    pub async fn send_message(
        &self,
        room_id: &ruma::RoomId,
        sender: &UserId,
        event_type: &str,
        content: serde_json::Value,
    ) -> Result<Outcome> {
        if let Some(r) = self.remote_backend() {
            let intent = remote::RoomIntent::SendMessage {
                room_id: room_id.to_string(),
                sender: sender.to_string(),
                event_type: event_type.to_owned(),
                content,
                ts: None,
            };
            return remote::want_outcome(remote::call(r, &intent).await?);
        }
        self.send_local(room_id, sender, event_type, None, content, None)
            .await
    }

    /// [`Self::send_message`] with an explicit `origin_server_ts` —
    /// appservice timestamp massaging (`?ts=`, MSC3316). The event still
    /// lands at the timeline tip; only its claimed time changes.
    pub async fn send_message_at(
        &self,
        room_id: &ruma::RoomId,
        sender: &UserId,
        event_type: &str,
        content: serde_json::Value,
        ts: u64,
    ) -> Result<Outcome> {
        if let Some(r) = self.remote_backend() {
            let intent = remote::RoomIntent::SendMessage {
                room_id: room_id.to_string(),
                sender: sender.to_string(),
                event_type: event_type.to_owned(),
                content,
                ts: Some(ts),
            };
            return remote::want_outcome(remote::call(r, &intent).await?);
        }
        self.send_local(room_id, sender, event_type, None, content, Some(ts))
            .await
    }

    /// Ingest a complete PDU (the federation-shaped entry point): raw
    /// canonical JSON, signatures and hashes included.
    pub async fn ingest_pdu(&self, raw: CanonicalJsonObject) -> Result<Outcome> {
        if let Some(r) = self.remote_backend() {
            let intent = remote::RoomIntent::IngestPdu {
                raw,
                origin: None,
                healing: false,
                reject_missing_auth: false,
            };
            return remote::want_outcome(remote::call(r, &intent).await?);
        }
        let (version, room_id, is_create) = self.classify(&raw).await?;
        let _guard = self.lock_room(room_id.as_str()).await;
        // Ordinary inbound PDU: its origin is responsible for distributing it,
        // so we do not relay it onward.
        self.process(raw, version, &room_id, is_create, false).await
    }

    /// Like [`Self::ingest_pdu`], but an event whose `auth_events` cite
    /// events not present locally is stored *rejected* against its auth
    /// chain instead of failing with [`RoomError::MissingAuthEvents`].
    /// For use only after fetching the cited events has already been
    /// tried and failed: an unfetchable auth ancestor makes the event
    /// permanently unverifiable, and rejecting it (rather than erroring)
    /// is what lets the events built on top of it resolve as rejected in
    /// turn and the transaction succeed (Synapse's behaviour;
    /// Complement's TestCorruptedAuthChain).
    pub async fn ingest_pdu_rejecting_missing_auth(
        &self,
        raw: CanonicalJsonObject,
    ) -> Result<Outcome> {
        if let Some(r) = self.remote_backend() {
            let intent = remote::RoomIntent::IngestPdu {
                raw,
                origin: None,
                healing: false,
                reject_missing_auth: true,
            };
            return remote::want_outcome(remote::call(r, &intent).await?);
        }
        let (version, room_id, is_create) = self.classify(&raw).await?;
        let _guard = self.lock_room(room_id.as_str()).await;
        self.process_inner(raw, version, &room_id, is_create, false, true)
            .await
    }

    /// Verify a single PDU's structure, signature, and content hash against
    /// the currently trusted keys, WITHOUT ingesting it. Returns `true`
    /// only when fully verified. Used to vet off-timeline state snapshots
    /// (gap-fill `/state`) before trusting them — the caller must first
    /// trust the keys of every server that authored one of the events.
    /// Looks the room version up from stored meta; use
    /// [`Self::verify_pdu_at`] when the room does not exist locally yet
    /// (a fresh send_join).
    pub async fn verify_pdu(&self, room_id: &str, raw: &CanonicalJsonObject) -> bool {
        let Ok(Some(meta)) = self.store().meta(room_id).await else {
            return false;
        };
        let Ok(version) = RoomVersion::parse(&meta.version) else {
            return false;
        };
        self.verify_pdu_at(version, raw)
    }

    /// Like [`Self::verify_pdu`] but with an explicit room version, so it
    /// works before the room is stored locally (send_join import). The
    /// caller must have trusted the authoring servers' keys first.
    pub fn verify_pdu_at(&self, version: RoomVersion, raw: &CanonicalJsonObject) -> bool {
        if validation::validate_pdu(raw, version).is_err() {
            return false;
        }
        let keys = self
            .verify_keys
            .read()
            .expect("verify_keys lock poisoned")
            .clone();
        matches!(
            validation::verify_event(raw, version, &keys),
            Ok(VerifyOutcome::Verified)
        )
    }

    /// The event ID a PDU will have, without ingesting it. Lets the
    /// `/send` handler key per-PDU results even when ingest fails before an
    /// [`Outcome`] exists. `None` if the PDU is too malformed to classify.
    pub async fn pdu_event_id(&self, raw: &CanonicalJsonObject) -> Option<OwnedEventId> {
        let (version, _room_id, _is_create) = self.classify(raw).await.ok()?;
        event::event_id(raw, version).ok()
    }

    /// Build and sign an `m.room.member` invite for `target` (a remote
    /// user), without applying it: a remote invitee's server must co-sign
    /// it (via `PUT /invite`) before we ingest the co-signed event. Returns
    /// the room version and the signed event.
    pub async fn build_invite(
        &self,
        room_id: &ruma::RoomId,
        sender: &UserId,
        target: &UserId,
        mut content: serde_json::Map<String, serde_json::Value>,
    ) -> Result<(RoomVersion, CanonicalJsonObject)> {
        if let Some(r) = self.remote_backend() {
            let intent = remote::RoomIntent::BuildInvite {
                room_id: room_id.to_string(),
                sender: sender.to_string(),
                target: target.to_string(),
                content,
            };
            return match remote::call(r, &intent).await? {
                remote::RoomIntentOk::Invite(version, raw) => {
                    Ok((RoomVersion::parse(&version)?, raw))
                }
                other => Err(RoomError::Codec(format!("expected Invite, got {other:?}"))),
            };
        }
        let _guard = self.lock_room(room_id.as_str()).await;
        // `membership: invite` is authoritative; extra content (e.g. the
        // `is_direct` flag) rides along on the invite member event.
        content.insert("membership".to_owned(), "invite".into());
        let (raw, version) = self
            .build_local(
                room_id,
                sender,
                "m.room.member",
                Some(target.as_str()),
                serde_json::Value::Object(content),
                None,
            )
            .await?;
        Ok((version, raw))
    }

    /// Build an unsigned `m.room.member` join template for `user_id` (a
    /// user on another server) — the `GET /make_join` response. prev/auth
    /// events and depth are computed from current room state; the joining
    /// server fills in `origin`/`origin_server_ts`/`event_id` and signs.
    pub async fn make_join_template(
        &self,
        peers: &shards::RoomShards,
        room_id: &ruma::RoomId,
        user_id: &UserId,
    ) -> Result<(RoomVersion, CanonicalJsonObject)> {
        // A restricted / knock_restricted room needs an authorising local
        // user stamped into the template; a non-restricted room yields
        // `NotNeeded`. Denials become the spec errcodes at the fed layer.
        let authoriser = match self
            .restricted_join_authoriser(peers, room_id, user_id)
            .await?
        {
            RestrictedAuth::NotNeeded => None,
            RestrictedAuth::Authorised(u) => Some(u),
            RestrictedAuth::FailsConditions => {
                return Err(RoomError::CannotAuthoriseJoin(RestrictedDenial::Forbidden))
            }
            RestrictedAuth::CannotValidate => {
                return Err(RoomError::CannotAuthoriseJoin(
                    RestrictedDenial::CannotValidate,
                ))
            }
            RestrictedAuth::CannotGrant => {
                return Err(RoomError::CannotAuthoriseJoin(
                    RestrictedDenial::CannotGrant,
                ))
            }
        };
        self.make_membership_template(room_id, user_id, "join", authoriser.as_deref())
            .await
    }

    /// Build an unsigned `m.room.member` leave template — the `GET
    /// /make_leave` response (used to reject a remote invite or leave a
    /// remote room).
    pub async fn make_leave_template(
        &self,
        room_id: &ruma::RoomId,
        user_id: &UserId,
    ) -> Result<(RoomVersion, CanonicalJsonObject)> {
        self.make_membership_template(room_id, user_id, "leave", None)
            .await
    }

    /// Build an unsigned `m.room.member` knock template — the `GET
    /// /make_knock` response. The knocking server fills in
    /// `origin`/`origin_server_ts`/`reason`/`event_id` and signs.
    pub async fn make_knock_template(
        &self,
        room_id: &ruma::RoomId,
        user_id: &UserId,
    ) -> Result<(RoomVersion, CanonicalJsonObject)> {
        self.make_membership_template(room_id, user_id, "knock", None)
            .await
    }

    /// The raw content-bearing event for `(ty, sk)` in a resolved state
    /// map, loaded from the store that map came from.
    async fn state_event_content(
        &self,
        store: &RoomStore,
        state: &std::collections::BTreeMap<(String, String), String>,
        ty: &str,
        sk: &str,
    ) -> Result<Option<CanonicalJsonObject>> {
        let Some(event_id) = state.get(&(ty.to_owned(), sk.to_owned())) else {
            return Ok(None);
        };
        self.load_raw(store, event_id).await
    }

    /// `user`'s membership in a resolved state map — read from the store
    /// the map came from (an allow room's events live in ITS shard).
    async fn membership_in(
        &self,
        store: &RoomStore,
        state: &std::collections::BTreeMap<(String, String), String>,
        user: &str,
    ) -> Result<String> {
        let Some(event_id) = state.get(&("m.room.member".to_owned(), user.to_owned())) else {
            return Ok("leave".to_owned());
        };
        let Some(obj) = self.load_raw(store, event_id).await? else {
            return Ok("leave".to_owned());
        };
        Ok(obj
            .get("content")
            .and_then(|c| c.as_object())
            .and_then(|c| c.get("membership"))
            .and_then(|m| m.as_str())
            .unwrap_or("leave")
            .to_owned())
    }

    /// Decide whether `joiner` may join the restricted / `knock_restricted`
    /// room `room_id`, and if so which local user authorises it
    /// (MSC3083/MSC3787). Returns [`RestrictedAuth::NotNeeded`] for any room
    /// whose join rule is not restricted (so callers can invoke it
    /// unconditionally). This is only the authorising decision — the auth
    /// rules independently validate the resulting event.
    ///
    /// `peers` routes the allow-condition reads: an allow room usually
    /// lives in a *different* shard than the room being joined, and
    /// reading it from this shard's store would report it unknown —
    /// refusing to vouch for a room the server does hold.
    pub async fn restricted_join_authoriser(
        &self,
        peers: &shards::RoomShards,
        room_id: &ruma::RoomId,
        joiner: &UserId,
    ) -> Result<RestrictedAuth> {
        let store = self.store();
        let Some(meta) = store.meta(room_id.as_str()).await.map_err(storage_err)? else {
            // We don't hold the room — nothing to authorise locally.
            return Ok(RestrictedAuth::NotNeeded);
        };
        let version = RoomVersion::parse(&meta.version)?;
        let state = store
            .resolve_group(room_id.as_str(), meta.current_group)
            .await
            .map_err(storage_err)?;

        // Join rule + allow list (both live in the join_rules event content).
        let join_rules_ev = self
            .state_event_content(&store, &state, "m.room.join_rules", "")
            .await?;
        let jr_content = join_rules_ev
            .as_ref()
            .and_then(|e| e.get("content"))
            .and_then(|c| c.as_object());
        let join_rule = jr_content
            .and_then(|c| c.get("join_rule"))
            .and_then(|v| v.as_str())
            .unwrap_or("invite");
        if !matches!(join_rule, "restricted" | "knock_restricted") {
            return Ok(RestrictedAuth::NotNeeded);
        }

        // An already-joined or -invited user needs no authoriser (auth rule
        // 5.3.5.1 allows the join outright).
        if matches!(
            self.membership_in(&store, &state, joiner.as_str())
                .await?
                .as_str(),
            "join" | "invite"
        ) {
            return Ok(RestrictedAuth::NotNeeded);
        }

        // Evaluate the `allow` conditions.
        let entries = match jr_content.and_then(|c| c.get("allow")) {
            Some(CanonicalJsonValue::Array(a)) => a.clone(),
            // Malformed / missing `allow` degrades to invite-only.
            _ => return Ok(RestrictedAuth::FailsConditions),
        };
        let mut condition_met = false;
        let mut uncheckable = false;
        for entry in &entries {
            let CanonicalJsonValue::Object(o) = entry else {
                continue;
            };
            if o.get("type").and_then(|v| v.as_str()) != Some("m.room_membership") {
                continue;
            }
            let Some(allowed_room) = o.get("room_id").and_then(|v| v.as_str()) else {
                continue;
            };
            // The allow room routes by ITS OWN id — usually a different
            // shard than the room being joined.
            let allow_store = peers.for_room(allowed_room).store();
            match allow_store.meta(allowed_room).await.map_err(storage_err)? {
                None => uncheckable = true,
                Some(m2) => {
                    let s2 = allow_store
                        .resolve_group(allowed_room, m2.current_group)
                        .await
                        .map_err(storage_err)?;
                    // Our copy of the allow room is authoritative only
                    // while one of our users is joined to it — once the
                    // last local member leaves we stop receiving its
                    // events, so any membership read would be stale.
                    // Synapse likewise refuses to vouch from a room it no
                    // longer participates in (M_UNABLE_TO_AUTHORISE_JOIN;
                    // TestRestrictedRoomsRemoteJoinFailOver's second leg).
                    let our_name = self.signer.server_name();
                    let mut participating = false;
                    for (ty, sk) in s2.keys() {
                        if ty != "m.room.member" {
                            continue;
                        }
                        let Ok(uid) = OwnedUserId::try_from(sk.clone()) else {
                            continue;
                        };
                        if uid.server_name() == our_name
                            && self.membership_in(&allow_store, &s2, sk).await? == "join"
                        {
                            participating = true;
                            break;
                        }
                    }
                    if !participating {
                        uncheckable = true;
                    } else if self
                        .membership_in(&allow_store, &s2, joiner.as_str())
                        .await?
                        == "join"
                    {
                        condition_met = true;
                        break;
                    }
                }
            }
        }
        if !condition_met {
            return Ok(if uncheckable {
                RestrictedAuth::CannotValidate
            } else {
                RestrictedAuth::FailsConditions
            });
        }

        // A condition is met — pick a local member with invite power to be
        // the authorising user. Any powered local member works (MSC3083 does
        // not require a room *creator*); prefer the highest power for a
        // stable, unambiguous choice.
        let Some(create_raw) = self
            .state_event_content(&store, &state, "m.room.create", "")
            .await?
        else {
            return Err(RoomError::Malformed("room has no create event".into()));
        };
        let create = IdentifiedPdu::from_canonical(&create_raw, version)
            .map_err(|e| RoomError::Malformed(e.to_string()))?;
        let pl = self
            .state_event_content(&store, &state, "m.room.power_levels", "")
            .await?
            .map(|raw| IdentifiedPdu::from_canonical(&raw, version))
            .transpose()
            .map_err(|e| RoomError::Malformed(e.to_string()))?;
        let power = RoomPowerLevels::resolve(version, &create, pl.as_ref())
            .map_err(|e| RoomError::Malformed(e.to_string()))?;

        let our_name = self.signer.server_name();
        let mut best: Option<(OwnedUserId, PowerLevel)> = None;
        for (ty, sk) in state.keys() {
            if ty != "m.room.member" {
                continue;
            }
            let Ok(uid) = OwnedUserId::try_from(sk.clone()) else {
                continue;
            };
            if uid.server_name() != our_name {
                continue;
            }
            if self.membership_in(&store, &state, sk).await? != "join" {
                continue;
            }
            let level = power.user(&uid);
            if level.satisfies(power.invite) && best.as_ref().is_none_or(|(_, b)| level > *b) {
                best = Some((uid, level));
            }
        }
        Ok(match best {
            Some((u, _)) => RestrictedAuth::Authorised(u),
            None => RestrictedAuth::CannotGrant,
        })
    }

    async fn make_membership_template(
        &self,
        room_id: &ruma::RoomId,
        user_id: &UserId,
        membership: &str,
        authoriser: Option<&UserId>,
    ) -> Result<(RoomVersion, CanonicalJsonObject)> {
        let store = self.store();
        let meta = store
            .meta(room_id.as_str())
            .await
            .map_err(storage_err)?
            .ok_or_else(|| RoomError::UnknownRoom(room_id.to_string()))?;
        let version = RoomVersion::parse(&meta.version)?;
        let current = store
            .resolve_group(room_id.as_str(), meta.current_group)
            .await
            .map_err(storage_err)?;

        let mut depth: u64 = 0;
        for id in &meta.extremities {
            let prev = store
                .event(id)
                .await
                .map_err(storage_err)?
                .ok_or_else(|| RoomError::MissingEvents(vec![id.clone()]))?;
            depth = depth.max(prev.depth);
        }

        let mut content = serde_json::json!({ "membership": membership });
        // A restricted join names the authorising user; stamping it before
        // `auth_types_for_event` ensures that user's membership is pulled
        // into `auth_events` (so the auth check can verify their power).
        if let Some(authoriser) = authoriser {
            content["join_authorised_via_users_server"] = authoriser.as_str().into();
        }
        let content_obj = canonicalize(content)?;
        let auth_types = auth::auth_types_for_event(
            version,
            "m.room.member",
            user_id,
            Some(user_id.as_str()),
            &content_obj,
        );
        let auth_events: Vec<&String> = auth_types.iter().filter_map(|k| current.get(k)).collect();

        let template = canonicalize(serde_json::json!({
            "room_id": room_id.as_str(),
            "sender": user_id.as_str(),
            "state_key": user_id.as_str(),
            "origin_server_ts": now_ms(),
            "type": "m.room.member",
            "content": CanonicalJsonValue::Object(content_obj),
            "auth_events": auth_events,
            "prev_events": meta.extremities,
            "depth": depth + 1,
        }))?;
        Ok((version, template))
    }

    /// Apply a remote server's signed leave/reject event (`PUT
    /// /send_leave`). Verifies + persists it through the normal pipeline
    /// (the outbound sender distributes it). The caller must have trusted
    /// the origin's keys.
    pub async fn send_leave(&self, raw: CanonicalJsonObject) -> Result<Outcome> {
        if let Some(r) = self.remote_backend() {
            return remote::want_outcome(
                remote::call(r, &remote::RoomIntent::SendLeave { raw }).await?,
            );
        }
        let (version, room_id, _is_create) = self.classify(&raw).await?;
        let _guard = self.lock_room(room_id.as_str()).await;
        // We are the resident servicing this leave/reject handshake: flag the
        // membership so the outbound sender relays it to the room's other
        // servers (spec "Leaving Rooms").
        self.process(raw, version, &room_id, false, true).await
    }

    /// The room's current forward extremities (the DAG leaves). Empty if
    /// the room is unknown. Used as `earliest_events` when requesting a
    /// gap fill, so the peer walks back only to what we already have.
    pub async fn room_extremities(&self, room_id: &str) -> Result<Vec<String>> {
        Ok(self
            .store()
            .meta(room_id)
            .await
            .map_err(storage_err)?
            .map(|m| m.extremities)
            .unwrap_or_default())
    }

    /// The event closest to `ts` (MSC3030 "jump to date"), shared by the
    /// CS and federation `timestamp_to_event` endpoints. Forwards
    /// (`backward == false`) returns the first event at or after `ts`,
    /// backwards the last at or before; ties break by room order
    /// (earliest forwards, latest backwards). `None` when no event
    /// qualifies. Searches the local timeline, plus already-backfilled
    /// history when `include_history` (the CS route gates that on the
    /// room's history visibility, like `/messages`); chasing history we
    /// don't hold yet (the federated fallback) is the caller's concern.
    pub async fn timestamp_to_event(
        &self,
        room_id: &str,
        ts: u64,
        backward: bool,
        include_history: bool,
    ) -> Result<Option<(String, u64)>> {
        let store = self.store();
        // One chronological position across both orders: history sits
        // below the whole timeline, and its indexes grow *older*.
        let timeline = store
            .room_timeline(room_id, 0, None, usize::MAX, false)
            .await
            .map_err(storage_err)?
            .into_iter()
            .map(|(seq, id)| ((1u64, seq), id));
        let history = if include_history {
            store
                .room_history(room_id, 0, None, usize::MAX, false)
                .await
                .map_err(storage_err)?
        } else {
            Vec::new()
        }
        .into_iter()
        .map(|(idx, id)| ((0u64, u64::MAX - idx), id));
        let mut best: Option<(u64, (u64, u64), String)> = None;
        for (pos, id) in timeline.chain(history) {
            let Some(stored) = store.event(&id).await.map_err(storage_err)? else {
                continue;
            };
            let raw: serde_json::Value = match serde_json::from_slice(&stored.raw) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let Some(ots) = raw.get("origin_server_ts").and_then(|t| t.as_u64()) else {
                continue;
            };
            let matches_dir = if backward { ots <= ts } else { ots >= ts };
            if !matches_dir {
                continue;
            }
            let better = match &best {
                None => true,
                Some((bts, bpos, _)) if backward => (ots, pos) > (*bts, *bpos),
                Some((bts, bpos, _)) => (ots, pos) < (*bts, *bpos),
            };
            if better {
                best = Some((ots, pos, id));
            }
        }
        Ok(best.map(|(ots, _, id)| (id, ots)))
    }

    /// Whether `server` currently has a joined user in the room — the
    /// membership check inbound federation endpoints apply before serving
    /// room data (state, timestamps) to a caller.
    pub async fn server_in_room(&self, room_id: &str, server: &str) -> Result<bool> {
        Ok(self
            .remote_servers_in_room(room_id, "")
            .await?
            .iter()
            .any(|s| s == server))
    }

    /// Whether `server` has a user with a *pending invite* in the room's
    /// current state. An invited server is not a stranger — the room
    /// reached out to it, and it must be able to fetch the invite's
    /// supporting events (`/event`) to ingest the invite into a copy of
    /// the room it already hosts. Counts exactly `invite`: a ban or a
    /// leave is not an invitation.
    pub async fn server_invited_to_room(&self, room_id: &str, server: &str) -> Result<bool> {
        let store = self.store();
        let Some(meta) = store
            .meta(room_id)
            .await
            .map_err(|e| RoomError::Storage(e.to_string()))?
        else {
            return Ok(false);
        };
        let state = store
            .resolve_group(room_id, meta.current_group)
            .await
            .map_err(|e| RoomError::Storage(e.to_string()))?;
        let suffix = format!(":{server}");
        for ((event_type, state_key), event_id) in &state {
            if event_type != "m.room.member" || !state_key.ends_with(&suffix) {
                continue;
            }
            let Some(stored) = store
                .event(event_id)
                .await
                .map_err(|e| RoomError::Storage(e.to_string()))?
            else {
                continue;
            };
            let raw: serde_json::Value =
                serde_json::from_slice(&stored.raw).map_err(|e| RoomError::Codec(e.to_string()))?;
            if raw
                .get("content")
                .and_then(|c| c.get("membership"))
                .and_then(|m| m.as_str())
                == Some("invite")
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Apply per-server history visibility to events about to be served
    /// over federation (`/backfill`, `/get_missing_events` — Synapse's
    /// `filter_events_for_server`): an event whose visibility at that
    /// point was `joined`/`invited`, at which `server` had no user with
    /// the required membership, is replaced by its redacted copy. Events
    /// under `shared`/`world_readable` (and events whose state we cannot
    /// resolve — outliers, rejected) pass through unchanged.
    pub async fn filter_events_for_server(
        &self,
        room_id: &str,
        server: &str,
        events: Vec<CanonicalJsonObject>,
    ) -> Result<Vec<CanonicalJsonObject>> {
        let store = self.store();
        let Some(meta) = store.meta(room_id).await.map_err(storage_err)? else {
            return Ok(events);
        };
        let version = RoomVersion::parse(&meta.version)?;
        let mut out = Vec::with_capacity(events.len());
        for raw in events {
            let visible = async {
                let Some(id) = self.pdu_event_id(&raw).await else {
                    return Ok::<bool, RoomError>(true);
                };
                let Some(stored) = store.event(id.as_str()).await.map_err(storage_err)? else {
                    return Ok(true);
                };
                if stored.state_group_after == 0 {
                    return Ok(true); // no state known: treat as visible
                }
                let state = store
                    .resolve_group(room_id, stored.state_group_after)
                    .await
                    .map_err(storage_err)?;
                let vis_eid = state
                    .get(&("m.room.history_visibility".to_owned(), String::new()))
                    .cloned();
                let vis_ev = match &vis_eid {
                    Some(eid) => self.load_raw(&store, eid).await.ok().flatten(),
                    None => None,
                };
                let vis = vis_ev
                    .and_then(|ev| {
                        ev.get("content")
                            .and_then(|c| c.as_object())
                            .and_then(|c| c.get("history_visibility"))
                            .and_then(|v| v.as_str())
                            .map(ToOwned::to_owned)
                    })
                    .unwrap_or_else(|| "shared".to_owned());
                let required: &[&str] = match vis.as_str() {
                    "joined" => &["join"],
                    "invited" => &["join", "invite"],
                    _ => return Ok(true), // shared / world_readable
                };
                for ((ty, sk), eid) in &state {
                    if ty != "m.room.member" {
                        continue;
                    }
                    let Ok(uid) = OwnedUserId::try_from(sk.clone()) else {
                        continue;
                    };
                    if uid.server_name() != server {
                        continue;
                    }
                    let membership = self.load_raw(&store, eid).await?.and_then(|ev| {
                        ev.get("content")
                            .and_then(|c| c.as_object())
                            .and_then(|c| c.get("membership"))
                            .and_then(|m| m.as_str())
                            .map(ToOwned::to_owned)
                    });
                    if membership.is_some_and(|m| required.contains(&m.as_str())) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            .await?;
            if visible {
                out.push(raw);
            } else {
                out.push(
                    saltator_core::validation::redact(&raw, version)
                        .map_err(|e| RoomError::Malformed(e.to_string()))?,
                );
            }
        }
        Ok(out)
    }

    /// The room's current `m.room.server_acl`, if any is set.
    pub async fn server_acl(&self, room_id: &str) -> Result<Option<saltator_core::acl::ServerAcl>> {
        let store = self.store();
        let Some(meta) = store.meta(room_id).await.map_err(storage_err)? else {
            return Ok(None);
        };
        let current = store
            .resolve_group(room_id, meta.current_group)
            .await
            .map_err(storage_err)?;
        let Some(event_id) = current.get(&("m.room.server_acl".to_owned(), String::new())) else {
            return Ok(None);
        };
        let Some(stored) = store.event(event_id).await.map_err(storage_err)? else {
            return Ok(None);
        };
        let raw: CanonicalJsonObject =
            serde_json::from_slice(&stored.raw).map_err(|e| RoomError::Codec(e.to_string()))?;
        match raw.get("content") {
            Some(CanonicalJsonValue::Object(content)) => {
                Ok(Some(saltator_core::acl::ServerAcl::from_content(content)))
            }
            _ => Ok(None),
        }
    }

    /// Whether the room's server ACL denies `server` from participating.
    /// False when the room is unknown or has no ACL (fail open — an ACL must
    /// be present to deny).
    pub async fn server_acl_denies(&self, room_id: &str, server: &str) -> bool {
        matches!(self.server_acl(room_id).await, Ok(Some(acl)) if !acl.is_allowed(server))
    }

    /// Walk the room DAG backward from `start` event IDs along
    /// `prev_events`, returning up to `limit` events (the `/backfill`
    /// response). The `start` events are included; highest-depth (most
    /// recent) first. Unknown start IDs are skipped; rejected events are
    /// not returned.
    pub async fn backfill(
        &self,
        start: &[String],
        limit: usize,
    ) -> Result<Vec<CanonicalJsonObject>> {
        self.walk_back(start.to_vec(), &BTreeSet::new(), limit, 0)
            .await
    }

    /// `POST /get_missing_events`: return the ancestors of `latest`
    /// (the events themselves excluded) along `prev_events`, stopping at
    /// and excluding `earliest`, up to `limit` events at depth ≥
    /// `min_depth`. Oldest (lowest-depth) first — the order a requester
    /// applies them in.
    pub async fn get_missing_events(
        &self,
        earliest: &[String],
        latest: &[String],
        limit: usize,
        min_depth: u64,
    ) -> Result<Vec<CanonicalJsonObject>> {
        let store = self.store();
        // Exclude both the earliest boundary and the latest events
        // themselves; seed the walk with the latest events' parents.
        let mut stop: BTreeSet<String> = earliest.iter().cloned().collect();
        let mut seed = Vec::new();
        for id in latest {
            stop.insert(id.clone());
            if let Some(stored) = store.event(id).await.map_err(storage_err)? {
                let raw: CanonicalJsonObject = serde_json::from_slice(&stored.raw)
                    .map_err(|e| RoomError::Codec(e.to_string()))?;
                seed.extend(prev_event_ids(&raw));
            }
        }
        let mut events = self.walk_back(seed, &stop, limit, min_depth).await?;
        events.reverse(); // newest-first walk → oldest-first response
        Ok(events)
    }

    /// Shared backward DAG walk: BFS over `prev_events` from `seed`,
    /// skipping `stop` IDs, collecting non-rejected events at depth ≥
    /// `min_depth`, newest (highest depth) first, capped at `limit`.
    async fn walk_back(
        &self,
        seed: Vec<String>,
        stop: &BTreeSet<String>,
        limit: usize,
        min_depth: u64,
    ) -> Result<Vec<CanonicalJsonObject>> {
        let store = self.store();
        let mut seen: BTreeSet<String> = stop.clone();
        // Frontier ordered by depth; process highest depth first.
        let mut frontier: BTreeSet<(u64, String)> = BTreeSet::new();
        for id in &seed {
            if seen.contains(id) {
                continue;
            }
            if let Some(ev) = store.event(id).await.map_err(storage_err)? {
                if ev.rejected.is_none() {
                    frontier.insert((ev.depth, id.clone()));
                }
            }
        }
        let mut out = Vec::new();
        while out.len() < limit {
            // Pop the highest-depth entry.
            let Some((depth, id)) = frontier.iter().next_back().cloned() else {
                break;
            };
            frontier.remove(&(depth, id.clone()));
            if !seen.insert(id.clone()) {
                continue;
            }
            let Some(stored) = store.event(&id).await.map_err(storage_err)? else {
                continue;
            };
            if stored.rejected.is_some() || stored.depth < min_depth {
                continue;
            }
            let raw: CanonicalJsonObject =
                serde_json::from_slice(&stored.raw).map_err(|e| RoomError::Codec(e.to_string()))?;
            for prev in prev_event_ids(&raw) {
                if !seen.contains(&prev) {
                    if let Some(pv) = store.event(&prev).await.map_err(storage_err)? {
                        if pv.rejected.is_none() {
                            frontier.insert((pv.depth, prev));
                        }
                    }
                }
            }
            out.push(raw);
        }
        Ok(out)
    }

    /// Apply a remote server's signed join event (`PUT /send_join`) and
    /// return the room's current state and its auth chain, plus the join
    /// co-signed by us. The caller must have trusted the origin's keys.
    pub async fn send_join(&self, raw: CanonicalJsonObject) -> Result<SendJoinResult> {
        if let Some(r) = self.remote_backend() {
            return match remote::call(r, &remote::RoomIntent::SendJoin { raw }).await? {
                remote::RoomIntentOk::Join(res) => Ok(res),
                other => Err(RoomError::Codec(format!("expected Join, got {other:?}"))),
            };
        }
        let (version, room_id, _is_create) = self.classify(&raw).await?;
        // Co-sign BEFORE validating/persisting. A restricted join names an
        // authorising user on THIS server, and auth rule 4.2 requires the
        // event to be signed by that user's homeserver (us) — so our
        // signature must be present when `process` verifies it, and the
        // stored + relayed event must carry it. Co-signing re-runs the
        // (identical) content hash and merges our signature alongside the
        // joiner's; it does not change the event ID (signatures are excluded
        // from the reference hash), so the joiner's `{eventId}` still matches.
        let mut signed = raw;
        self.signer.hash_and_sign_event(&mut signed, version)?;

        // Verify + persist through the normal pipeline (signature, hash,
        // auth against join rules).
        let outcome = {
            let _guard = self.lock_room(room_id.as_str()).await;
            // We are the resident servicing this join handshake: flag the
            // membership so the outbound sender relays it to the room's other
            // servers (spec "Joining Rooms": "The resident server must also
            // send the event to other servers participating in the room").
            self.process(signed.clone(), version, &room_id, false, true)
                .await?
        };
        match &outcome {
            Outcome::Accepted { .. } | Outcome::Duplicate { .. } => {}
            Outcome::Rejected { reason, .. } => {
                return Err(RoomError::Malformed(format!("join rejected: {reason}")));
            }
        }

        let store = self.store();
        // Current room state, and the transitive auth chain behind it.
        let meta = store
            .meta(room_id.as_str())
            .await
            .map_err(storage_err)?
            .ok_or_else(|| RoomError::UnknownRoom(room_id.to_string()))?;
        let state_map = store
            .resolve_group(room_id.as_str(), meta.current_group)
            .await
            .map_err(storage_err)?;
        let mut state = Vec::new();
        let mut auth_seed = BTreeSet::new();
        for event_id in state_map.values() {
            if let Some(obj) = self.load_raw(&store, event_id).await? {
                for auth_id in auth_event_ids(&obj) {
                    auth_seed.insert(auth_id);
                }
                state.push(obj);
            }
        }
        let auth_chain = self.collect_auth_chain(&store, auth_seed).await?;

        Ok(SendJoinResult {
            event: signed,
            state,
            auth_chain,
        })
    }

    /// Apply a remote server's signed knock event (`PUT /send_knock`).
    /// Verifies + persists it through the normal pipeline (signature, hash,
    /// auth against the room's `knock`/`knock_restricted` join rule) with
    /// `relay=true` so the outbound sender distributes the knock to the
    /// room's other servers. Returns the stripped current room state for
    /// the knocking server to show its user (spec "Knocking Rooms").
    pub async fn send_knock(&self, raw: CanonicalJsonObject) -> Result<SendKnockResult> {
        if let Some(r) = self.remote_backend() {
            return match remote::call(r, &remote::RoomIntent::SendKnock { raw }).await? {
                remote::RoomIntentOk::Knock(res) => Ok(res),
                other => Err(RoomError::Codec(format!("expected Knock, got {other:?}"))),
            };
        }
        let (version, room_id, _is_create) = self.classify(&raw).await?;
        let knocker = str_of(&raw, "state_key")?.to_owned();
        let outcome = {
            let _guard = self.lock_room(room_id.as_str()).await;
            self.process(raw, version, &room_id, false, true).await?
        };
        match &outcome {
            Outcome::Accepted { .. } | Outcome::Duplicate { .. } => {}
            Outcome::Rejected { reason, .. } => {
                return Err(RoomError::Malformed(format!("knock rejected: {reason}")));
            }
        }

        // Stripped current state (create in full per MSC4311) plus the
        // knocker's own membership event — enough to identify the room.
        let store = self.store();
        let meta = store
            .meta(room_id.as_str())
            .await
            .map_err(storage_err)?
            .ok_or_else(|| RoomError::UnknownRoom(room_id.to_string()))?;
        let state_map = store
            .resolve_group(room_id.as_str(), meta.current_group)
            .await
            .map_err(storage_err)?;
        let mut wanted: Vec<(String, String)> = KNOCK_STATE_TYPES
            .iter()
            .map(|t| ((*t).to_owned(), String::new()))
            .collect();
        wanted.push(("m.room.member".to_owned(), knocker));
        let mut knock_room_state = Vec::new();
        for key in wanted {
            if let Some(event_id) = state_map.get(&key) {
                if let Some(obj) = self.load_raw(&store, event_id).await? {
                    knock_room_state.push(stripped_state_event(&obj));
                }
            }
        }
        Ok(SendKnockResult { knock_room_state })
    }

    /// Import a room from a `send_join` response: trust the resident's
    /// state dump wholesale and initialize the room so the local joiner can
    /// sync and send. `join` is our co-signed membership event; `state` is
    /// the resolved room state; `auth_chain` backs it. Returns the join's
    /// outcome. Idempotent: a room we already host is left untouched.
    pub async fn import_room(
        &self,
        version: RoomVersion,
        join: CanonicalJsonObject,
        state: Vec<CanonicalJsonObject>,
        auth_chain: Vec<CanonicalJsonObject>,
    ) -> Result<Outcome> {
        if let Some(r) = self.remote_backend() {
            let intent = remote::RoomIntent::ImportRoom {
                version: version.as_str().to_owned(),
                event: join,
                state,
                auth_chain,
            };
            return remote::want_outcome(remote::call(r, &intent).await?);
        }
        let join_id = event::event_id(&join, version)?;
        let room_id = str_of(&join, "room_id")?.to_owned();
        let join_depth = join
            .get("depth")
            .and_then(|d| d.as_integer())
            .and_then(|i| u64::try_from(i64::from(i)).ok())
            .unwrap_or(0);

        // Build the resolved state map, then force our join into it (the
        // resident may return state from before the join was applied).
        let mut state_map: BTreeMap<(String, String), String> = BTreeMap::new();
        let mut events = Vec::new();
        let mut seen = BTreeSet::new();
        let push_event = |obj: &CanonicalJsonObject,
                          events: &mut Vec<types::ImportEvent>,
                          seen: &mut BTreeSet<String>|
         -> Result<Option<String>> {
            let id = event::event_id(obj, version)?.to_string();
            if seen.insert(id.clone()) {
                let depth = obj
                    .get("depth")
                    .and_then(|d| d.as_integer())
                    .and_then(|i| u64::try_from(i64::from(i)).ok())
                    .unwrap_or(0);
                events.push(types::ImportEvent {
                    event_id: id.clone(),
                    raw: raw_bytes(obj)?,
                    depth,
                });
            }
            Ok(Some(id))
        };

        for obj in auth_chain.iter().chain(state.iter()) {
            let id = push_event(obj, &mut events, &mut seen)?.unwrap();
            // Only state events (those with a state_key) enter the map.
            if let (Ok(ty), Some(CanonicalJsonValue::String(sk))) =
                (str_of(obj, "type"), obj.get("state_key"))
            {
                state_map.insert((ty.to_owned(), sk.clone()), id);
            }
        }
        // The join membership is always the joiner's current state.
        let sender = str_of(&join, "sender")?.to_owned();
        state_map.insert(("m.room.member".to_owned(), sender), join_id.to_string());

        // Everything before our join lives on the resident: the join's
        // unheld prev_events seed the backfill frontier.
        let history_frontier: Vec<String> = prev_event_ids(&join)
            .into_iter()
            .filter(|id| !seen.contains(id))
            .collect();

        let create_event_id = state_map
            .get(&("m.room.create".to_owned(), String::new()))
            .cloned()
            .ok_or_else(|| RoomError::Malformed("send_join state has no create event".into()))?;

        let cmd = RoomCommand::Import(Box::new(types::ImportRoom {
            room_id,
            version: version.as_str().to_owned(),
            create_event_id,
            events,
            join_event_id: join_id.to_string(),
            join_raw: raw_bytes(&join)?,
            join_depth,
            state: state_map.into_iter().collect(),
            history_frontier,
        }));

        match self.propose_cmd(&cmd).await? {
            RoomResponse::Accepted { event_id, seq } => Ok(Outcome::Accepted {
                event_id: OwnedEventId::try_from(event_id)
                    .map_err(|e| RoomError::Malformed(e.to_string()))?,
                seq,
            }),
            RoomResponse::Duplicate { event_id } => Ok(Outcome::Duplicate {
                event_id: OwnedEventId::try_from(event_id)
                    .map_err(|e| RoomError::Malformed(e.to_string()))?,
            }),
            other => Err(RoomError::Codec(format!(
                "unexpected import response: {other:?}"
            ))),
        }
    }

    /// Append backfilled PDUs (fetched from the room's resident server via
    /// `GET /backfill`) to the room's history order. Events already on the
    /// timeline or in history are skipped; the rest are stored
    /// off-timeline and indexed newest-first by `(depth, origin_server_ts,
    /// event_id)`. Trusted wholesale like [`Self::import_room`] — the
    /// resident already validated its own history (per-event signature
    /// verification is future hardening). Returns `(indexed, complete)`.
    pub async fn import_history(
        &self,
        room_id: &str,
        pdus: Vec<CanonicalJsonObject>,
    ) -> Result<(u64, bool)> {
        if let Some(r) = self.remote_backend() {
            let intent = remote::RoomIntent::ImportHistory {
                room_id: room_id.to_owned(),
                pdus,
            };
            return match remote::call(r, &intent).await? {
                remote::RoomIntentOk::History(indexed, complete) => Ok((indexed, complete)),
                other => Err(RoomError::Codec(format!("expected History, got {other:?}"))),
            };
        }
        let mut events = Vec::new();
        let mut seen = BTreeSet::new();
        let meta = self
            .store()
            .meta(room_id)
            .await
            .map_err(storage_err)?
            .ok_or_else(|| {
                RoomError::Malformed(format!("history import: unknown room {room_id}"))
            })?;
        let version = RoomVersion::parse(&meta.version)?;
        for obj in &pdus {
            // Only events of this room enter its history.
            match obj.get("room_id") {
                Some(CanonicalJsonValue::String(r)) if r != room_id => continue,
                _ => {}
            }
            let Ok(id) = event::event_id(obj, version) else {
                continue; // unhashable PDU: drop, don't fail the batch
            };
            if !seen.insert(id.to_string()) {
                continue;
            }
            let depth = obj
                .get("depth")
                .and_then(|d| d.as_integer())
                .and_then(|i| u64::try_from(i64::from(i)).ok())
                .unwrap_or(0);
            let ts = obj
                .get("origin_server_ts")
                .and_then(|d| d.as_integer())
                .and_then(|i| u64::try_from(i64::from(i)).ok())
                .unwrap_or(0);
            events.push((depth, ts, id.to_string(), raw_bytes(obj)?));
        }
        // Newest first: history indexes grow older.
        events.sort_by(|a, b| (b.0, b.1, &b.2).cmp(&(a.0, a.1, &a.2)));
        let cmd = RoomCommand::ImportHistory(Box::new(types::ImportHistory {
            room_id: room_id.to_owned(),
            events: events
                .into_iter()
                .map(|(depth, _, event_id, raw)| types::ImportEvent {
                    event_id,
                    raw,
                    depth,
                })
                .collect(),
        }));
        match self.propose_cmd(&cmd).await? {
            RoomResponse::History { indexed, complete } => Ok((indexed, complete)),
            other => Err(RoomError::Codec(format!(
                "unexpected history response: {other:?}"
            ))),
        }
    }

    /// Append a chain of events recovered past an unfillable gap: they
    /// hang off ancestors the origin refused to return, so they anchor on
    /// a state snapshot (fetched via `GET /state` at the chain's oldest
    /// event) instead of resolving through the pipeline. `chain` is
    /// oldest-first, as `/get_missing_events` returns it. Returns how many
    /// events joined the timeline.
    pub async fn import_segment(
        &self,
        room_id: &str,
        state: Vec<CanonicalJsonObject>,
        auth_chain: Vec<CanonicalJsonObject>,
        chain: Vec<CanonicalJsonObject>,
    ) -> Result<u64> {
        let meta = self
            .store()
            .meta(room_id)
            .await
            .map_err(storage_err)?
            .ok_or_else(|| {
                RoomError::Malformed(format!("segment import: unknown room {room_id}"))
            })?;
        let version = RoomVersion::parse(&meta.version)?;

        // An event may only enter the snapshot if its *transitive* auth
        // chain resolves — every reference reachable from its auth_events
        // is either in this fetch or already in our store. The origin can
        // refuse to serve an ancestor (Complement's TestCorruptedAuthChain
        // 404s one on purpose): every event whose auth chain crosses that
        // hole is unverifiable and must be dropped here, exactly as the
        // live pipeline would have rejected it, or a forged/unauthorised
        // state entry could ride the snapshot into current state.
        let store = self.store();
        let mut fetched_auth: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for obj in auth_chain.iter().chain(state.iter()).chain(chain.iter()) {
            if let Ok(id) = event::event_id(obj, version) {
                fetched_auth.insert(id.to_string(), auth_event_ids(obj));
            }
        }
        let mut verdict: BTreeMap<String, bool> = BTreeMap::new();
        // (An inner fn rather than a closure: the walk awaits store
        // reads, and async closures capturing &mut state aren't a thing.)
        async fn resolvable(
            store: &RoomStore,
            fetched_auth: &BTreeMap<String, Vec<String>>,
            verdict: &mut BTreeMap<String, bool>,
            seed: &str,
        ) -> bool {
            let mut pending = vec![seed.to_owned()];
            let mut visiting = BTreeSet::new();
            while let Some(id) = pending.pop() {
                if verdict.get(&id).copied() == Some(false) {
                    verdict.insert(seed.to_owned(), false);
                    return false;
                }
                if verdict.contains_key(&id) || !visiting.insert(id.clone()) {
                    continue;
                }
                let refs = match fetched_auth.get(&id) {
                    Some(refs) => refs.clone(),
                    // Not part of this fetch: it must already be ours
                    // (its own chain was checked when it was stored).
                    None => match store.event(&id).await {
                        Ok(Some(_)) => {
                            verdict.insert(id, true);
                            continue;
                        }
                        _ => {
                            verdict.insert(id, false);
                            verdict.insert(seed.to_owned(), false);
                            return false;
                        }
                    },
                };
                pending.extend(refs);
            }
            for id in visiting {
                verdict.insert(id, true);
            }
            true
        }

        let mut events = Vec::new();
        let mut seen = BTreeSet::new();
        let mut state_map: BTreeMap<(String, String), String> = BTreeMap::new();
        let import_event = |obj: &CanonicalJsonObject| -> Option<types::ImportEvent> {
            let id = event::event_id(obj, version).ok()?;
            let depth = obj
                .get("depth")
                .and_then(|d| d.as_integer())
                .and_then(|i| u64::try_from(i64::from(i)).ok())
                .unwrap_or(0);
            Some(types::ImportEvent {
                event_id: id.to_string(),
                raw: raw_bytes(obj).ok()?,
                depth,
            })
        };
        let mut dropped = 0usize;
        for (is_state, obj) in auth_chain
            .iter()
            .map(|o| (false, o))
            .chain(state.iter().map(|o| (true, o)))
        {
            let Some(ev) = import_event(obj) else {
                continue;
            };
            if !resolvable(&store, &fetched_auth, &mut verdict, &ev.event_id).await {
                dropped += 1;
                continue;
            }
            // Only the `state` list defines the snapshot: an auth-chain
            // event with the same (type, state_key) is a *superseded*
            // entry, and letting it stand in when the state's own entry
            // was dropped above would resurrect old state (a stale
            // membership) as current.
            if is_state {
                if let (Ok(ty), Some(CanonicalJsonValue::String(sk))) =
                    (str_of(obj, "type"), obj.get("state_key"))
                {
                    state_map.insert((ty.to_owned(), sk.clone()), ev.event_id.clone());
                }
            }
            if seen.insert(ev.event_id.clone()) {
                events.push(ev);
            }
        }
        if dropped > 0 {
            tracing::warn!(
                room_id,
                dropped,
                "segment import: dropped snapshot events with unresolvable auth chains"
            );
        }

        let mut timeline = Vec::new();
        let mut frontier_add = Vec::new();
        for (i, obj) in chain.iter().enumerate() {
            let Some(ev) = import_event(obj) else {
                continue;
            };
            if i == 0 {
                frontier_add = prev_event_ids(obj);
            }
            timeline.push(ev);
        }

        let cmd = RoomCommand::ImportSegment(Box::new(types::ImportSegment {
            room_id: room_id.to_owned(),
            events,
            state: state_map.into_iter().collect(),
            timeline,
            frontier_add,
        }));
        match self.propose_cmd(&cmd).await? {
            RoomResponse::Segment { appended } => Ok(appended),
            other => Err(RoomError::Codec(format!(
                "unexpected segment response: {other:?}"
            ))),
        }
    }

    /// The room's backward-extremity frontier: event ids known to precede
    /// our history that we do not hold (empty = history complete).
    pub async fn history_frontier(&self, room_id: &str) -> Result<Vec<String>> {
        Ok(self
            .store()
            .meta(room_id)
            .await
            .map_err(storage_err)?
            .map(|m| m.history_frontier)
            .unwrap_or_default())
    }

    async fn load_raw(
        &self,
        store: &RoomStore,
        event_id: &str,
    ) -> Result<Option<CanonicalJsonObject>> {
        let Some(stored) = store.event(event_id).await.map_err(storage_err)? else {
            return Ok(None);
        };
        Ok(Some(
            serde_json::from_slice(&stored.raw).map_err(|e| RoomError::Codec(e.to_string()))?,
        ))
    }

    /// Transitive closure of `auth_events` starting from `seed` event IDs.
    /// The auth chain of an event: the transitive closure of its
    /// `auth_events` (not the event itself), as raw objects. Serves the
    /// federation `/event_auth` endpoint. `Ok(None)` if we don't hold the
    /// event.
    pub async fn event_auth_chain(
        &self,
        event_id: &str,
    ) -> Result<Option<Vec<CanonicalJsonObject>>> {
        let store = self.store();
        let Some(event) = self.load_raw(&store, event_id).await? else {
            return Ok(None);
        };
        let seed: BTreeSet<String> = auth_event_ids(&event).into_iter().collect();
        Ok(Some(self.collect_auth_chain(&store, seed).await?))
    }

    /// The resolved room state *before* `event_id` and that state's auth
    /// chain, as `(event_id, raw)` pairs — the payload of the federation
    /// `/state` and `/state_ids` endpoints. Matches Synapse's semantics:
    /// the event's own `(type, state_key)` entry is replaced by the entry
    /// it superseded (recovered via `auth_events`, like
    /// [`Self::prev_state_content`]) or dropped if there was none.
    /// `Ok(None)` when we don't hold the event, it is rejected, or it
    /// belongs to another room.
    #[allow(clippy::type_complexity)]
    pub async fn state_before_event(
        &self,
        room_id: &str,
        event_id: &str,
    ) -> Result<
        Option<(
            Vec<(String, CanonicalJsonObject)>,
            Vec<(String, CanonicalJsonObject)>,
        )>,
    > {
        let store = self.store();
        let Some(stored) = store.event(event_id).await.map_err(storage_err)? else {
            return Ok(None);
        };
        if stored.state_group_after == 0 {
            return Ok(None); // rejected: no state known at it
        }
        let raw: serde_json::Value =
            serde_json::from_slice(&stored.raw).map_err(|e| RoomError::Codec(e.to_string()))?;
        if raw.get("room_id").and_then(|v| v.as_str()) != Some(room_id) {
            return Ok(None);
        }
        let mut state = store
            .resolve_group(room_id, stored.state_group_after)
            .await
            .map_err(storage_err)?;

        // `state_group_after` includes a state event itself — back it out.
        if let (Some(etype), Some(skey)) = (
            raw.get("type").and_then(|v| v.as_str()),
            raw.get("state_key").and_then(|v| v.as_str()),
        ) {
            let key = (etype.to_owned(), skey.to_owned());
            let mut replaced = false;
            // Materialized before the loop: an iterator of borrowing
            // closures held across an await trips rustc's higher-ranked
            // lifetime inference (rust-lang/rust#89976).
            let auth_ids: Vec<String> = raw
                .get("auth_events")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            for auth_id in &auth_ids {
                let Some(ae) = self.load_raw(&store, auth_id).await? else {
                    continue;
                };
                if ae.get("type").and_then(|v| v.as_str()) == Some(etype)
                    && ae.get("state_key").and_then(|v| v.as_str()) == Some(skey)
                {
                    state.insert(key.clone(), auth_id.clone());
                    replaced = true;
                    break;
                }
            }
            if !replaced {
                state.remove(&key);
            }
        }

        let mut pdus = Vec::new();
        let mut auth_seed = BTreeSet::new();
        for id in state.values() {
            let Some(obj) = self.load_raw(&store, id).await? else {
                continue;
            };
            auth_seed.extend(auth_event_ids(&obj));
            pdus.push((id.clone(), obj));
        }
        let mut auth_chain_pairs = Vec::new();
        for obj in self.collect_auth_chain(&store, auth_seed).await? {
            if let Some(id) = self.pdu_event_id(&obj).await {
                auth_chain_pairs.push((id.to_string(), obj));
            }
        }
        let auth_chain = auth_chain_pairs.into_iter().collect();
        Ok(Some((pdus, auth_chain)))
    }

    async fn collect_auth_chain(
        &self,
        store: &RoomStore,
        seed: BTreeSet<String>,
    ) -> Result<Vec<CanonicalJsonObject>> {
        let mut seen = BTreeSet::new();
        let mut queue: Vec<String> = seed.into_iter().collect();
        let mut chain = Vec::new();
        while let Some(id) = queue.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            if let Some(obj) = self.load_raw(store, &id).await? {
                for auth_id in auth_event_ids(&obj) {
                    if !seen.contains(&auth_id) {
                        queue.push(auth_id);
                    }
                }
                chain.push(obj);
            }
        }
        Ok(chain)
    }

    /// Record a read receipt (durable; bumps the shard seq so `/sync`
    /// windows cover it). Returns the receipt's seq — 0 if it was already
    /// recorded for the same event.
    pub async fn write_receipt(
        &self,
        room_id: &ruma::RoomId,
        user_id: &UserId,
        receipt_type: &str,
        event_id: &EventId,
        thread_id: Option<String>,
        ts: u64,
    ) -> Result<u64> {
        if let Some(r) = self.remote_backend() {
            let intent = remote::RoomIntent::WriteReceipt {
                room_id: room_id.to_string(),
                user_id: user_id.to_string(),
                receipt_type: receipt_type.to_owned(),
                event_id: event_id.to_string(),
                thread_id,
                ts,
            };
            return match remote::call(r, &intent).await? {
                remote::RoomIntentOk::Seq(seq) => Ok(seq),
                other => Err(RoomError::Codec(format!("expected Seq, got {other:?}"))),
            };
        }
        let resp = self
            .propose_cmd(&RoomCommand::Receipt(ReceiptCmd {
                room_id: room_id.to_string(),
                user_id: user_id.to_string(),
                receipt_type: receipt_type.to_owned(),
                event_id: event_id.to_string(),
                thread_id,
                ts,
            }))
            .await?;
        match resp {
            RoomResponse::Receipt { seq } => Ok(seq),
            other => Err(RoomError::Codec(format!(
                "unexpected response to receipt: {other:?}"
            ))),
        }
    }

    // -- internals --------------------------------------------------------

    async fn send_local(
        &self,
        room_id: &ruma::RoomId,
        sender: &UserId,
        event_type: &str,
        state_key: Option<&str>,
        content: serde_json::Value,
        ts_override: Option<u64>,
    ) -> Result<Outcome> {
        // The lock spans build + process: prev_events/auth_events read
        // here must still be the room's tip when the proposal lands.
        let _guard = self.lock_room(room_id.as_str()).await;
        let (raw, version) = self
            .build_local(room_id, sender, event_type, state_key, content, ts_override)
            .await?;
        // Locally authored: the sender's `is_local` check fans it out already.
        self.process(raw, version, &room_id.to_owned(), false, false)
            .await
    }

    /// Determine room version and room ID of a PDU prior to validation.
    async fn classify(
        &self,
        raw: &CanonicalJsonObject,
    ) -> Result<(RoomVersion, OwnedRoomId, bool)> {
        let event_type = str_of(raw, "type")?;
        let is_create = event_type == "m.room.create"
            && matches!(raw.get("state_key"), Some(CanonicalJsonValue::String(s)) if s.is_empty());

        if is_create {
            let content = match raw.get("content") {
                Some(CanonicalJsonValue::Object(o)) => o,
                _ => return Err(RoomError::Malformed("create event without content".into())),
            };
            let version = RoomVersion::parse(str_of(content, "room_version").map_err(|_| {
                RoomError::Malformed("create content without room_version".into())
            })?)?;
            let room_id = if version.room_id_is_create_event_id() {
                event::room_id_for_create(raw, version)?
            } else {
                room_id_of(raw)?
            };
            return Ok((version, room_id, true));
        }

        let room_id = room_id_of(raw)?;
        let meta = self
            .store()
            .meta(room_id.as_str())
            .await
            .map_err(storage_err)?
            .ok_or_else(|| RoomError::UnknownRoom(room_id.to_string()))?;
        Ok((RoomVersion::parse(&meta.version)?, room_id, false))
    }

    /// Build and sign a local event on the room's current tip.
    /// `ts_override` replaces the `origin_server_ts` stamp (appservice
    /// timestamp massaging).
    async fn build_local(
        &self,
        room_id: &ruma::RoomId,
        sender: &UserId,
        event_type: &str,
        state_key: Option<&str>,
        content: serde_json::Value,
        ts_override: Option<u64>,
    ) -> Result<(CanonicalJsonObject, RoomVersion)> {
        let store = self.store();
        let meta = store
            .meta(room_id.as_str())
            .await
            .map_err(storage_err)?
            .ok_or_else(|| RoomError::UnknownRoom(room_id.to_string()))?;
        let version = RoomVersion::parse(&meta.version)?;
        let current = store
            .resolve_group(room_id.as_str(), meta.current_group)
            .await
            .map_err(storage_err)?;

        // prev_events = the forward extremities; depth = max(prev) + 1.
        let mut depth: u64 = 0;
        for id in &meta.extremities {
            let prev = store
                .event(id)
                .await
                .map_err(storage_err)?
                .ok_or_else(|| RoomError::MissingEvents(vec![id.clone()]))?;
            depth = depth.max(prev.depth);
        }

        let content_obj = match CanonicalJsonValue::try_from(content)
            .map_err(|e| RoomError::Malformed(format!("content not canonical JSON: {e}")))?
        {
            CanonicalJsonValue::Object(o) => o,
            _ => return Err(RoomError::Malformed("content must be an object".into())),
        };

        // auth_events via the selection algorithm over current state.
        let auth_types =
            auth::auth_types_for_event(version, event_type, sender, state_key, &content_obj);
        let auth_events: Vec<&String> = auth_types.iter().filter_map(|k| current.get(k)).collect();

        let mut obj = serde_json::json!({
            "room_id": room_id.as_str(),
            "sender": sender.as_str(),
            "origin_server_ts": ts_override.unwrap_or_else(now_ms),
            "type": event_type,
            "content": CanonicalJsonValue::Object(content_obj),
            "auth_events": auth_events,
            "prev_events": meta.extremities,
            "depth": depth + 1,
        });
        if let Some(sk) = state_key {
            obj["state_key"] = sk.into();
        }
        let mut raw = canonicalize(obj)?;
        // Size-check before signing: hashes/signatures only grow the event,
        // and ruma's signer reports overflow as an opaque signing error.
        let canonical_len = serde_json::to_string(&raw)
            .map_err(|e| RoomError::Malformed(format!("unserializable: {e}")))?
            .len();
        if canonical_len > saltator_core::validation::MAX_PDU_BYTES {
            return Err(RoomError::Validation(
                saltator_core::validation::ValidationError::TooLarge(canonical_len),
            ));
        }
        self.signer.hash_and_sign_event(&mut raw, version)?;
        Ok((raw, version))
    }

    /// The nearest ancestor state groups behind a rejected event: walk its
    /// `prev_events` (transitively through further rejected events, bounded)
    /// collecting the first state group on each branch. Empty when nothing
    /// in reach carries state.
    async fn groups_behind_rejected(&self, store: &RoomStore, id: &str) -> BTreeSet<u64> {
        let mut groups = BTreeSet::new();
        let mut queue = vec![(id.to_owned(), 0usize)];
        let mut seen = BTreeSet::new();
        while let Some((id, depth)) = queue.pop() {
            if depth > 8 || !seen.insert(id.clone()) {
                continue;
            }
            let Ok(Some(obj)) = self.load_raw(store, &id).await else {
                continue;
            };
            for prev in prev_event_ids(&obj) {
                match store.event(&prev).await {
                    Ok(Some(se)) if se.state_group_after != 0 => {
                        groups.insert(se.state_group_after);
                    }
                    Ok(Some(_)) => queue.push((prev, depth + 1)),
                    _ => {}
                }
            }
        }
        groups
    }

    /// Pipeline steps 1–5 for one event. Caller holds the room lock.
    async fn process(
        &self,
        raw: CanonicalJsonObject,
        version: RoomVersion,
        room_id: &OwnedRoomId,
        is_create: bool,
        relay: bool,
    ) -> Result<Outcome> {
        self.process_inner(raw, version, room_id, is_create, relay, false)
            .await
    }

    /// Pipeline steps 1–5 for one event. Caller holds the room lock.
    async fn process_inner(
        &self,
        raw: CanonicalJsonObject,
        version: RoomVersion,
        room_id: &OwnedRoomId,
        is_create: bool,
        // True only for the resident-side `send_join`/`send_leave` handshake:
        // the accepted membership is flagged so the outbound sender fans it
        // out to the room's other servers (spec "Joining/Leaving Rooms").
        relay: bool,
        // Store the event rejected when auth_events cite locally-absent
        // events, instead of erroring MissingAuthEvents — see
        // [`Self::ingest_pdu_rejecting_missing_auth`].
        reject_missing_auth: bool,
    ) -> Result<Outcome> {
        // -- 1. validate: format, then signatures/hash.
        let mut raw = raw;
        let mut pdu = validation::validate_pdu(&raw, version)?;
        let keys = self
            .verify_keys
            .read()
            .expect("verify_keys lock poisoned")
            .clone();
        match validation::verify_event(&raw, version, &keys)? {
            VerifyOutcome::Verified => {}
            VerifyOutcome::SignedButHashMismatch => {
                // Per spec: process the redacted form instead of rejecting.
                raw = validation::redact(&raw, version)?;
                pdu = validation::validate_pdu(&raw, version)?;
            }
        }
        let event_id = event::event_id(&raw, version)?;
        let event = IdentifiedPdu {
            event_id: event_id.clone(),
            pdu,
        };

        let store = self.store();
        if store
            .event(event_id.as_str())
            .await
            .map_err(storage_err)?
            .is_some()
        {
            return Ok(Outcome::Duplicate { event_id });
        }
        let meta = store.meta(room_id.as_str()).await.map_err(storage_err)?;
        if !is_create && meta.is_none() {
            return Err(RoomError::UnknownRoom(room_id.to_string()));
        }

        // -- 2. fetch auth_events and prev_events.
        let mut missing: Vec<String> = Vec::new();
        let mut missing_auth: Vec<String> = Vec::new();
        let mut auth_events: Vec<(IdentifiedPdu, bool)> = Vec::new();
        for id in event.auth_events() {
            match store.event(id.as_str()).await.map_err(storage_err)? {
                Some(se) => {
                    let rejected = se.rejected.is_some();
                    auth_events.push((parse_stored(id.clone(), &se)?, rejected));
                }
                None => missing_auth.push(id.to_string()),
            }
        }
        let mut prev_groups: BTreeSet<u64> = BTreeSet::new();
        for id in event.prev_events() {
            match store.event(id.as_str()).await.map_err(storage_err)? {
                // An auth-chain-rejected prev (no state group of its own)
                // is still a legitimate prev — rejected events stay in the
                // DAG, and refusing them here would sink every later event
                // (Complement's RejectsEventsWithRejectedAuthEvents sends a
                // clean sentinel behind two rejected messages). Its
                // rejection left the room state unchanged, so its own
                // prevs' state stands in; only a chain with no resolvable
                // ancestor is genuinely missing.
                Some(se) if se.state_group_after == 0 => {
                    let groups = self.groups_behind_rejected(&store, id.as_str()).await;
                    if groups.is_empty() {
                        missing.push(id.to_string());
                    } else {
                        prev_groups.extend(groups);
                    }
                }
                Some(se) => {
                    prev_groups.insert(se.state_group_after);
                }
                None => missing.push(id.to_string()),
            }
        }
        // Prev gaps dominate: they need the timeline walk
        // (`/get_missing_events`), and once filled the retry surfaces any
        // remaining auth misses.
        if !missing.is_empty() {
            return Err(RoomError::MissingEvents(missing));
        }
        if !missing_auth.is_empty() {
            if reject_missing_auth {
                return self
                    .propose_rejected(
                        room_id,
                        &event,
                        &raw,
                        Rejected::AuthChain(format!("auth events unfetchable: {missing_auth:?}")),
                        &meta,
                    )
                    .await;
            }
            return Err(RoomError::MissingAuthEvents(missing_auth));
        }

        // Events rejected against their own auth chain never participate
        // in state resolution (state-rejected ones do).
        let fetch = |id: &EventId| -> Option<IdentifiedPdu> {
            if id == event.event_id {
                return Some(event.clone());
            }
            let se = store.event_sync(id.as_str()).ok().flatten()?;
            if matches!(se.rejected, Some(Rejected::AuthChain(_))) {
                return None;
            }
            parse_stored(id.to_owned(), &se).ok()
        };

        // -- 3a. structural auth-events checks + rules over the
        //        auth-event state. Failure → rejected against the event's
        //        own auth chain.
        let entries: Vec<AuthEntry<'_, IdentifiedPdu>> = auth_events
            .iter()
            .map(|(e, rejected)| AuthEntry {
                event: e,
                rejected: *rejected,
            })
            .collect();
        if let Err(rej) = auth::check_auth_events(version, &event, &entries) {
            return self
                .propose_rejected(
                    room_id,
                    &event,
                    &raw,
                    Rejected::AuthChain(rej.to_string()),
                    &meta,
                )
                .await;
        }
        let mut auth_state: StateMap<IdentifiedPdu> = auth_events
            .into_iter()
            .map(|(e, _)| {
                (
                    (
                        e.event_type().to_owned(),
                        e.state_key().unwrap_or_default().to_owned(),
                    ),
                    e,
                )
            })
            .collect();
        // v12: the create event is deliberately absent from auth_events
        // (its ID is the room ID) — it participates in the auth-event
        // state implicitly.
        if !is_create && !version.create_event_in_auth_events() {
            let create_id = meta
                .as_ref()
                .map(|m| m.create_event_id.clone())
                .expect("meta checked above for non-create events");
            let se = store
                .event(&create_id)
                .await
                .map_err(storage_err)?
                .ok_or_else(|| RoomError::MissingEvents(vec![create_id.clone()]))?;
            let create_id = OwnedEventId::try_from(create_id)
                .map_err(|e| RoomError::Codec(format!("event id: {e}")))?;
            auth_state.insert(
                ("m.room.create".to_owned(), String::new()),
                parse_stored(create_id, &se)?,
            );
        }
        if let Err(rej) = auth::check_state_dependent(version, &event, &auth_state) {
            return self
                .propose_rejected(
                    room_id,
                    &event,
                    &raw,
                    Rejected::AuthChain(rej.to_string()),
                    &meta,
                )
                .await;
        }

        // -- 3b/4. state before the event (resolving prev forks), then the
        //          state-dependent rules against it.
        let mut next_group = meta.as_ref().map(|m| m.next_group).unwrap_or(1);
        let mut new_groups: Vec<(u64, StateGroup)> = Vec::new();

        let (state_before, before_group): (StateIds, u64) = if is_create {
            (StateIds::new(), 0)
        } else if prev_groups.len() == 1 {
            let g = *prev_groups.iter().next().expect("len checked");
            (materialize(&store, room_id.as_str(), g).await?, g)
        } else {
            let mut sets = Vec::with_capacity(prev_groups.len());
            for g in &prev_groups {
                sets.push(materialize(&store, room_id.as_str(), *g).await?);
            }
            let resolved = state_res::resolve(version, &sets, &fetch)?;
            let g = alloc_full(&mut next_group, &mut new_groups, &resolved);
            (resolved, g)
        };

        let before_view = state_view(&event, version, &state_before, &fetch)?;
        if let Err(rej) = auth::check_state_dependent(version, &event, &before_view) {
            // State-rejected events keep a state group (state after =
            // state before): state resolution may still walk through them.
            return self
                .propose_rejected_with_state(
                    room_id,
                    &event,
                    &raw,
                    Rejected::State(rej.to_string()),
                    new_groups,
                    before_group,
                    next_group,
                )
                .await;
        }

        // -- 5a. state after the event.
        let state_key_pair = event
            .state_key()
            .map(|sk| (event.event_type().to_owned(), sk.to_owned()));
        let (after_group, state_after): (u64, StateIds) = match &state_key_pair {
            None => (before_group, state_before.clone()),
            Some(key) => {
                let mut sa = state_before.clone();
                sa.insert(key.clone(), event_id.clone());
                let parent = if is_create {
                    None
                } else {
                    Some(
                        store
                            .group(room_id.as_str(), before_group)
                            .await
                            .map_err(storage_err)?
                            .ok_or_else(|| {
                                RoomError::Storage(format!("state group {before_group} missing"))
                            })?,
                    )
                };
                match parent {
                    // Delta over the previous state, unless the chain is
                    // at its cap — then a full snapshot (spec.md §5.2).
                    Some(p) if p.chain_len + 1 < MAX_GROUP_CHAIN => {
                        let id = next_group;
                        next_group += 1;
                        new_groups.push((
                            id,
                            StateGroup {
                                parent: Some(before_group),
                                chain_len: p.chain_len + 1,
                                entries: vec![(key.clone(), event_id.to_string())],
                            },
                        ));
                        (id, sa)
                    }
                    _ => {
                        let id = alloc_full(&mut next_group, &mut new_groups, &sa);
                        (id, sa)
                    }
                }
            }
        };

        // -- 5b. new forward extremities and the room's current state.
        let mut extremities: BTreeSet<String> = meta
            .as_ref()
            .map(|m| m.extremities.iter().cloned().collect())
            .unwrap_or_default();
        for id in event.prev_events() {
            extremities.remove(id.as_str());
        }
        extremities.insert(event_id.to_string());

        let current_group = if extremities.len() == 1 {
            after_group
        } else {
            // The room still has a dangling fork: the current state is the
            // resolution across all extremities' after-states.
            let mut sets = Vec::with_capacity(extremities.len());
            for id in &extremities {
                if id == event_id.as_str() {
                    sets.push(state_after.clone());
                } else {
                    let se = store
                        .event(id)
                        .await
                        .map_err(storage_err)?
                        .ok_or_else(|| RoomError::MissingEvents(vec![id.clone()]))?;
                    sets.push(materialize(&store, room_id.as_str(), se.state_group_after).await?);
                }
            }
            let resolved = state_res::resolve(version, &sets, &fetch)?;
            if resolved == state_after {
                after_group
            } else {
                alloc_full(&mut next_group, &mut new_groups, &resolved)
            }
        };

        // Accepted m.room.redaction: decide whether it *applies* to its
        // target (spec "Redactions": same sender, or redact power level).
        let redacts = if event.event_type() == "m.room.redaction" {
            self.redaction_target(&store, room_id, &event, version, &state_before, &fetch)
                .await?
        } else {
            None
        };

        // -- 5c. persist: one Raft proposal, one deterministic KV batch.
        let cmd = AppendEvent {
            room_id: room_id.to_string(),
            event_id: event_id.to_string(),
            raw: raw_bytes(&raw)?,
            depth: u64::from(event.pdu.depth),
            rejected: None,
            new_groups,
            state_group_after: after_group,
            new_current_group: current_group,
            new_extremities: extremities.into_iter().collect(),
            next_group,
            create_version: is_create.then(|| version.as_str().to_owned()),
            redacts,
            relay,
        };
        self.propose(cmd).await
    }

    /// For an accepted `m.room.redaction`, the target event it may be
    /// applied to: locally known, same room, and either sent by the
    /// redaction's sender or redactable at the sender's power level
    /// (evaluated against the state before the redaction).
    ///
    /// A redaction naming a target this server does not hold is dropped:
    /// it is accepted as an event but applies to nothing. A federated
    /// redaction that arrives before its target therefore never takes
    /// effect, which is a known gap rather than a decision.
    async fn redaction_target(
        &self,
        store: &RoomStore,
        room_id: &ruma::RoomId,
        event: &IdentifiedPdu,
        version: RoomVersion,
        state_before: &StateIds,
        fetch: &impl Fn(&EventId) -> Option<IdentifiedPdu>,
    ) -> Result<Option<String>> {
        let Some(CanonicalJsonValue::String(target_id)) = event.content().get("redacts") else {
            return Ok(None);
        };
        let Ok(target_id) = OwnedEventId::try_from(target_id.as_str()) else {
            return Ok(None);
        };
        let Some(stored) = store.event(target_id.as_str()).await.map_err(storage_err)? else {
            return Ok(None);
        };
        if stored.rejected.is_some() {
            return Ok(None);
        }
        let target = parse_stored(target_id.clone(), &stored)?;
        // v12 create events carry no room_id and are never redactable
        // through this path.
        if target.room_id() != Some(room_id) {
            return Ok(None);
        }
        if target.sender() == event.sender() {
            return Ok(Some(target_id.to_string()));
        }
        let create_key = ("m.room.create".to_owned(), String::new());
        let Some(create) = state_before.get(&create_key).and_then(|id| fetch(id)) else {
            return Ok(None);
        };
        let pl_key = ("m.room.power_levels".to_owned(), String::new());
        let pl_event = state_before.get(&pl_key).and_then(|id| fetch(id));
        let pls = RoomPowerLevels::resolve(version, &create, pl_event.as_ref())
            .map_err(|e| RoomError::Malformed(e.to_string()))?;
        Ok(pls
            .user(event.sender())
            .satisfies(pls.redact)
            .then(|| target_id.to_string()))
    }

    async fn propose_rejected(
        &self,
        room_id: &OwnedRoomId,
        event: &IdentifiedPdu,
        raw: &CanonicalJsonObject,
        rejected: Rejected,
        meta: &Option<RoomMeta>,
    ) -> Result<Outcome> {
        let next_group = meta.as_ref().map(|m| m.next_group).unwrap_or(1);
        self.propose_rejected_with_state(room_id, event, raw, rejected, Vec::new(), 0, next_group)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn propose_rejected_with_state(
        &self,
        room_id: &OwnedRoomId,
        event: &IdentifiedPdu,
        raw: &CanonicalJsonObject,
        rejected: Rejected,
        new_groups: Vec<(u64, StateGroup)>,
        state_group_after: u64,
        next_group: u64,
    ) -> Result<Outcome> {
        let cmd = AppendEvent {
            room_id: room_id.to_string(),
            event_id: event.event_id.to_string(),
            raw: raw_bytes(raw)?,
            depth: u64::from(event.pdu.depth),
            rejected: Some(rejected),
            new_groups,
            state_group_after,
            new_current_group: 0,
            new_extremities: Vec::new(),
            next_group,
            create_version: None,
            redacts: None,
            relay: false,
        };
        self.propose(cmd).await
    }

    async fn propose_cmd(&self, cmd: &RoomCommand) -> Result<RoomResponse> {
        let bytes = postcard::to_stdvec(cmd).map_err(|e| RoomError::Codec(e.to_string()))?;
        let resp = self.shard_handle().propose(bytes).await?;
        postcard::from_bytes(&resp).map_err(|e| RoomError::Codec(e.to_string()))
    }

    async fn propose(&self, cmd: AppendEvent) -> Result<Outcome> {
        let resp = self
            .propose_cmd(&RoomCommand::Append(Box::new(cmd)))
            .await?;
        let parse_id = |s: String| {
            OwnedEventId::try_from(s).map_err(|e| RoomError::Codec(format!("event id: {e}")))
        };
        Ok(match resp {
            RoomResponse::Accepted { event_id, seq } => Outcome::Accepted {
                event_id: parse_id(event_id)?,
                seq,
            },
            RoomResponse::Rejected { event_id, reason } => Outcome::Rejected {
                event_id: parse_id(event_id)?,
                reason,
            },
            RoomResponse::Duplicate { event_id } => Outcome::Duplicate {
                event_id: parse_id(event_id)?,
            },
            RoomResponse::Receipt { .. }
            | RoomResponse::History { .. }
            | RoomResponse::Segment { .. } => {
                return Err(RoomError::Codec(
                    "unexpected non-event response to append".into(),
                ))
            }
        })
    }

    async fn lock_room(&self, room_id: &str) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.room_locks.lock().await;
            locks.entry(room_id.to_owned()).or_default().clone()
        };
        lock.lock_owned().await
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Allocate a full-snapshot state group.
fn alloc_full(
    next_group: &mut u64,
    new_groups: &mut Vec<(u64, StateGroup)>,
    state: &StateIds,
) -> u64 {
    let id = *next_group;
    *next_group += 1;
    new_groups.push((
        id,
        StateGroup {
            parent: None,
            chain_len: 0,
            entries: state
                .iter()
                .map(|(k, v)| (k.clone(), v.to_string()))
                .collect(),
        },
    ));
    id
}

/// Materialize the sub-view of `state` the auth rules can touch for this
/// event.
fn state_view(
    event: &IdentifiedPdu,
    version: RoomVersion,
    state: &StateIds,
    fetch: &impl Fn(&EventId) -> Option<IdentifiedPdu>,
) -> Result<StateMap<IdentifiedPdu>> {
    let mut needed = auth::auth_types_for_event(
        version,
        event.event_type(),
        event.sender(),
        event.state_key(),
        event.content(),
    );
    needed.insert(("m.room.create".to_owned(), String::new()));

    let mut view = StateMap::new();
    for key in needed {
        if let Some(id) = state.get(&key) {
            let e = fetch(id).ok_or_else(|| RoomError::MissingEvents(vec![id.to_string()]))?;
            view.insert(key, e);
        }
    }
    Ok(view)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_millis() as u64
}

fn canonicalize(value: serde_json::Value) -> Result<CanonicalJsonObject> {
    match CanonicalJsonValue::try_from(value) {
        Ok(CanonicalJsonValue::Object(o)) => Ok(o),
        Ok(_) => Err(RoomError::Malformed("event must be an object".into())),
        Err(e) => Err(RoomError::Malformed(e.to_string())),
    }
}

fn raw_bytes(raw: &CanonicalJsonObject) -> Result<Vec<u8>> {
    serde_json::to_vec(raw).map_err(|e| RoomError::Codec(e.to_string()))
}

/// Stripped-state form of an event (`content`/`sender`/`state_key`/`type`),
/// used for `knock_room_state`. The `m.room.create` event is served in full
/// (MSC4311): the knocking server needs its `origin_server_ts` and, in v12,
/// full content to verify the room.
fn stripped_state_event(raw: &CanonicalJsonObject) -> serde_json::Value {
    let is_create = matches!(
        raw.get("type"),
        Some(CanonicalJsonValue::String(t)) if t == "m.room.create"
    );
    let keys: &[&str] = if is_create {
        &[
            "content",
            "sender",
            "state_key",
            "type",
            "origin_server_ts",
            "auth_events",
            "depth",
            "hashes",
            "prev_events",
            "signatures",
        ]
    } else {
        &["content", "sender", "state_key", "type"]
    };
    let mut out = serde_json::Map::new();
    for key in keys {
        if let Some(v) = raw.get(*key) {
            out.insert((*key).to_owned(), serde_json::Value::from(v.clone()));
        }
    }
    serde_json::Value::Object(out)
}

fn str_of<'a>(obj: &'a CanonicalJsonObject, key: &str) -> Result<&'a str> {
    match obj.get(key) {
        Some(CanonicalJsonValue::String(s)) => Ok(s),
        _ => Err(RoomError::Malformed(format!("missing string `{key}`"))),
    }
}

fn room_id_of(raw: &CanonicalJsonObject) -> Result<OwnedRoomId> {
    OwnedRoomId::try_from(str_of(raw, "room_id")?.to_owned())
        .map_err(|e| RoomError::Malformed(format!("room_id: {e}")))
}

/// Parse a stored event back into its typed view.
fn parse_stored(event_id: OwnedEventId, stored: &StoredEvent) -> Result<IdentifiedPdu> {
    let value: serde_json::Value =
        serde_json::from_slice(&stored.raw).map_err(|e| RoomError::Codec(e.to_string()))?;
    let raw = canonicalize(value)?;
    Ok(IdentifiedPdu {
        event_id,
        pdu: Pdu::from_canonical(&raw)?,
    })
}

async fn materialize(store: &RoomStore, room_id: &str, group: u64) -> Result<StateIds> {
    let map = store
        .resolve_group(room_id, group)
        .await
        .map_err(storage_err)?;
    let mut out = StateIds::new();
    for (k, v) in map {
        out.insert(
            k,
            OwnedEventId::try_from(v).map_err(|e| RoomError::Codec(format!("event id: {e}")))?,
        );
    }
    Ok(out)
}
