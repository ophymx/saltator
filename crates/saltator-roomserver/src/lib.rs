//! The room server: the event pipeline and the room keyspace state
//! machine (spec.md §5.2), running on the generic shard runtime.
//!
//! Every event — local send or federated PDU — passes through one
//! pipeline at the room-shard leader:
//!
//! 1. **Validate** — schema/size checks, signature + content-hash
//!    verification (hash mismatch → redact, not reject).
//! 2. **Fetch** — resolve `auth_events`/`prev_events` from the shard;
//!    events not present locally surface as [`RoomError::MissingEvents`]
//!    (M3 turns this into federated missing-event/state fetch).
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

pub mod hierarchy;
mod machine;
mod signer;
mod types;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use openraft::network::RaftNetworkFactory;
use ruma::signatures::PublicKeyMap;
use ruma::{CanonicalJsonObject, CanonicalJsonValue, EventId, OwnedEventId, OwnedRoomId, UserId};
use tokio::sync::{broadcast, Mutex, OwnedMutexGuard};

use saltator_core::auth::{self, AuthEntry, StateMap};
use saltator_core::event::{self, EventFormatError, IdentifiedPdu, Pdu};
use saltator_core::power_levels::RoomPowerLevels;
use saltator_core::room_version::UnsupportedRoomVersion;
use saltator_core::state_res::{self, StateIds, StateResError};
use saltator_core::validation::{self, ValidationError, VerificationError, VerifyOutcome};
use saltator_core::{Event, RoomVersion};
use saltator_shard::{ChangeRecord, NodeId, ShardHandle, ShardId, ShardRegistry, TypeConfig};
use saltator_store::{Keyspace, KvEngine};

pub use machine::{RoomApp, RoomStore};
pub use signer::{ServerSigner, SignError};
pub use types::{
    AppendEvent, ChangePayload, ReceiptCmd, ReceiptRecord, Rejected, RoomCommand, RoomMeta,
    RoomResponse, SeqEntry, StateGroup, StoredEvent, MAX_GROUP_CHAIN,
};

/// M1 runs a single room shard; the fixed shard count and placement land
/// with clustering (M4).
pub const ROOM_SHARD: ShardId = ShardId::new(Keyspace::Room, 0);

#[derive(Debug, thiserror::Error)]
pub enum RoomError {
    #[error("unknown room {0}")]
    UnknownRoom(String),
    /// Referenced events are not present locally. M3 turns this into the
    /// federated missing-event / state fetch of pipeline step 2.
    #[error("events required but not present locally: {0:?}")]
    MissingEvents(Vec<String>),
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
    #[error("shard: {0}")]
    Shard(#[from] saltator_shard::ShardError),
    #[error("storage: {0}")]
    Storage(String),
    #[error("codec: {0}")]
    Codec(String),
}

type Result<T> = std::result::Result<T, RoomError>;

fn storage_err(e: impl std::fmt::Display) -> RoomError {
    RoomError::Storage(e.to_string())
}

/// Pipeline outcome for one event.
#[derive(Debug, Clone, PartialEq, Eq)]
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
pub struct SendJoinResult {
    pub event: CanonicalJsonObject,
    pub state: Vec<CanonicalJsonObject>,
    pub auth_chain: Vec<CanonicalJsonObject>,
}

/// The `PUT /send_knock` response payload: the stripped current room state
/// (`knock_room_state`) that lets the knocking server show the room to its
/// user while the knock is pending.
pub struct SendKnockResult {
    pub knock_room_state: Vec<serde_json::Value>,
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

pub struct RoomServer {
    handle: ShardHandle,
    signer: Arc<ServerSigner>,
    /// Verification keys by entity. Seeded with our own keys; remote
    /// server keys are added explicitly until M3 brings key fetching.
    verify_keys: std::sync::RwLock<PublicKeyMap>,
    room_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl RoomServer {
    /// Start the room shard on this node and return the server handle.
    pub async fn start(
        node_id: NodeId,
        engine: Arc<dyn KvEngine>,
        signer: Arc<ServerSigner>,
        network: impl RaftNetworkFactory<TypeConfig>,
        bootstrap_addr: Option<String>,
        registry: Option<&ShardRegistry>,
    ) -> Result<Arc<Self>> {
        let handle = ShardHandle::start(
            ROOM_SHARD,
            node_id,
            engine,
            Arc::new(RoomApp),
            network,
            bootstrap_addr,
            registry,
        )
        .await?;
        let verify_keys = std::sync::RwLock::new(signer.public_key_map());
        Ok(Arc::new(Self {
            handle,
            signer,
            verify_keys,
            room_locks: Mutex::new(HashMap::new()),
        }))
    }

    pub fn shard_handle(&self) -> &ShardHandle {
        &self.handle
    }

    /// Typed read access to the shard's applied state.
    pub fn store(&self) -> RoomStore {
        RoomStore::new(self.handle.read_ctx())
    }

    /// Subscribe to the room shard's change stream.
    pub fn subscribe(&self) -> broadcast::Receiver<ChangeRecord> {
        self.handle.subscribe()
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
    pub fn prev_state_content(
        &self,
        event_id: &str,
    ) -> Result<Option<(serde_json::Value, String)>> {
        let store = self.store();
        let Some(stored) = store.event(event_id).map_err(storage_err)? else {
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
            let Some(ae) = store.event(auth_id).map_err(storage_err)? else {
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

    pub fn remote_servers_in_room(&self, room_id: &str, exclude: &str) -> Result<Vec<String>> {
        let store = self.store();
        let Some(meta) = store
            .meta(room_id)
            .map_err(|e| RoomError::Storage(e.to_string()))?
        else {
            return Ok(Vec::new());
        };
        let state = store
            .resolve_group(room_id, meta.current_group)
            .map_err(|e| RoomError::Storage(e.to_string()))?;
        let mut servers = BTreeSet::new();
        for ((event_type, state_key), event_id) in &state {
            if event_type != "m.room.member" {
                continue;
            }
            let Some(stored) = store
                .event(event_id)
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

    /// Trust verification keys for a remote entity (tests / static
    /// configuration; M3 replaces this with spec key fetching).
    pub fn trust_keys(&self, entity: &str, keys: BTreeMap<String, ruma::serde::Base64>) {
        self.verify_keys
            .write()
            .expect("verify_keys lock poisoned")
            .insert(entity.to_owned(), keys);
    }

    pub async fn shutdown(&self) -> Result<()> {
        Ok(self.handle.shutdown().await?)
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

        let _guard = self.lock_room(room_id.as_str()).await;
        let outcome = self.process(raw, version, &room_id, true, false).await?;
        Ok((room_id, outcome))
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
        self.send_local(room_id, sender, event_type, Some(state_key), content)
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
        self.send_local(room_id, sender, event_type, None, content)
            .await
    }

    /// Ingest a complete PDU (the federation-shaped entry point): raw
    /// canonical JSON, signatures and hashes included.
    pub async fn ingest_pdu(&self, raw: CanonicalJsonObject) -> Result<Outcome> {
        let (version, room_id, is_create) = self.classify(&raw)?;
        let _guard = self.lock_room(room_id.as_str()).await;
        // Ordinary inbound PDU: its origin is responsible for distributing it,
        // so we do not relay it onward.
        self.process(raw, version, &room_id, is_create, false).await
    }

    /// Verify a single PDU's structure, signature, and content hash against
    /// the currently trusted keys, WITHOUT ingesting it. Returns `true`
    /// only when fully verified. Used to vet off-timeline state snapshots
    /// (gap-fill `/state`) before trusting them — the caller must first
    /// trust the keys of every server that authored one of the events.
    /// Looks the room version up from stored meta; use
    /// [`Self::verify_pdu_at`] when the room does not exist locally yet
    /// (a fresh send_join).
    pub fn verify_pdu(&self, room_id: &str, raw: &CanonicalJsonObject) -> bool {
        let Ok(Some(meta)) = self.store().meta(room_id) else {
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
    pub fn pdu_event_id(&self, raw: &CanonicalJsonObject) -> Option<OwnedEventId> {
        let (version, _room_id, _is_create) = self.classify(raw).ok()?;
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
        let _guard = self.lock_room(room_id.as_str()).await;
        // `membership: invite` is authoritative; extra content (e.g. the
        // `is_direct` flag) rides along on the invite member event.
        content.insert("membership".to_owned(), "invite".into());
        let (raw, version) = self.build_local(
            room_id,
            sender,
            "m.room.member",
            Some(target.as_str()),
            serde_json::Value::Object(content),
        )?;
        Ok((version, raw))
    }

    /// Build an unsigned `m.room.member` join template for `user_id` (a
    /// user on another server) — the `GET /make_join` response. prev/auth
    /// events and depth are computed from current room state; the joining
    /// server fills in `origin`/`origin_server_ts`/`event_id` and signs.
    pub fn make_join_template(
        &self,
        room_id: &ruma::RoomId,
        user_id: &UserId,
    ) -> Result<(RoomVersion, CanonicalJsonObject)> {
        self.make_membership_template(room_id, user_id, "join")
    }

    /// Build an unsigned `m.room.member` leave template — the `GET
    /// /make_leave` response (used to reject a remote invite or leave a
    /// remote room).
    pub fn make_leave_template(
        &self,
        room_id: &ruma::RoomId,
        user_id: &UserId,
    ) -> Result<(RoomVersion, CanonicalJsonObject)> {
        self.make_membership_template(room_id, user_id, "leave")
    }

    /// Build an unsigned `m.room.member` knock template — the `GET
    /// /make_knock` response. The knocking server fills in
    /// `origin`/`origin_server_ts`/`reason`/`event_id` and signs.
    pub fn make_knock_template(
        &self,
        room_id: &ruma::RoomId,
        user_id: &UserId,
    ) -> Result<(RoomVersion, CanonicalJsonObject)> {
        self.make_membership_template(room_id, user_id, "knock")
    }

    fn make_membership_template(
        &self,
        room_id: &ruma::RoomId,
        user_id: &UserId,
        membership: &str,
    ) -> Result<(RoomVersion, CanonicalJsonObject)> {
        let store = self.store();
        let meta = store
            .meta(room_id.as_str())
            .map_err(storage_err)?
            .ok_or_else(|| RoomError::UnknownRoom(room_id.to_string()))?;
        let version = RoomVersion::parse(&meta.version)?;
        let current = store
            .resolve_group(room_id.as_str(), meta.current_group)
            .map_err(storage_err)?;

        let mut depth: u64 = 0;
        for id in &meta.extremities {
            let prev = store
                .event(id)
                .map_err(storage_err)?
                .ok_or_else(|| RoomError::MissingEvents(vec![id.clone()]))?;
            depth = depth.max(prev.depth);
        }

        let content = serde_json::json!({ "membership": membership });
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
        let (version, room_id, _is_create) = self.classify(&raw)?;
        let _guard = self.lock_room(room_id.as_str()).await;
        // We are the resident servicing this leave/reject handshake: flag the
        // membership so the outbound sender relays it to the room's other
        // servers (spec "Leaving Rooms").
        self.process(raw, version, &room_id, false, true).await
    }

    /// The room's current forward extremities (the DAG leaves). Empty if
    /// the room is unknown. Used as `earliest_events` when requesting a
    /// gap fill, so the peer walks back only to what we already have.
    pub fn room_extremities(&self, room_id: &str) -> Result<Vec<String>> {
        Ok(self
            .store()
            .meta(room_id)
            .map_err(storage_err)?
            .map(|m| m.extremities)
            .unwrap_or_default())
    }

    /// The room's current `m.room.server_acl`, if any is set.
    pub fn server_acl(&self, room_id: &str) -> Result<Option<saltator_core::acl::ServerAcl>> {
        let store = self.store();
        let Some(meta) = store.meta(room_id).map_err(storage_err)? else {
            return Ok(None);
        };
        let current = store
            .resolve_group(room_id, meta.current_group)
            .map_err(storage_err)?;
        let Some(event_id) = current.get(&("m.room.server_acl".to_owned(), String::new())) else {
            return Ok(None);
        };
        let Some(stored) = store.event(event_id).map_err(storage_err)? else {
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
    pub fn server_acl_denies(&self, room_id: &str, server: &str) -> bool {
        matches!(self.server_acl(room_id), Ok(Some(acl)) if !acl.is_allowed(server))
    }

    /// Walk the room DAG backward from `start` event IDs along
    /// `prev_events`, returning up to `limit` events (the `/backfill`
    /// response). The `start` events are included; highest-depth (most
    /// recent) first. Unknown start IDs are skipped; rejected events are
    /// not returned.
    pub fn backfill(&self, start: &[String], limit: usize) -> Result<Vec<CanonicalJsonObject>> {
        self.walk_back(start.to_vec(), &BTreeSet::new(), limit, 0)
    }

    /// `POST /get_missing_events`: return the ancestors of `latest`
    /// (the events themselves excluded) along `prev_events`, stopping at
    /// and excluding `earliest`, up to `limit` events at depth ≥
    /// `min_depth`. Oldest (lowest-depth) first — the order a requester
    /// applies them in.
    pub fn get_missing_events(
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
            if let Some(stored) = store.event(id).map_err(storage_err)? {
                let raw: CanonicalJsonObject = serde_json::from_slice(&stored.raw)
                    .map_err(|e| RoomError::Codec(e.to_string()))?;
                seed.extend(prev_event_ids(&raw));
            }
        }
        let mut events = self.walk_back(seed, &stop, limit, min_depth)?;
        events.reverse(); // newest-first walk → oldest-first response
        Ok(events)
    }

    /// Shared backward DAG walk: BFS over `prev_events` from `seed`,
    /// skipping `stop` IDs, collecting non-rejected events at depth ≥
    /// `min_depth`, newest (highest depth) first, capped at `limit`.
    fn walk_back(
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
            if let Some(ev) = store.event(id).map_err(storage_err)? {
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
            let Some(stored) = store.event(&id).map_err(storage_err)? else {
                continue;
            };
            if stored.rejected.is_some() || stored.depth < min_depth {
                continue;
            }
            let raw: CanonicalJsonObject =
                serde_json::from_slice(&stored.raw).map_err(|e| RoomError::Codec(e.to_string()))?;
            for prev in prev_event_ids(&raw) {
                if !seen.contains(&prev) {
                    if let Some(pv) = store.event(&prev).map_err(storage_err)? {
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
        let (version, room_id, _is_create) = self.classify(&raw)?;
        // Verify + persist through the normal pipeline (signature, hash,
        // auth against join rules).
        let outcome = {
            let _guard = self.lock_room(room_id.as_str()).await;
            // We are the resident servicing this join handshake: flag the
            // membership so the outbound sender relays it to the room's other
            // servers (spec "Joining Rooms": "The resident server must also
            // send the event to other servers participating in the room").
            self.process(raw, version, &room_id, false, true).await?
        };
        match &outcome {
            Outcome::Accepted { .. } | Outcome::Duplicate { .. } => {}
            Outcome::Rejected { reason, .. } => {
                return Err(RoomError::Malformed(format!("join rejected: {reason}")));
            }
        }
        let event_id = outcome.event_id().to_string();

        let store = self.store();
        // Co-sign the accepted join (resident adds its signature).
        let mut event = store
            .event(&event_id)
            .map_err(storage_err)?
            .ok_or_else(|| RoomError::MissingEvents(vec![event_id.clone()]))?;
        let mut signed: CanonicalJsonObject =
            serde_json::from_slice(&event.raw).map_err(|e| RoomError::Codec(e.to_string()))?;
        // Re-runs the (identical) content hash and merges our signature in
        // alongside the joiner's.
        self.signer.hash_and_sign_event(&mut signed, version)?;
        event.raw = raw_bytes(&signed)?;

        // Current room state, and the transitive auth chain behind it.
        let meta = store
            .meta(room_id.as_str())
            .map_err(storage_err)?
            .ok_or_else(|| RoomError::UnknownRoom(room_id.to_string()))?;
        let state_map = store
            .resolve_group(room_id.as_str(), meta.current_group)
            .map_err(storage_err)?;
        let mut state = Vec::new();
        let mut auth_seed = BTreeSet::new();
        for event_id in state_map.values() {
            if let Some(obj) = self.load_raw(&store, event_id)? {
                for auth_id in auth_event_ids(&obj) {
                    auth_seed.insert(auth_id);
                }
                state.push(obj);
            }
        }
        let auth_chain = self.collect_auth_chain(&store, auth_seed)?;

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
        let (version, room_id, _is_create) = self.classify(&raw)?;
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
            .map_err(storage_err)?
            .ok_or_else(|| RoomError::UnknownRoom(room_id.to_string()))?;
        let state_map = store
            .resolve_group(room_id.as_str(), meta.current_group)
            .map_err(storage_err)?;
        let mut wanted: Vec<(String, String)> = KNOCK_STATE_TYPES
            .iter()
            .map(|t| ((*t).to_owned(), String::new()))
            .collect();
        wanted.push(("m.room.member".to_owned(), knocker));
        let mut knock_room_state = Vec::new();
        for key in wanted {
            if let Some(event_id) = state_map.get(&key) {
                if let Some(obj) = self.load_raw(&store, event_id)? {
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
        let mut events = Vec::new();
        let mut seen = BTreeSet::new();
        let meta = self
            .store()
            .meta(room_id)
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
            .map_err(storage_err)?
            .ok_or_else(|| {
                RoomError::Malformed(format!("segment import: unknown room {room_id}"))
            })?;
        let version = RoomVersion::parse(&meta.version)?;

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
        for obj in auth_chain.iter().chain(state.iter()) {
            let Some(ev) = import_event(obj) else {
                continue;
            };
            if let (Ok(ty), Some(CanonicalJsonValue::String(sk))) =
                (str_of(obj, "type"), obj.get("state_key"))
            {
                state_map.insert((ty.to_owned(), sk.clone()), ev.event_id.clone());
            }
            if seen.insert(ev.event_id.clone()) {
                events.push(ev);
            }
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
    pub fn history_frontier(&self, room_id: &str) -> Result<Vec<String>> {
        Ok(self
            .store()
            .meta(room_id)
            .map_err(storage_err)?
            .map(|m| m.history_frontier)
            .unwrap_or_default())
    }

    fn load_raw(&self, store: &RoomStore, event_id: &str) -> Result<Option<CanonicalJsonObject>> {
        let Some(stored) = store.event(event_id).map_err(storage_err)? else {
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
    pub fn event_auth_chain(&self, event_id: &str) -> Result<Option<Vec<CanonicalJsonObject>>> {
        let store = self.store();
        let Some(event) = self.load_raw(&store, event_id)? else {
            return Ok(None);
        };
        let seed: BTreeSet<String> = auth_event_ids(&event).into_iter().collect();
        Ok(Some(self.collect_auth_chain(&store, seed)?))
    }

    fn collect_auth_chain(
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
            if let Some(obj) = self.load_raw(store, &id)? {
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
    ) -> Result<Outcome> {
        // The lock spans build + process: prev_events/auth_events read
        // here must still be the room's tip when the proposal lands.
        let _guard = self.lock_room(room_id.as_str()).await;
        let (raw, version) = self.build_local(room_id, sender, event_type, state_key, content)?;
        // Locally authored: the sender's `is_local` check fans it out already.
        self.process(raw, version, &room_id.to_owned(), false, false)
            .await
    }

    /// Determine room version and room ID of a PDU prior to validation.
    fn classify(&self, raw: &CanonicalJsonObject) -> Result<(RoomVersion, OwnedRoomId, bool)> {
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
            .map_err(storage_err)?
            .ok_or_else(|| RoomError::UnknownRoom(room_id.to_string()))?;
        Ok((RoomVersion::parse(&meta.version)?, room_id, false))
    }

    /// Build and sign a local event on the room's current tip.
    fn build_local(
        &self,
        room_id: &ruma::RoomId,
        sender: &UserId,
        event_type: &str,
        state_key: Option<&str>,
        content: serde_json::Value,
    ) -> Result<(CanonicalJsonObject, RoomVersion)> {
        let store = self.store();
        let meta = store
            .meta(room_id.as_str())
            .map_err(storage_err)?
            .ok_or_else(|| RoomError::UnknownRoom(room_id.to_string()))?;
        let version = RoomVersion::parse(&meta.version)?;
        let current = store
            .resolve_group(room_id.as_str(), meta.current_group)
            .map_err(storage_err)?;

        // prev_events = the forward extremities; depth = max(prev) + 1.
        let mut depth: u64 = 0;
        for id in &meta.extremities {
            let prev = store
                .event(id)
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
            "origin_server_ts": now_ms(),
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

    /// Pipeline steps 1–5 for one event. Caller holds the room lock.
    async fn process(
        &self,
        raw: CanonicalJsonObject,
        version: RoomVersion,
        room_id: &OwnedRoomId,
        is_create: bool,
        // True only for the resident-side `send_join`/`send_leave` handshake:
        // the accepted membership is flagged so the outbound sender fans it
        // out to the room's other servers (spec "Joining/Leaving Rooms").
        relay: bool,
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
            .map_err(storage_err)?
            .is_some()
        {
            return Ok(Outcome::Duplicate { event_id });
        }
        let meta = store.meta(room_id.as_str()).map_err(storage_err)?;
        if !is_create && meta.is_none() {
            return Err(RoomError::UnknownRoom(room_id.to_string()));
        }

        // -- 2. fetch auth_events and prev_events.
        let mut missing: Vec<String> = Vec::new();
        let mut auth_events: Vec<(IdentifiedPdu, bool)> = Vec::new();
        for id in event.auth_events() {
            match store.event(id.as_str()).map_err(storage_err)? {
                Some(se) => {
                    let rejected = se.rejected.is_some();
                    auth_events.push((parse_stored(id.clone(), &se)?, rejected));
                }
                None => missing.push(id.to_string()),
            }
        }
        let mut prev_groups: BTreeSet<u64> = BTreeSet::new();
        for id in event.prev_events() {
            match store.event(id.as_str()).map_err(storage_err)? {
                // A prev without a state group (auth-chain-rejected) gives
                // us no state to work from — treat as unfetchable.
                Some(se) if se.state_group_after == 0 => missing.push(id.to_string()),
                Some(se) => {
                    prev_groups.insert(se.state_group_after);
                }
                None => missing.push(id.to_string()),
            }
        }
        if !missing.is_empty() {
            return Err(RoomError::MissingEvents(missing));
        }

        // Events rejected against their own auth chain never participate
        // in state resolution (state-rejected ones do).
        let fetch = |id: &EventId| -> Option<IdentifiedPdu> {
            if id == event.event_id {
                return Some(event.clone());
            }
            let se = store.event(id.as_str()).ok().flatten()?;
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
            (materialize(&store, room_id.as_str(), g)?, g)
        } else {
            let mut sets = Vec::with_capacity(prev_groups.len());
            for g in &prev_groups {
                sets.push(materialize(&store, room_id.as_str(), *g)?);
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
                        .map_err(storage_err)?
                        .ok_or_else(|| RoomError::MissingEvents(vec![id.clone()]))?;
                    sets.push(materialize(&store, room_id.as_str(), se.state_group_after)?);
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
            self.redaction_target(&store, room_id, &event, version, &state_before, &fetch)?
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
    /// (evaluated against the state before the redaction). Unknown targets
    /// are dropped for now — M3 revisits out-of-order federated
    /// redactions.
    fn redaction_target(
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
        let Some(stored) = store.event(target_id.as_str()).map_err(storage_err)? else {
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
        let resp = self.handle.propose(bytes).await?;
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

fn materialize(store: &RoomStore, room_id: &str, group: u64) -> Result<StateIds> {
    let map = store.resolve_group(room_id, group).map_err(storage_err)?;
    let mut out = StateIds::new();
    for (k, v) in map {
        out.insert(
            k,
            OwnedEventId::try_from(v).map_err(|e| RoomError::Codec(format!("event id: {e}")))?,
        );
    }
    Ok(out)
}
