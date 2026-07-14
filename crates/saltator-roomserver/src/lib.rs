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
        let outcome = self.process(raw, version, &room_id, true).await?;
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
        self.process(raw, version, &room_id, is_create).await
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
        ts: u64,
    ) -> Result<u64> {
        let resp = self
            .propose_cmd(&RoomCommand::Receipt(ReceiptCmd {
                room_id: room_id.to_string(),
                user_id: user_id.to_string(),
                receipt_type: receipt_type.to_owned(),
                event_id: event_id.to_string(),
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
        self.process(raw, version, &room_id.to_owned(), false).await
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
            RoomResponse::Receipt { .. } => {
                return Err(RoomError::Codec(
                    "unexpected receipt response to append".into(),
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
