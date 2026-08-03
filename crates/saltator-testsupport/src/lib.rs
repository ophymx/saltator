//! Shared test support: a light-weight mock Matrix federation peer — the
//! Rust analogue of Complement's in-process `federation.NewServer`. A
//! dev-dependency of the crates whose tests drive federation
//! (`saltator-federation`, `saltator-cs-api`).
//!
//! Unlike tests that spin up a *real* `RoomServer` as the peer, this peer
//! crafts and signs events directly, so it can build arbitrary — including
//! deliberately malformed or DAG-forked — rooms that a real server would
//! refuse to produce. It:
//!
//!   1. has its own ed25519 identity and serves `/_matrix/key/v2/server`,
//!   2. hosts rooms as a signed event DAG ([`PeerRoom`]),
//!   3. serves the endpoints our server calls (`make_join`, `send_join`),
//!   4. actively pushes signed transactions to our server, and
//!   5. captures what our server sends back (its outbound requests).
//!
//! Event construction mirrors `RoomServer::create_room` /
//! `make_membership_template` exactly, and reuses the real
//! `auth_types_for_event` selection + `event::event_id` hashing, so events
//! this peer produces are byte-for-byte the shape our pipeline expects.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::routing::{get, put};
use axum::Json;
use ruma::{CanonicalJsonObject, CanonicalJsonValue, OwnedServerName, UserId};
use serde_json::json;

use saltator_core::auth::auth_types_for_event;
use saltator_core::{event, RoomVersion};
use saltator_federation::sign_request;
use saltator_roomserver::ServerSigner;

/// Wall-clock milliseconds (for key validity and transaction stamps).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Coerce a `serde_json::Value` into a canonical object (panics if it isn't
/// one — test-only).
pub fn canon(v: serde_json::Value) -> CanonicalJsonObject {
    match CanonicalJsonValue::try_from(v).unwrap() {
        CanonicalJsonValue::Object(o) => o,
        _ => panic!("value is not a JSON object"),
    }
}

/// The `event_id`s referenced under `key` (v3+ list-of-strings form).
fn id_list(raw: &CanonicalJsonObject, key: &str) -> Vec<String> {
    match raw.get(key) {
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

/// Strip an event's `signatures` — the standard way to craft a PDU that
/// must fail signature verification (Complement does the same via
/// `sjson.SetRawBytes(raw, "signatures", "{}")`).
pub fn strip_signatures(mut raw: CanonicalJsonObject) -> CanonicalJsonObject {
    raw.insert(
        "signatures".to_owned(),
        CanonicalJsonValue::Object(CanonicalJsonObject::new()),
    );
    raw
}

/// A room hosted by the peer: a signed event DAG plus its resolved current
/// state and forward extremities.
pub struct PeerRoom {
    pub version: RoomVersion,
    pub room_id: String,
    signer: Arc<ServerSigner>,
    server_name: String,
    /// `event_id` -> raw event.
    events: BTreeMap<String, CanonicalJsonObject>,
    /// `(type, state_key)` -> `event_id` (current resolved state).
    state: BTreeMap<(String, String), String>,
    /// The DAG leaves — `prev_events` for the next appended event.
    extremities: Vec<String>,
    /// Monotonic `origin_server_ts` source (deterministic spacing).
    ts: u64,
}

impl PeerRoom {
    /// Bootstrap a joinable public room: create → creator join → power
    /// levels → public join rule. `creator` is a full user ID on the peer.
    fn bootstrap(signer: Arc<ServerSigner>, version: RoomVersion, creator: &str) -> Self {
        let server_name = signer.server_name().as_str().to_owned();
        let mut room = Self {
            version,
            room_id: String::new(),
            signer,
            server_name,
            events: BTreeMap::new(),
            state: BTreeMap::new(),
            extremities: Vec::new(),
            ts: 1_600_000_000_000,
        };
        room.build_create(creator);
        room.state_event(
            creator,
            "m.room.member",
            creator,
            json!({"membership": "join"}),
        );
        room.state_event(
            creator,
            "m.room.power_levels",
            "",
            json!({"users": {creator: 100}}),
        );
        room.state_event(
            creator,
            "m.room.join_rules",
            "",
            json!({"join_rule": "public"}),
        );
        room
    }

    fn next_ts(&mut self) -> u64 {
        self.ts += 1;
        self.ts
    }

    fn depth_of(&self, id: &str) -> u64 {
        match self.events.get(id).and_then(|r| r.get("depth")) {
            Some(CanonicalJsonValue::Integer(i)) => i64::from(*i).max(0) as u64,
            _ => 0,
        }
    }

    fn max_prev_depth(&self, prev: &[String]) -> u64 {
        prev.iter().map(|id| self.depth_of(id)).max().unwrap_or(0)
    }

    /// Build, sign, and record the `m.room.create` event; derive the room ID.
    fn build_create(&mut self, creator: &str) {
        let mut content = serde_json::Map::new();
        content.insert("room_version".into(), self.version.as_str().into());
        if self.version.creator_in_create_content() {
            content.insert("creator".into(), creator.into());
        }
        let ts = self.next_ts();
        let mut v = json!({
            "sender": creator,
            "origin_server_ts": ts,
            "type": "m.room.create",
            "state_key": "",
            "content": content,
            "auth_events": [],
            "prev_events": [],
            "depth": 1,
        });
        let room_id = if self.version.room_id_is_create_event_id() {
            None
        } else {
            let rid = ruma::RoomId::new_v1(self.signer.server_name());
            v["room_id"] = rid.as_str().into();
            Some(rid.as_str().to_owned())
        };
        let mut raw = canon(v);
        self.signer
            .hash_and_sign_event(&mut raw, self.version)
            .unwrap();
        self.room_id = room_id.unwrap_or_else(|| {
            event::room_id_for_create(&raw, self.version)
                .unwrap()
                .to_string()
        });
        // v12: the create event carries no room_id; the DAG still keys on it.
        let id = event::event_id(&raw, self.version).unwrap().to_string();
        self.events.insert(id.clone(), raw);
        self.state
            .insert(("m.room.create".into(), String::new()), id.clone());
        self.extremities = vec![id];
    }

    /// The `auth_events` an event of `(ty, state_key)` from `sender` needs,
    /// resolved from current state — exactly the server's selection.
    fn auth_events_for(
        &self,
        sender: &str,
        ty: &str,
        state_key: Option<&str>,
        content: &CanonicalJsonObject,
    ) -> Vec<String> {
        let sender_id = UserId::parse(sender).unwrap();
        auth_types_for_event(self.version, ty, &sender_id, state_key, content)
            .iter()
            .filter_map(|k| self.state.get(k).cloned())
            .collect()
    }

    /// Append a state event on the current extremities.
    pub fn state_event(
        &mut self,
        sender: &str,
        ty: &str,
        state_key: &str,
        content: serde_json::Value,
    ) -> String {
        self.append(sender, ty, Some(state_key), content, None)
    }

    /// Append a message (non-state) event on the current extremities.
    pub fn message(&mut self, sender: &str, content: serde_json::Value) -> String {
        self.append(sender, "m.room.message", None, content, None)
    }

    /// Append a state event, then strip its signature so it lands in the
    /// room's current state as an *unverifiable* event (for testing that a
    /// receiver drops non-critical unverifiable state rather than refusing
    /// the whole send_join). The reference hash — and thus the event ID —
    /// is unchanged by stripping signatures, so the event is well-formed but
    /// unsigned.
    pub fn unverifiable_state_event(
        &mut self,
        sender: &str,
        ty: &str,
        state_key: &str,
        content: serde_json::Value,
    ) -> String {
        self.append_inner(sender, ty, Some(state_key), content, None, true)
    }

    /// Append an event with explicit `prev_events` — the primitive for
    /// forking (prev = an earlier event) or merging (prev = several leaves).
    pub fn event_with_prev(
        &mut self,
        sender: &str,
        ty: &str,
        state_key: Option<&str>,
        content: serde_json::Value,
        prev: Vec<String>,
    ) -> String {
        self.append(sender, ty, state_key, content, Some(prev))
    }

    fn append(
        &mut self,
        sender: &str,
        ty: &str,
        state_key: Option<&str>,
        content: serde_json::Value,
        prev_override: Option<Vec<String>>,
    ) -> String {
        self.append_inner(sender, ty, state_key, content, prev_override, false)
    }

    fn append_inner(
        &mut self,
        sender: &str,
        ty: &str,
        state_key: Option<&str>,
        content: serde_json::Value,
        prev_override: Option<Vec<String>>,
        strip_sig: bool,
    ) -> String {
        let content_obj = canon(content);
        let auth_events = self.auth_events_for(sender, ty, state_key, &content_obj);
        let prev = prev_override.unwrap_or_else(|| self.extremities.clone());
        let depth = self.max_prev_depth(&prev) + 1;
        let ts = self.next_ts();
        let mut v = json!({
            "room_id": self.room_id,
            "sender": sender,
            "origin_server_ts": ts,
            "type": ty,
            "content": CanonicalJsonValue::Object(content_obj),
            "auth_events": auth_events,
            "prev_events": prev,
            "depth": depth,
        });
        if let Some(sk) = state_key {
            v["state_key"] = sk.into();
        }
        let mut raw = canon(v);
        self.signer
            .hash_and_sign_event(&mut raw, self.version)
            .unwrap();
        let id = event::event_id(&raw, self.version).unwrap().to_string();
        if strip_sig {
            raw = strip_signatures(raw);
        }
        self.record(
            id.clone(),
            raw,
            state_key.map(|sk| (ty.to_owned(), sk.to_owned())),
            &prev,
        );
        id
    }

    /// Record an event, updating state and forward extremities.
    fn record(
        &mut self,
        id: String,
        raw: CanonicalJsonObject,
        state_slot: Option<(String, String)>,
        prev: &[String],
    ) {
        self.events.insert(id.clone(), raw);
        if let Some(slot) = state_slot {
            self.state.insert(slot, id.clone());
        }
        // Extremities = (old extremities not consumed by prev) + this event.
        let mut ext: Vec<String> = self
            .extremities
            .iter()
            .filter(|e| !prev.contains(e))
            .cloned()
            .collect();
        ext.push(id);
        self.extremities = ext;
    }

    /// The raw event by ID (for building transactions to push).
    pub fn raw(&self, id: &str) -> CanonicalJsonObject {
        self.events.get(id).expect("unknown event id").clone()
    }

    /// The room's current forward extremities (use as `prev_events` for a
    /// crafted event that should sit at the tip).
    pub fn tip(&self) -> Vec<String> {
        self.extremities.clone()
    }

    /// The event ID of a current state entry (`m.room.create`, power levels,
    /// a member) — for hand-building `auth_events`.
    pub fn state_event_id(&self, ty: &str, state_key: &str) -> Option<String> {
        self.state
            .get(&(ty.to_owned(), state_key.to_owned()))
            .cloned()
    }

    /// Craft (build + sign) a standalone event with **explicit** `prev_events`
    /// and `auth_events`, without folding it into the room's tracked state or
    /// forward extremities. This is the primitive for hand-shaping DAG
    /// fragments — rejected events, outliers, events that cite a specific
    /// (possibly rejected) auth event — that the automatic builders won't
    /// produce. The raw event is retained so later `raw()`/auth lookups
    /// resolve it. Returns its `(event_id, raw)`.
    pub fn craft(
        &mut self,
        sender: &str,
        ty: &str,
        state_key: Option<&str>,
        content: serde_json::Value,
        prev: Vec<String>,
        auth_events: Vec<String>,
    ) -> (String, CanonicalJsonObject) {
        let depth = self.max_prev_depth(&prev) + 1;
        let ts = self.next_ts();
        let mut v = json!({
            "room_id": self.room_id,
            "sender": sender,
            "origin_server_ts": ts,
            "type": ty,
            "content": CanonicalJsonValue::Object(canon(content)),
            "auth_events": auth_events,
            "prev_events": prev,
            "depth": depth,
        });
        if let Some(sk) = state_key {
            v["state_key"] = sk.into();
        }
        let mut raw = canon(v);
        self.signer
            .hash_and_sign_event(&mut raw, self.version)
            .unwrap();
        let id = event::event_id(&raw, self.version).unwrap().to_string();
        self.events.insert(id.clone(), raw.clone());
        (id, raw)
    }

    /// An unsigned `m.room.member` join template for `user_id` (the shape
    /// `make_join` returns; the joiner fills nothing and signs it as-is).
    fn join_template(&self, user_id: &str) -> CanonicalJsonObject {
        let content = canon(json!({"membership": "join"}));
        let auth_events = self.auth_events_for(user_id, "m.room.member", Some(user_id), &content);
        let depth = self.max_prev_depth(&self.extremities) + 1;
        canon(json!({
            "room_id": self.room_id,
            "sender": user_id,
            "state_key": user_id,
            "origin_server_ts": now_ms(),
            "type": "m.room.member",
            "content": CanonicalJsonValue::Object(content),
            "auth_events": auth_events,
            "prev_events": self.extremities,
            "depth": depth,
        }))
    }

    /// Current resolved state, as raw events.
    fn state_events(&self) -> Vec<CanonicalJsonObject> {
        self.state
            .values()
            .map(|id| self.events[id].clone())
            .collect()
    }

    /// Transitive `auth_events` closure of `seeds` (the seeds excluded).
    fn auth_chain(&self, seeds: &[String]) -> Vec<CanonicalJsonObject> {
        let mut out = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut stack: Vec<String> = seeds.to_vec();
        while let Some(id) = stack.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            if let Some(raw) = self.events.get(&id) {
                for a in id_list(raw, "auth_events") {
                    stack.push(a);
                }
                out.push(raw.clone());
            }
        }
        out
    }

    /// Accept a joiner's signed membership: co-sign it, fold it into the
    /// DAG, and return the `send_join` response body (matching the shape our
    /// `send_join` handler produces: `{event, state, auth_chain, origin}`).
    fn accept_join(&mut self, mut join: CanonicalJsonObject) -> serde_json::Value {
        // Co-sign as the resident (real servers do; the ID is unchanged
        // since reference hashes exclude signatures).
        self.signer
            .hash_and_sign_event(&mut join, self.version)
            .unwrap();
        let id = event::event_id(&join, self.version).unwrap().to_string();
        let sender = match join.get("state_key") {
            Some(CanonicalJsonValue::String(s)) => s.clone(),
            _ => String::new(),
        };
        let prev = id_list(&join, "prev_events");
        let seeds = id_list(&join, "auth_events");
        self.record(
            id.clone(),
            join.clone(),
            Some(("m.room.member".to_owned(), sender)),
            &prev,
        );
        let to_array = |v: Vec<CanonicalJsonObject>| {
            serde_json::Value::Array(
                v.into_iter()
                    .map(|o| serde_json::Value::from(CanonicalJsonValue::Object(o)))
                    .collect(),
            )
        };
        json!({
            "event": CanonicalJsonValue::Object(join),
            "state": to_array(self.state_events()),
            "auth_chain": to_array(self.auth_chain(&seeds)),
            "origin": self.server_name,
        })
    }
}

/// A captured inbound transaction (our server's outbound `/send`).
#[derive(Clone, Debug)]
pub struct ReceivedTxn {
    pub origin: String,
    pub pdus: Vec<serde_json::Value>,
    pub edus: Vec<serde_json::Value>,
}

struct PeerInner {
    name: OwnedServerName,
    signer: Arc<ServerSigner>,
    rooms: Mutex<BTreeMap<String, PeerRoom>>,
    received: Mutex<Vec<ReceivedTxn>>,
}

/// A running mock federation peer.
pub struct MockPeer {
    pub name: String,
    pub signer: Arc<ServerSigner>,
    pub base_url: String,
    inner: Arc<PeerInner>,
    txn_seq: AtomicU64,
}

impl MockPeer {
    /// Start a peer at server name `name` (e.g. `"peer.test"`), spawning its
    /// HTTP surface on a loopback port.
    pub async fn start(name: &str) -> MockPeer {
        let server_name: OwnedServerName = name.try_into().unwrap();
        let (signer, _) = ServerSigner::generate(server_name.clone(), "1".to_owned());
        let signer = Arc::new(signer);
        let inner = Arc::new(PeerInner {
            name: server_name,
            signer: signer.clone(),
            rooms: Mutex::new(BTreeMap::new()),
            received: Mutex::new(Vec::new()),
        });
        let app = axum::Router::new()
            .route("/_matrix/key/v2/server", get(serve_keys))
            .route(
                "/_matrix/federation/v1/make_join/{room_id}/{user_id}",
                get(serve_make_join),
            )
            .route(
                "/_matrix/federation/v2/send_join/{room_id}/{event_id}",
                put(serve_send_join),
            )
            .route("/_matrix/federation/v1/send/{txn_id}", put(serve_send))
            .with_state(inner.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        MockPeer {
            name: name.to_owned(),
            signer,
            base_url: format!("http://{addr}"),
            inner,
            txn_seq: AtomicU64::new(0),
        }
    }

    /// Bootstrap a joinable public room owned by `@<creator>:<peer>`.
    /// Returns the room ID.
    pub fn make_room(&self, version: RoomVersion, creator_localpart: &str) -> String {
        let creator = format!("@{creator_localpart}:{}", self.name);
        let room = PeerRoom::bootstrap(self.signer.clone(), version, &creator);
        let room_id = room.room_id.clone();
        self.inner
            .rooms
            .lock()
            .unwrap()
            .insert(room_id.clone(), room);
        room_id
    }

    /// Mutate a hosted room (append events, fork the DAG, grab raw events).
    pub fn with_room<T>(&self, room_id: &str, f: impl FnOnce(&mut PeerRoom) -> T) -> T {
        let mut rooms = self.inner.rooms.lock().unwrap();
        f(rooms.get_mut(room_id).expect("unknown room"))
    }

    /// Push a signed transaction of `pdus` to `our_base` (a running server
    /// whose server name is `our_name`), authenticated as this peer.
    pub async fn send_transaction(
        &self,
        our_base: &str,
        our_name: &str,
        pdus: Vec<CanonicalJsonObject>,
    ) -> serde_json::Value {
        let seq = self.txn_seq.fetch_add(1, Ordering::SeqCst);
        let path = format!("/_matrix/federation/v1/send/txn{seq}");
        let body = json!({
            "origin": self.name,
            "origin_server_ts": now_ms(),
            "pdus": pdus
                .into_iter()
                .map(|o| serde_json::Value::from(CanonicalJsonValue::Object(o)))
                .collect::<Vec<_>>(),
        });
        let content = CanonicalJsonValue::try_from(body.clone()).unwrap();
        let auth = sign_request(&self.signer, "PUT", &path, our_name, Some(&content)).unwrap();
        reqwest::Client::new()
            .put(format!("{our_base}{path}"))
            .header(reqwest::header::AUTHORIZATION, auth)
            .json(&body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    /// Transactions our server has pushed to this peer (its outbound).
    pub fn received(&self) -> Vec<ReceivedTxn> {
        self.inner.received.lock().unwrap().clone()
    }
}

async fn serve_keys(State(inner): State<Arc<PeerInner>>) -> Json<serde_json::Value> {
    let mut verify_keys = CanonicalJsonObject::new();
    let mut key_obj = CanonicalJsonObject::new();
    key_obj.insert(
        "key".to_owned(),
        CanonicalJsonValue::String(inner.signer.public_key_b64()),
    );
    verify_keys.insert(inner.signer.key_id(), CanonicalJsonValue::Object(key_obj));

    let mut object = CanonicalJsonObject::new();
    object.insert(
        "server_name".to_owned(),
        CanonicalJsonValue::String(inner.name.as_str().to_owned()),
    );
    object.insert(
        "verify_keys".to_owned(),
        CanonicalJsonValue::Object(verify_keys),
    );
    object.insert(
        "old_verify_keys".to_owned(),
        CanonicalJsonValue::Object(CanonicalJsonObject::new()),
    );
    object.insert(
        "valid_until_ts".to_owned(),
        CanonicalJsonValue::Integer(
            ruma::Int::try_from((now_ms() + 24 * 60 * 60 * 1000) as i64).unwrap_or(ruma::Int::MAX),
        ),
    );
    inner.signer.sign_json(&mut object).unwrap();
    Json(serde_json::Value::from(CanonicalJsonValue::Object(object)))
}

async fn serve_make_join(
    State(inner): State<Arc<PeerInner>>,
    Path((room_id, user_id)): Path<(String, String)>,
) -> Json<serde_json::Value> {
    let rooms = inner.rooms.lock().unwrap();
    let Some(room) = rooms.get(&room_id) else {
        return Json(json!({"errcode": "M_NOT_FOUND", "error": "unknown room"}));
    };
    let template = room.join_template(&user_id);
    Json(json!({
        "room_version": room.version.as_str(),
        "event": CanonicalJsonValue::Object(template),
    }))
}

async fn serve_send_join(
    State(inner): State<Arc<PeerInner>>,
    Path((room_id, _event_id)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let mut rooms = inner.rooms.lock().unwrap();
    let Some(room) = rooms.get_mut(&room_id) else {
        return Json(json!({"errcode": "M_NOT_FOUND", "error": "unknown room"}));
    };
    let join = match CanonicalJsonValue::try_from(body) {
        Ok(CanonicalJsonValue::Object(o)) => o,
        _ => return Json(json!({"errcode": "M_BAD_JSON", "error": "join is not an object"})),
    };
    Json(room.accept_join(join))
}

async fn serve_send(
    State(inner): State<Arc<PeerInner>>,
    Path(_txn_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let origin = body
        .get("origin")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    let pdus = body
        .get("pdus")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let edus = body
        .get("edus")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    inner
        .received
        .lock()
        .unwrap()
        .push(ReceivedTxn { origin, pdus, edus });
    Json(json!({ "pdus": {} }))
}
