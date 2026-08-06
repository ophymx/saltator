//! Healing-policy tests against a mock [`EventFetcher`]: the sequences
//! Complement exercises over HTTP (prev-gap timeline walk, auth-outlier
//! fetch, rejection settling), reproduced in-process with no network.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ruma::{CanonicalJsonObject, CanonicalJsonValue, OwnedRoomId, OwnedUserId, RoomId};
use serde_json::json;

use saltator_core::RoomVersion;
use saltator_roomserver::{EventFetcher, Outcome, RoomServer, ServerSigner};
use saltator_shard::NoopNetworkFactory;
use saltator_store::RocksEngine;

const SERVER: &str = "hs.test";

fn user(local: &str) -> OwnedUserId {
    OwnedUserId::try_from(format!("@{local}:{SERVER}")).unwrap()
}

fn canonical(v: serde_json::Value) -> CanonicalJsonObject {
    match CanonicalJsonValue::try_from(v).unwrap() {
        CanonicalJsonValue::Object(o) => o,
        _ => panic!("not an object"),
    }
}

struct Env {
    _dir: tempfile::TempDir,
    server: Arc<RoomServer>,
    signer: Arc<ServerSigner>,
}

async fn start_env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let (signer, _der) = ServerSigner::generate(
        ruma::OwnedServerName::try_from(SERVER).unwrap(),
        "0".to_owned(),
    );
    let signer = Arc::new(signer);
    let engine = Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());
    let server = RoomServer::start(
        1,
        engine,
        signer.clone(),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    server
        .shard_handle()
        .wait_for_leader(std::time::Duration::from_secs(10))
        .await
        .unwrap();
    Env {
        _dir: dir,
        server,
        signer,
    }
}

fn accepted(outcome: &Outcome) -> u64 {
    match outcome {
        Outcome::Accepted { seq, .. } => *seq,
        other => panic!("expected Accepted, got {other:?}"),
    }
}

/// Bootstrap: create, creator join, PL (bob 50), public join rule, bob
/// joins. Returns the room id.
async fn bootstrap_room(env: &Env, version: RoomVersion) -> OwnedRoomId {
    let alice = user("alice");
    let bob = user("bob");
    let (room_id, outcome) = env
        .server
        .create_room(&alice, version, serde_json::Map::new())
        .await
        .unwrap();
    accepted(&outcome);
    let s = &env.server;
    for (sender, ty, sk, content) in [
        (
            &alice,
            "m.room.member",
            alice.as_str(),
            json!({"membership": "join"}),
        ),
        (
            &alice,
            "m.room.power_levels",
            "",
            json!({"users": {alice.as_str(): 100, bob.as_str(): 50}}),
        ),
        (
            &alice,
            "m.room.join_rules",
            "",
            json!({"join_rule": "public"}),
        ),
        (
            &bob,
            "m.room.member",
            bob.as_str(),
            json!({"membership": "join"}),
        ),
    ] {
        accepted(
            &s.send_state(&room_id, sender, ty, sk, content)
                .await
                .unwrap(),
        );
    }
    room_id
}

#[allow(clippy::too_many_arguments)]
fn craft_pdu(
    env: &Env,
    version: RoomVersion,
    room_id: &RoomId,
    sender: &str,
    event_type: &str,
    state_key: Option<&str>,
    content: serde_json::Value,
    prev_events: &[String],
    auth_events: &[String],
    depth: u64,
) -> CanonicalJsonObject {
    let mut v = json!({
        "room_id": room_id.as_str(),
        "sender": sender,
        "origin_server_ts": 1_700_000_000_000_u64 + depth,
        "type": event_type,
        "content": content,
        "auth_events": auth_events,
        "prev_events": prev_events,
        "depth": depth,
    });
    if let Some(sk) = state_key {
        v["state_key"] = sk.into();
    }
    let mut raw = canonical(v);
    env.signer.hash_and_sign_event(&mut raw, version).unwrap();
    raw
}

/// Auth events for a crafted event, read from current room state.
fn auth_ids_from_state(
    env: &Env,
    version: RoomVersion,
    room_id: &RoomId,
    event_type: &str,
    sender: &OwnedUserId,
    state_key: Option<&str>,
    content: &serde_json::Value,
) -> Vec<String> {
    let store = env.server.store();
    let meta = store.meta(room_id.as_str()).unwrap().unwrap();
    let current = store
        .resolve_group(room_id.as_str(), meta.current_group)
        .unwrap();
    let content = canonical(content.clone());
    saltator_core::auth::auth_types_for_event(version, event_type, sender, state_key, &content)
        .into_iter()
        .filter_map(|k| current.get(&k).cloned())
        .collect()
}

fn event_id(env: &Env, obj: &CanonicalJsonObject) -> String {
    env.server.pdu_event_id(obj).unwrap().to_string()
}

/// Mock transport: canned responses + a call log for asserting which
/// healing sequence ran.
#[derive(Default)]
struct MockFetcher {
    /// `/event/{id}` responses; absent = the origin 404s it.
    events: HashMap<String, CanonicalJsonObject>,
    /// `/get_missing_events` response (oldest first).
    missing_chain: Vec<CanonicalJsonObject>,
    calls: Mutex<Vec<String>>,
}

impl MockFetcher {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
    fn log(&self, s: impl Into<String>) {
        self.calls.lock().unwrap().push(s.into());
    }
}

impl EventFetcher for MockFetcher {
    async fn get_missing_events(
        &self,
        _origin: &str,
        _room_id: &str,
        _earliest: Vec<String>,
        _latest: &str,
        _limit: usize,
    ) -> Result<Vec<CanonicalJsonObject>, String> {
        self.log("get_missing_events");
        Ok(self.missing_chain.clone())
    }
    async fn state_ids(
        &self,
        _origin: &str,
        _room_id: &str,
        _event_id: &str,
    ) -> Result<(Vec<String>, Vec<String>), String> {
        self.log("state_ids");
        Err("not served".into())
    }
    async fn state(
        &self,
        _origin: &str,
        _room_id: &str,
        _event_id: &str,
    ) -> Result<(Vec<CanonicalJsonObject>, Vec<CanonicalJsonObject>), String> {
        self.log("state");
        Err("not served".into())
    }
    async fn event(
        &self,
        _origin: &str,
        event_id: &str,
    ) -> Result<Option<CanonicalJsonObject>, String> {
        self.log(format!("event:{event_id}"));
        Ok(self.events.get(event_id).cloned())
    }
    async fn trust_origin_keys(&self, _origin: &str) {}
    async fn trust_event_servers(&self, _events: &[CanonicalJsonObject]) {}
}

/// A prev-gap heals through the timeline walk: B arrives citing unknown
/// A; `/get_missing_events` serves A; both land accepted.
#[tokio::test]
async fn prev_gap_heals_via_timeline_walk() {
    let env = start_env().await;
    let version = RoomVersion::V11;
    let room_id = bootstrap_room(&env, version).await;
    let bob = user("bob");
    let tip = env.server.room_extremities(room_id.as_str()).unwrap();
    let auth = auth_ids_from_state(
        &env,
        version,
        &room_id,
        "m.room.message",
        &bob,
        None,
        &json!({}),
    );

    let a = craft_pdu(
        &env,
        version,
        &room_id,
        bob.as_str(),
        "m.room.message",
        None,
        json!({"body": "A"}),
        &tip,
        &auth,
        40,
    );
    let a_id = event_id(&env, &a);
    let b = craft_pdu(
        &env,
        version,
        &room_id,
        bob.as_str(),
        "m.room.message",
        None,
        json!({"body": "B"}),
        std::slice::from_ref(&a_id),
        &auth,
        41,
    );

    let fetcher = MockFetcher {
        missing_chain: vec![a.clone()],
        ..Default::default()
    };
    let outcome = env
        .server
        .ingest_pdu_healing(&fetcher, SERVER, b)
        .await
        .unwrap();
    accepted(&outcome);
    assert!(env.server.store().event(&a_id).unwrap().is_some());
    assert!(fetcher.calls().contains(&"get_missing_events".to_owned()));
}

/// An auth-only miss fetches the cited event as an outlier via `/event`
/// and must NOT fire the timeline walk (Complement's
/// RejectsEventsWithRejectedAuthEvents forbids it).
#[tokio::test]
async fn missing_auth_fetches_outlier_never_timeline_walk() {
    let env = start_env().await;
    let version = RoomVersion::V11;
    let room_id = bootstrap_room(&env, version).await;
    let bob = user("bob");
    let tip = env.server.room_extremities(room_id.as_str()).unwrap();
    let member_auth = auth_ids_from_state(
        &env,
        version,
        &room_id,
        "m.room.member",
        &bob,
        Some(bob.as_str()),
        &json!({"membership": "join"}),
    );

    // M: a membership refresh we never ingested — cited as C's auth.
    let m = craft_pdu(
        &env,
        version,
        &room_id,
        bob.as_str(),
        "m.room.member",
        Some(bob.as_str()),
        json!({"membership": "join", "displayname": "outlier"}),
        &tip,
        &member_auth,
        40,
    );
    let m_id = event_id(&env, &m);
    let msg_auth = auth_ids_from_state(
        &env,
        version,
        &room_id,
        "m.room.message",
        &bob,
        None,
        &json!({}),
    );
    // C cites M in its member slot: replace bob's current member event.
    let c_auth: Vec<String> = msg_auth
        .iter()
        .map(|id| {
            let is_member = env
                .server
                .store()
                .event(id)
                .unwrap()
                .map(|se| {
                    serde_json::from_slice::<serde_json::Value>(&se.raw)
                        .map(|v| v.get("type").and_then(|t| t.as_str()) == Some("m.room.member"))
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            if is_member {
                m_id.clone()
            } else {
                id.clone()
            }
        })
        .collect();
    let c = craft_pdu(
        &env,
        version,
        &room_id,
        bob.as_str(),
        "m.room.message",
        None,
        json!({"body": "C"}),
        &tip,
        &c_auth,
        41,
    );

    let fetcher = MockFetcher {
        events: HashMap::from([(m_id.clone(), m.clone())]),
        ..Default::default()
    };
    let outcome = env
        .server
        .ingest_pdu_healing(&fetcher, SERVER, c)
        .await
        .unwrap();
    accepted(&outcome);
    let calls = fetcher.calls();
    assert!(calls.contains(&format!("event:{m_id}")));
    assert!(
        !calls.contains(&"get_missing_events".to_owned()),
        "auth-only miss must not fire the timeline walk: {calls:?}"
    );
}

/// An auth chain the origin refuses to serve settles as a stored
/// rejection (no error), and a later event behind the rejected one still
/// lands — the TestCorruptedAuthChain / RejectsEvents sentinel contract.
#[tokio::test]
async fn unfetchable_auth_chain_settles_as_rejection() {
    let env = start_env().await;
    let version = RoomVersion::V11;
    let room_id = bootstrap_room(&env, version).await;
    let bob = user("bob");
    let tip = env.server.room_extremities(room_id.as_str()).unwrap();
    let member_auth = auth_ids_from_state(
        &env,
        version,
        &room_id,
        "m.room.member",
        &bob,
        Some(bob.as_str()),
        &json!({"membership": "join"}),
    );

    // M is never served by the origin (the deliberate 404).
    let m = craft_pdu(
        &env,
        version,
        &room_id,
        bob.as_str(),
        "m.room.member",
        Some(bob.as_str()),
        json!({"membership": "join", "displayname": "vanished"}),
        &tip,
        &member_auth,
        40,
    );
    let m_id = event_id(&env, &m);
    let msg_auth = auth_ids_from_state(
        &env,
        version,
        &room_id,
        "m.room.message",
        &bob,
        None,
        &json!({}),
    );
    let d_auth: Vec<String> = msg_auth
        .iter()
        .map(|id| {
            let is_member = env
                .server
                .store()
                .event(id)
                .unwrap()
                .map(|se| {
                    serde_json::from_slice::<serde_json::Value>(&se.raw)
                        .map(|v| v.get("type").and_then(|t| t.as_str()) == Some("m.room.member"))
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            if is_member {
                m_id.clone()
            } else {
                id.clone()
            }
        })
        .collect();
    let d = craft_pdu(
        &env,
        version,
        &room_id,
        bob.as_str(),
        "m.room.message",
        None,
        json!({"body": "D"}),
        &tip,
        &d_auth,
        41,
    );
    let d_id = event_id(&env, &d);

    let fetcher = MockFetcher::default(); // serves nothing
    let outcome = env
        .server
        .ingest_pdu_healing(&fetcher, SERVER, d.clone())
        .await
        .unwrap();
    assert!(
        matches!(outcome, Outcome::Rejected { .. }),
        "unfetchable auth chain must settle as rejection, got {outcome:?}"
    );

    // The sentinel: an ordinary event behind the rejected one still lands
    // (its state falls back to the rejected event's ancestors).
    let sentinel = craft_pdu(
        &env,
        version,
        &room_id,
        bob.as_str(),
        "m.room.message",
        None,
        json!({"body": "sentinel"}),
        &[d_id],
        &msg_auth,
        42,
    );
    let outcome = env
        .server
        .ingest_pdu_healing(&fetcher, SERVER, sentinel)
        .await
        .unwrap();
    accepted(&outcome);
}
