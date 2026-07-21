//! M1 exit criterion (spec.md §12): events flow through the full pipeline
//! in-process — local sends and federation-shaped PDU ingests, both room
//! versions, validate → fetch → authorize → resolve → persist → emit.

use std::sync::Arc;

use ruma::{CanonicalJsonObject, CanonicalJsonValue, OwnedRoomId, OwnedUserId, RoomId};
use serde_json::json;

use saltator_core::RoomVersion;
use saltator_roomserver::{
    ChangePayload, Outcome, Rejected, RoomError, RoomServer, SeqEntry, ServerSigner,
};
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

/// Bootstrap a room to a usable state: create, creator join, power levels
/// (bob at 50), public join rule, bob joins. Returns the room ID.
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
    accepted(
        &s.send_state(
            &room_id,
            &alice,
            "m.room.member",
            alice.as_str(),
            json!({"membership": "join"}),
        )
        .await
        .unwrap(),
    );
    // v12 creators have infinite power and must NOT be listed in `users`.
    let users = if version.privileged_creators() {
        json!({bob.as_str(): 50})
    } else {
        json!({alice.as_str(): 100, bob.as_str(): 50})
    };
    accepted(
        &s.send_state(
            &room_id,
            &alice,
            "m.room.power_levels",
            "",
            json!({"users": users}),
        )
        .await
        .unwrap(),
    );
    accepted(
        &s.send_state(
            &room_id,
            &alice,
            "m.room.join_rules",
            "",
            json!({"join_rule": "public"}),
        )
        .await
        .unwrap(),
    );
    accepted(
        &s.send_state(
            &room_id,
            &bob,
            "m.room.member",
            bob.as_str(),
            json!({"membership": "join"}),
        )
        .await
        .unwrap(),
    );
    room_id
}

/// Hand-craft, hash, and sign a PDU with explicit prev/auth events — the
/// federation-shaped path.
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

/// The auth events a crafted event needs, read from current room state.
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

async fn full_pipeline(version: RoomVersion) {
    let env = start_env().await;
    let alice = user("alice");
    let bob = user("bob");
    let mut changes = env.server.subscribe();

    let room_id = bootstrap_room(&env, version).await;

    // v12 rooms derive their ID from the create event.
    if version.room_id_is_create_event_id() {
        let store = env.server.store();
        let meta = store.meta(room_id.as_str()).unwrap().unwrap();
        assert_eq!(&room_id.as_str()[1..], &meta.create_event_id[1..]);
    }

    // Messages flow and are sequenced.
    let m1 = accepted(
        &env.server
            .send_message(
                &room_id,
                &alice,
                "m.room.message",
                json!({"msgtype": "m.text", "body": "hi"}),
            )
            .await
            .unwrap(),
    );
    let m2 = accepted(
        &env.server
            .send_message(
                &room_id,
                &bob,
                "m.room.message",
                json!({"msgtype": "m.text", "body": "hey"}),
            )
            .await
            .unwrap(),
    );
    assert!(m2 > m1);

    // Current state has exactly the expected keys.
    let store = env.server.store();
    let meta = store.meta(room_id.as_str()).unwrap().unwrap();
    let state = store
        .resolve_group(room_id.as_str(), meta.current_group)
        .unwrap();
    let mut keys: Vec<&(String, String)> = state.keys().collect();
    keys.sort();
    assert_eq!(
        keys.iter()
            .map(|(t, k)| (t.as_str(), k.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("m.room.create", ""),
            ("m.room.join_rules", ""),
            ("m.room.member", alice.as_str()),
            ("m.room.member", bob.as_str()),
            ("m.room.power_levels", ""),
        ],
    );

    // One extremity: the last message.
    assert_eq!(meta.extremities.len(), 1);

    // The change stream saw every accepted event, in seq order.
    let mut seen = Vec::new();
    while let Ok(c) = changes.try_recv() {
        match RoomServer::decode_change(&c.payload).unwrap() {
            ChangePayload::Event {
                room_id: payload_room,
                ..
            } => assert_eq!(payload_room, room_id.as_str()),
            other => panic!("expected event change, got {other:?}"),
        }
        seen.push(c.seq);
    }
    assert_eq!(seen.len(), 7); // create, join, PL, join_rules, join, 2 messages
    assert!(seen.windows(2).all(|w| w[0] < w[1]));

    // Timeline reads back the same order.
    let timeline = store.timeline(0, 100).unwrap();
    assert_eq!(timeline.len(), 7);
    assert_eq!(timeline.last().unwrap().0, m2);

    // Sender not in the room → rejected by the auth rules, stored as
    // rejected, invisible to timeline and extremities.
    let outcome = env
        .server
        .send_message(
            &room_id,
            &user("mallory"),
            "m.room.message",
            json!({"body": "let me in"}),
        )
        .await
        .unwrap();
    let rejected_id = match &outcome {
        Outcome::Rejected { event_id, .. } => event_id.clone(),
        other => panic!("expected Rejected, got {other:?}"),
    };
    // The sender's non-membership is already visible in the auth-event
    // state (their member event can't be selected), so this rejects at
    // the auth-chain stage.
    let se = store.event(rejected_id.as_str()).unwrap().unwrap();
    assert!(matches!(se.rejected, Some(Rejected::AuthChain(_))));
    assert_eq!(store.timeline(0, 100).unwrap().len(), 7);
    let meta = store.meta(room_id.as_str()).unwrap().unwrap();
    assert!(!meta.extremities.contains(&rejected_id.to_string()));

    // A PDU referencing unknown events surfaces the federation hook.
    let missing_prev = craft_pdu(
        &env,
        version,
        &room_id,
        alice.as_str(),
        "m.room.message",
        None,
        json!({"body": "orphan"}),
        &["$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()],
        &auth_ids_from_state(
            &env,
            version,
            &room_id,
            "m.room.message",
            &alice,
            None,
            &json!({}),
        ),
        50,
    );
    match env.server.ingest_pdu(missing_prev).await {
        Err(RoomError::MissingEvents(ids)) => assert_eq!(ids.len(), 1),
        other => panic!("expected MissingEvents, got {other:?}"),
    }

    env.server.shutdown().await.unwrap();
}

#[tokio::test]
async fn full_pipeline_v11() {
    full_pipeline(RoomVersion::V11).await;
}

#[tokio::test]
async fn full_pipeline_v12() {
    full_pipeline(RoomVersion::V12).await;
}

async fn fork_and_state_resolution(version: RoomVersion) {
    let env = start_env().await;
    let alice = user("alice");
    let bob = user("bob");
    let room_id = bootstrap_room(&env, version).await;

    let store = env.server.store();
    let meta = store.meta(room_id.as_str()).unwrap().unwrap();
    assert_eq!(meta.extremities.len(), 1);
    let tip = meta.extremities[0].clone();
    let tip_depth = store.event(&tip).unwrap().unwrap().depth;

    // Two topic events forking off the same tip (bob is at PL 50 =
    // state_default, so both are authorized).
    let topic = |sender: &OwnedUserId, text: &str| {
        craft_pdu(
            &env,
            version,
            &room_id,
            sender.as_str(),
            "m.room.topic",
            Some(""),
            json!({"topic": text}),
            std::slice::from_ref(&tip),
            &auth_ids_from_state(
                &env,
                version,
                &room_id,
                "m.room.topic",
                sender,
                Some(""),
                &json!({}),
            ),
            tip_depth + 1,
        )
    };
    let fork_a = topic(&alice, "alpha");
    let fork_b = topic(&bob, "beta");

    let a_id = match env.server.ingest_pdu(fork_a).await.unwrap() {
        Outcome::Accepted { event_id, .. } => event_id,
        other => panic!("fork A: {other:?}"),
    };
    let b_id = match env.server.ingest_pdu(fork_b).await.unwrap() {
        Outcome::Accepted { event_id, .. } => event_id,
        other => panic!("fork B: {other:?}"),
    };

    // Both fork heads are extremities; current state resolved to ONE topic.
    let meta = store.meta(room_id.as_str()).unwrap().unwrap();
    let mut ext = meta.extremities.clone();
    ext.sort();
    let mut expect = vec![a_id.to_string(), b_id.to_string()];
    expect.sort();
    assert_eq!(ext, expect);
    let state = store
        .resolve_group(room_id.as_str(), meta.current_group)
        .unwrap();
    let topic_id = state
        .get(&("m.room.topic".to_owned(), String::new()))
        .unwrap();
    assert!(topic_id == a_id.as_str() || topic_id == b_id.as_str());

    // m.room.topic is not a power event, so the forks fall to mainline
    // ordering: equal mainline position and origin_server_ts here, so the
    // event-ID tie-break decides — events are applied in ascending order
    // and the later application wins, i.e. the greater event ID.
    let winner = std::cmp::max(a_id.as_str(), b_id.as_str());
    assert_eq!(topic_id, winner);

    // A local send now merges the fork: prev = both extremities.
    let merge_seq = accepted(
        &env.server
            .send_message(
                &room_id,
                &alice,
                "m.room.message",
                json!({"body": "merged"}),
            )
            .await
            .unwrap(),
    );
    let meta = store.meta(room_id.as_str()).unwrap().unwrap();
    assert_eq!(meta.extremities.len(), 1);
    let merge_event = store.event(&meta.extremities[0]).unwrap().unwrap();
    assert_eq!(merge_event.seq, merge_seq);

    // Resolved topic survives the merge.
    let state = store
        .resolve_group(room_id.as_str(), meta.current_group)
        .unwrap();
    assert_eq!(
        state
            .get(&("m.room.topic".to_owned(), String::new()))
            .unwrap(),
        winner
    );

    // Re-ingesting a fork head is a duplicate, not an error.
    let dup = topic(&alice, "alpha");
    match env.server.ingest_pdu(dup).await.unwrap() {
        Outcome::Duplicate { event_id } => assert_eq!(event_id, a_id),
        other => panic!("expected Duplicate, got {other:?}"),
    }

    env.server.shutdown().await.unwrap();
}

#[tokio::test]
async fn fork_and_state_resolution_v11() {
    fork_and_state_resolution(RoomVersion::V11).await;
}

#[tokio::test]
async fn fork_and_state_resolution_v12() {
    fork_and_state_resolution(RoomVersion::V12).await;
}

#[tokio::test]
async fn restart_recovers_rooms() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db");
    let (signer, der) = ServerSigner::generate(
        ruma::OwnedServerName::try_from(SERVER).unwrap(),
        "0".to_owned(),
    );
    let signer = Arc::new(signer);
    let alice = user("alice");

    let room_id;
    let seq_before;
    {
        let engine = Arc::new(RocksEngine::open(&db).unwrap());
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

        let (rid, outcome) = server
            .create_room(&alice, RoomVersion::V12, serde_json::Map::new())
            .await
            .unwrap();
        accepted(&outcome);
        let join = server
            .send_state(
                &rid,
                &alice,
                "m.room.member",
                alice.as_str(),
                json!({"membership": "join"}),
            )
            .await
            .unwrap();
        seq_before = accepted(&join);
        room_id = rid;
        server.shutdown().await.unwrap();
    }

    // Reopen: same key (from the persisted DER), no bootstrap — recovery
    // must come from disk.
    let signer = Arc::new(
        ServerSigner::from_der(
            ruma::OwnedServerName::try_from(SERVER).unwrap(),
            &der,
            "0".to_owned(),
        )
        .unwrap(),
    );
    let engine = Arc::new(RocksEngine::open(&db).unwrap());
    let server = RoomServer::start(1, engine, signer, NoopNetworkFactory, None, None)
        .await
        .unwrap();
    server
        .shard_handle()
        .wait_for_leader(std::time::Duration::from_secs(10))
        .await
        .unwrap();

    assert_eq!(server.shard_handle().seq().unwrap(), seq_before);
    let store = server.store();
    let meta = store.meta(room_id.as_str()).unwrap().unwrap();
    assert_eq!(meta.version, "12");

    // The room still accepts events.
    let seq = accepted(
        &server
            .send_message(&room_id, &alice, "m.room.message", json!({"body": "back"}))
            .await
            .unwrap(),
    );
    assert_eq!(seq, seq_before + 1);
    server.shutdown().await.unwrap();
}

/// M2 additions: durable receipts, redaction application, per-room
/// timeline reads.
#[tokio::test]
async fn receipts_redactions_room_timeline() {
    let env = start_env().await;
    let alice = user("alice");
    let bob = user("bob");
    let carol = user("carol");
    let room_id = bootstrap_room(&env, RoomVersion::V12).await;
    let store = env.server.store();

    let m1 = env
        .server
        .send_message(
            &room_id,
            &bob,
            "m.room.message",
            json!({"msgtype": "m.text", "body": "one"}),
        )
        .await
        .unwrap();
    let (m1_id, m1_seq) = match &m1 {
        Outcome::Accepted { event_id, seq } => (event_id.clone(), *seq),
        other => panic!("{other:?}"),
    };
    let m2_seq = accepted(
        &env.server
            .send_message(
                &room_id,
                &bob,
                "m.room.message",
                json!({"msgtype": "m.text", "body": "two"}),
            )
            .await
            .unwrap(),
    );

    // Per-room timeline: full window, then a bounded backwards page.
    let tl = store
        .room_timeline(room_id.as_str(), 0, None, 100, false)
        .unwrap();
    assert_eq!(tl.len(), 7); // 5 bootstrap state events + 2 messages
    assert_eq!(tl[tl.len() - 2], (m1_seq, m1_id.to_string()));
    let last_two = store
        .room_timeline(room_id.as_str(), 0, None, 2, true)
        .unwrap();
    assert_eq!(last_two.len(), 2);
    assert_eq!(last_two[0].0, m2_seq);
    assert_eq!(last_two[1].0, m1_seq);

    // Receipts: recorded, deduplicated, visible in T_SEQ catch-up scans.
    let seq = env
        .server
        .write_receipt(&room_id, &alice, "m.read", &m1_id, 1000)
        .await
        .unwrap();
    assert!(seq > m2_seq);
    let dup = env
        .server
        .write_receipt(&room_id, &alice, "m.read", &m1_id, 2000)
        .await
        .unwrap();
    assert_eq!(dup, 0);
    let receipts = store.receipts(room_id.as_str()).unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].0, alice.as_str());
    assert_eq!(receipts[0].1, "m.read");
    assert_eq!(receipts[0].2.event_id, m1_id.as_str());
    let (last_seq, last_entry) = store.timeline(0, 100).unwrap().pop().unwrap();
    assert_eq!(last_seq, seq);
    assert!(matches!(last_entry, SeqEntry::Receipt { .. }));

    // Redaction by the original sender applies.
    accepted(
        &env.server
            .send_message(
                &room_id,
                &bob,
                "m.room.redaction",
                json!({"redacts": m1_id.as_str(), "reason": "typo"}),
            )
            .await
            .unwrap(),
    );
    let served = store
        .served_event(m1_id.as_str(), RoomVersion::V12)
        .unwrap()
        .unwrap();
    let content = match served.get("content").unwrap() {
        CanonicalJsonValue::Object(o) => o,
        _ => panic!("content not an object"),
    };
    assert!(content.is_empty(), "message content must be stripped");
    assert!(matches!(
        served.get("unsigned"),
        Some(CanonicalJsonValue::Object(u)) if u.contains_key("redacted_because")
    ));

    // Bob (PL 50) may not redact alice's events (redact level defaults to
    // 50 but alice is a v12 creator — her events aren't his to redact...
    // use carol instead: carol is not in the room, so use bob redacting
    // alice's join: PL 50 >= redact 50 actually allows it. Use a stricter
    // room-level check: carol (not even a member) can't send at all.
    let outcome = env
        .server
        .send_message(
            &room_id,
            &carol,
            "m.room.redaction",
            json!({"redacts": m1_id.as_str()}),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, Outcome::Rejected { .. }));

    env.server.shutdown().await.unwrap();
}

#[tokio::test]
async fn remote_servers_in_room_lists_only_joined_remotes() {
    let env = start_env().await;
    let room_id = bootstrap_room(&env, RoomVersion::V11).await;

    // The bootstrap room has only local members (alice, bob on hs.test).
    let servers = env
        .server
        .remote_servers_in_room(room_id.as_str(), SERVER)
        .unwrap();
    assert!(
        servers.is_empty(),
        "local-only room has no remote destinations, got {servers:?}"
    );

    // Inviting a remote user does not make them a destination: only joined
    // members count.
    let alice = user("alice");
    let outcome = env
        .server
        .send_state(
            &room_id,
            &alice,
            "m.room.member",
            "@carol:remote.example",
            json!({"membership": "invite"}),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, Outcome::Accepted { .. }));
    let servers = env
        .server
        .remote_servers_in_room(room_id.as_str(), SERVER)
        .unwrap();
    assert!(
        servers.is_empty(),
        "invited (not joined) remote is not a destination, got {servers:?}"
    );

    // An unknown room yields no destinations.
    let none = env
        .server
        .remote_servers_in_room("!nonexistent:hs.test", SERVER)
        .unwrap();
    assert!(none.is_empty());

    env.server.shutdown().await.unwrap();
}
