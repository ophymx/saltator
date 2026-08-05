//! End-to-end resident-side remote join over HTTP: node B fetches a join
//! template from node A (`make_join`), signs it, submits it
//! (`send_join`), and receives A's room state with B's membership applied.

use std::sync::Arc;
use std::time::Duration;

use ruma::{CanonicalJsonObject, CanonicalJsonValue, OwnedServerName};
use serde_json::json;

use saltator_core::RoomVersion;
use saltator_federation::{router, sign_request, FedState, KeyCache, OldVerifyKey};
use saltator_roomserver::{Outcome, RoomServer, ServerSigner};
use saltator_shard::NoopNetworkFactory;
use saltator_store::RocksEngine;

async fn spawn(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn start_rooms(
    server: &str,
    signer: Arc<ServerSigner>,
    dir: &std::path::Path,
) -> Arc<RoomServer> {
    let engine = Arc::new(RocksEngine::open(&dir.join(server)).unwrap());
    let rooms = RoomServer::start(
        1,
        engine,
        signer,
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    rooms
        .shard_handle()
        .wait_for_leader(Duration::from_secs(10))
        .await
        .unwrap();
    rooms
}

fn obj(v: serde_json::Value) -> CanonicalJsonObject {
    match CanonicalJsonValue::try_from(v).unwrap() {
        CanonicalJsonValue::Object(o) => o,
        _ => panic!("not an object"),
    }
}

/// The verification primitive behind H1 import checks: `verify_pdu_at`
/// accepts a genuinely-signed event only when the authoring server's keys
/// are trusted, and rejects it when untrusted or tampered.
#[tokio::test]
async fn verify_pdu_at_accepts_only_trusted_untampered_events() {
    let dir = tempfile::tempdir().unwrap();
    let a_name: OwnedServerName = "a.test".try_into().unwrap();
    let b_name: OwnedServerName = "b.test".try_into().unwrap();
    let (a_signer, _) = ServerSigner::generate(a_name.clone(), "1".to_owned());
    let (b_signer, _) = ServerSigner::generate(b_name, "1".to_owned());
    let a_signer = Arc::new(a_signer);

    // A signs a real event (the room create event).
    let rooms_a = start_rooms("a", a_signer.clone(), dir.path()).await;
    let alice = ruma::OwnedUserId::try_from("@alice:a.test").unwrap();
    let (_room_id, oc) = rooms_a
        .create_room(&alice, RoomVersion::V11, serde_json::Map::new())
        .await
        .unwrap();
    let create_id = match oc {
        Outcome::Accepted { event_id, .. } => event_id,
        other => panic!("{other:?}"),
    };
    let raw: CanonicalJsonObject = serde_json::from_slice(
        &rooms_a
            .store()
            .event(create_id.as_str())
            .unwrap()
            .unwrap()
            .raw,
    )
    .unwrap();

    // A separate server B does the verifying; it knows only its own keys.
    let rooms_b = start_rooms("b", Arc::new(b_signer), dir.path()).await;

    // Untrusted author -> rejected (fail closed).
    assert!(
        !rooms_b.verify_pdu_at(RoomVersion::V11, &raw),
        "must reject an event whose author's keys are untrusted"
    );

    // Trust A's keys -> the genuine event verifies.
    let a_keys = a_signer
        .public_key_map()
        .get("a.test")
        .cloned()
        .expect("a.test keys");
    rooms_b.trust_keys("a.test", a_keys);
    assert!(
        rooms_b.verify_pdu_at(RoomVersion::V11, &raw),
        "must accept a genuinely-signed event from a trusted server"
    );

    // Tampered content -> rejected even with the author trusted (the
    // content hash no longer matches the signed event).
    let mut forged = raw.clone();
    forged.insert(
        "content".to_owned(),
        CanonicalJsonValue::try_from(json!({"creator": "@attacker:a.test", "injected": true}))
            .unwrap(),
    );
    assert!(
        !rooms_b.verify_pdu_at(RoomVersion::V11, &forged),
        "must reject a tampered event"
    );

    rooms_a.shutdown().await.unwrap();
    rooms_b.shutdown().await.unwrap();
}

#[tokio::test]
async fn remote_join_handshake_returns_room_state() {
    let dir = tempfile::tempdir().unwrap();
    let a_name: OwnedServerName = "a.test".try_into().unwrap();
    let b_name: OwnedServerName = "b.test".try_into().unwrap();
    let (a_signer, _) = ServerSigner::generate(a_name.clone(), "1".to_owned());
    let (b_signer, _) = ServerSigner::generate(b_name.clone(), "1".to_owned());
    let a_signer = Arc::new(a_signer);
    let b_signer = Arc::new(b_signer);

    // Node A hosts a public room.
    let rooms = start_rooms("a", a_signer.clone(), dir.path()).await;
    let alice = ruma::OwnedUserId::try_from("@alice:a.test").unwrap();
    let (room_id, oc) = rooms
        .create_room(&alice, RoomVersion::V11, serde_json::Map::new())
        .await
        .unwrap();
    assert!(matches!(oc, Outcome::Accepted { .. }));
    // Bootstrap to a joinable state: creator joins, power levels, public
    // join rule.
    for (ty, sk, content) in [
        (
            "m.room.member",
            alice.as_str(),
            json!({"membership": "join"}),
        ),
        (
            "m.room.power_levels",
            "",
            json!({"users": {alice.as_str(): 100}}),
        ),
        ("m.room.join_rules", "", json!({"join_rule": "public"})),
    ] {
        let oc = rooms
            .send_state(&room_id, &alice, ty, sk, content)
            .await
            .unwrap();
        assert!(matches!(oc, Outcome::Accepted { .. }), "{ty} not accepted");
    }

    // B's key server, so A can verify B's requests and B's signed join.
    let b_key_base = spawn(router(Arc::new(FedState::new(
        b_name.clone(),
        b_signer.clone(),
        Vec::<OldVerifyKey>::new(),
    ))))
    .await;

    // Node A's federation surface, authenticating callers against B's keys.
    let a_state = Arc::new(FedState {
        server_name: a_name.clone(),
        signer: a_signer.clone(),
        old_keys: Vec::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(b_key_base)),
        rooms: Some(rooms.clone()),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
    });
    let a_base = spawn(router(a_state)).await;

    let http = reqwest::Client::new();
    let bob = "@bob:b.test";

    // --- make_join: B asks A for a template.
    let mj_path = format!(
        "/_matrix/federation/v1/make_join/{}/{}",
        urlencoding(room_id.as_str()),
        urlencoding(bob)
    );
    let auth = sign_request(&b_signer, "GET", &mj_path, "a.test", None).unwrap();
    let mj: serde_json::Value = http
        .get(format!("{a_base}{mj_path}"))
        .header(reqwest::header::AUTHORIZATION, auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(mj["room_version"], "11", "make_join: {mj}");
    let template = mj["event"].clone();
    assert_eq!(template["sender"], bob);
    assert_eq!(template["content"]["membership"], "join");

    // --- B fills and signs the template into a real join PDU.
    let mut join = obj(template);
    let version = RoomVersion::V11;
    b_signer.hash_and_sign_event(&mut join, version).unwrap();
    let join_value = serde_json::Value::from(CanonicalJsonValue::Object(join));

    // --- send_join: B submits the signed join; A applies it and returns
    // the room state.
    let sj_path = format!(
        "/_matrix/federation/v2/send_join/{}/{}",
        urlencoding(room_id.as_str()),
        urlencoding("$placeholder")
    );
    let content = CanonicalJsonValue::try_from(join_value.clone()).unwrap();
    let auth = sign_request(&b_signer, "PUT", &sj_path, "a.test", Some(&content)).unwrap();
    let resp = http
        .put(format!("{a_base}{sj_path}"))
        .header(reqwest::header::AUTHORIZATION, auth)
        .json(&join_value)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "send_join status");
    let sj: serde_json::Value = resp.json().await.unwrap();

    // The returned state carries the create event and bob's join.
    let state = sj["state"].as_array().expect("state array");
    let has_create = state.iter().any(|e| e["type"] == "m.room.create");
    let has_bob_join = state.iter().any(|e| {
        e["type"] == "m.room.member"
            && e["state_key"] == bob
            && e["content"]["membership"] == "join"
    });
    assert!(has_create, "state missing create: {sj}");
    assert!(has_bob_join, "state missing bob's join membership: {sj}");
    assert_eq!(sj["origin"], "a.test");
    assert!(sj["auth_chain"].as_array().is_some());

    // A now counts b.test as a remote server in the room.
    let servers = rooms
        .remote_servers_in_room(room_id.as_str(), "a.test")
        .unwrap();
    assert_eq!(servers, vec!["b.test".to_owned()]);
}

/// Minimal path-segment percent-encoding for room/user/event IDs.
fn urlencoding(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[tokio::test]
async fn join_client_drives_the_full_handshake() {
    use saltator_federation::{join_remote_room, resident_of_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let a_name: OwnedServerName = "a.test".try_into().unwrap();
    let b_name: OwnedServerName = "b.test".try_into().unwrap();
    let (a_signer, _) = ServerSigner::generate(a_name.clone(), "1".to_owned());
    let (b_signer, _) = ServerSigner::generate(b_name.clone(), "1".to_owned());
    let a_signer = Arc::new(a_signer);
    let b_signer = Arc::new(b_signer);

    // Node A hosts a public room.
    let rooms = start_rooms("a", a_signer.clone(), dir.path()).await;
    let alice = ruma::OwnedUserId::try_from("@alice:a.test").unwrap();
    let (room_id, _) = rooms
        .create_room(&alice, RoomVersion::V11, serde_json::Map::new())
        .await
        .unwrap();
    for (ty, sk, content) in [
        (
            "m.room.member",
            alice.as_str(),
            json!({"membership": "join"}),
        ),
        (
            "m.room.power_levels",
            "",
            json!({"users": {alice.as_str(): 100}}),
        ),
        ("m.room.join_rules", "", json!({"join_rule": "public"})),
    ] {
        rooms
            .send_state(&room_id, &alice, ty, sk, content)
            .await
            .unwrap();
    }

    let b_key_base = spawn(router(Arc::new(FedState::new(
        b_name.clone(),
        b_signer.clone(),
        Vec::<OldVerifyKey>::new(),
    ))))
    .await;
    let a_state = Arc::new(FedState {
        server_name: a_name.clone(),
        signer: a_signer.clone(),
        old_keys: Vec::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(b_key_base)),
        rooms: Some(rooms.clone()),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
    });
    let a_base = spawn(router(a_state)).await;

    // The joining side derives the resident from the room ID and runs the
    // handshake with its own signing client.
    assert_eq!(
        resident_of_room(room_id.as_str()).as_deref(),
        Some("a.test")
    );
    let client = FederationClient::with_base_url(b_signer.clone(), a_base);
    let resp = join_remote_room(
        &client,
        &b_signer,
        "a.test",
        room_id.as_str(),
        "@bob:b.test",
    )
    .await
    .expect("join handshake succeeds");

    assert_eq!(resp.room_version, RoomVersion::V11);
    // Our membership event came back, co-signed by both servers.
    let sigs = resp
        .event
        .get("signatures")
        .and_then(|s| s.as_object())
        .unwrap();
    assert!(sigs.contains_key("a.test"), "resident co-signature missing");
    assert!(sigs.contains_key("b.test"), "our signature missing");
    // State includes the create event and our join.
    let has_create = resp.state.iter().any(|e| {
        matches!(e.get("type"), Some(ruma::CanonicalJsonValue::String(s)) if s == "m.room.create")
    });
    assert!(has_create, "state missing create event");
    assert!(!resp.auth_chain.is_empty(), "auth chain empty");

    // --- Import the response into node B's own room shard.
    let b_rooms = start_rooms("b", b_signer.clone(), dir.path()).await;
    let outcome = b_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import succeeds");
    assert!(
        matches!(outcome, Outcome::Accepted { .. }),
        "import: {outcome:?}"
    );

    // B now hosts the room: bob is joined, and a.test is a remote peer.
    let b_state =
        b_rooms.make_join_template(&room_id, &ruma::UserId::parse("@carol:c.test").unwrap());
    assert!(b_state.is_ok(), "B should now know the room");
    let peers = b_rooms
        .remote_servers_in_room(room_id.as_str(), "b.test")
        .unwrap();
    assert_eq!(
        peers,
        vec!["a.test".to_owned()],
        "B sees a.test in the room"
    );

    // Bob can send a message in the imported room (prev = his join,
    // auth resolves against imported state).
    let bob = ruma::UserId::parse("@bob:b.test").unwrap();
    let sent = b_rooms
        .send_message(
            &room_id,
            &bob,
            "m.room.message",
            json!({"msgtype":"m.text","body":"hi from bob"}),
        )
        .await
        .expect("send in imported room");
    assert!(
        matches!(sent, Outcome::Accepted { .. }),
        "bob's message: {sent:?}"
    );
}

/// Regression: a steady-state `/send` transaction from a foreign origin
/// (no DAG gap to backfill) must still verify each PDU against that origin's
/// signing keys — which live only in the key cache until the transaction
/// handler trusts them. Before the fix, only the gap-fill and send_join
/// paths seeded the keys, so a plain remote message was rejected with
/// "Could not find public keys for entity".
#[tokio::test]
async fn foreign_origin_transaction_verifies_against_fetched_keys() {
    use saltator_federation::{join_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let a_name: OwnedServerName = "a.test".try_into().unwrap();
    let b_name: OwnedServerName = "b.test".try_into().unwrap();
    let (a_signer, _) = ServerSigner::generate(a_name.clone(), "1".to_owned());
    let (b_signer, _) = ServerSigner::generate(b_name.clone(), "1".to_owned());
    let a_signer = Arc::new(a_signer);
    let b_signer = Arc::new(b_signer);

    // A hosts a public room; alice is joined with full power.
    let rooms_a = start_rooms("a", a_signer.clone(), dir.path()).await;
    let alice = ruma::OwnedUserId::try_from("@alice:a.test").unwrap();
    let (room_id, _) = rooms_a
        .create_room(&alice, RoomVersion::V11, serde_json::Map::new())
        .await
        .unwrap();
    for (ty, sk, content) in [
        (
            "m.room.member",
            alice.as_str(),
            json!({"membership": "join"}),
        ),
        (
            "m.room.power_levels",
            "",
            json!({"users": {alice.as_str(): 100}}),
        ),
        ("m.room.join_rules", "", json!({"join_rule": "public"})),
    ] {
        rooms_a
            .send_state(&room_id, &alice, ty, sk, content)
            .await
            .unwrap();
    }

    // Standalone key servers so each side can fetch the other's keys.
    let a_key_base = spawn(router(Arc::new(FedState::new(
        a_name.clone(),
        a_signer.clone(),
        Vec::<OldVerifyKey>::new(),
    ))))
    .await;
    let b_key_base = spawn(router(Arc::new(FedState::new(
        b_name.clone(),
        b_signer.clone(),
        Vec::<OldVerifyKey>::new(),
    ))))
    .await;

    // A's federation surface (authenticates B) so B can join.
    let a_state = Arc::new(FedState {
        server_name: a_name.clone(),
        signer: a_signer.clone(),
        old_keys: Vec::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(b_key_base)),
        rooms: Some(rooms_a.clone()),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
    });
    let a_base = spawn(router(a_state)).await;

    // B joins A's room and imports it, so B now hosts a copy with alice's
    // state and bob's join present.
    let b_rooms = start_rooms("b", b_signer.clone(), dir.path()).await;
    let client = FederationClient::with_base_url(b_signer.clone(), a_base);
    let resp = join_remote_room(
        &client,
        &b_signer,
        "a.test",
        room_id.as_str(),
        "@bob:b.test",
    )
    .await
    .expect("join");
    b_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import");

    // A sends a message; its prev event is bob's join, which B already has,
    // so B's ingest takes the steady-state path (no gap-fill to seed keys).
    let msg = rooms_a
        .send_message(
            &room_id,
            &alice,
            "m.room.message",
            json!({"msgtype": "m.text", "body": "hello bob"}),
        )
        .await
        .unwrap();
    let msg_id = match msg {
        Outcome::Accepted { event_id, .. } => event_id,
        other => panic!("message not accepted: {other:?}"),
    };
    let msg_pdu: serde_json::Value =
        serde_json::from_slice(&rooms_a.store().event(msg_id.as_str()).unwrap().unwrap().raw)
            .unwrap();

    // B's federation surface: authenticates callers against A's keys and
    // routes PDUs to B's room server.
    let b_state = Arc::new(FedState {
        server_name: b_name.clone(),
        signer: b_signer.clone(),
        old_keys: Vec::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(a_key_base)),
        rooms: Some(b_rooms.clone()),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
    });
    let b_base = spawn(router(b_state)).await;

    // A delivers the message to B over /send. B has never trusted A's keys
    // outside the key cache; accepting the PDU requires fetching them.
    let body = json!({
        "origin": "a.test",
        "origin_server_ts": 1000,
        "pdus": [msg_pdu],
    });
    let path = "/_matrix/federation/v1/send/txn-msg";
    let content = CanonicalJsonValue::try_from(body.clone()).unwrap();
    let auth = sign_request(&a_signer, "PUT", path, "b.test", Some(&content)).unwrap();
    let resp = reqwest::Client::new()
        .put(format!("{b_base}{path}"))
        .header(reqwest::header::AUTHORIZATION, auth)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let out: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        &out["pdus"][msg_id.as_str()],
        &json!({}),
        "foreign message should verify and ingest: {out}"
    );

    // And it actually landed in B's room.
    assert!(
        b_rooms.store().event(msg_id.as_str()).unwrap().is_some(),
        "message not persisted on B"
    );
}

#[tokio::test]
async fn leave_client_rejects_over_federation() {
    use saltator_federation::{join_remote_room, leave_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let a_name: OwnedServerName = "a.test".try_into().unwrap();
    let b_name: OwnedServerName = "b.test".try_into().unwrap();
    let (a_signer, _) = ServerSigner::generate(a_name.clone(), "1".to_owned());
    let (b_signer, _) = ServerSigner::generate(b_name.clone(), "1".to_owned());
    let a_signer = Arc::new(a_signer);
    let b_signer = Arc::new(b_signer);

    // A hosts a public room.
    let rooms = start_rooms("a", a_signer.clone(), dir.path()).await;
    let alice = ruma::OwnedUserId::try_from("@alice:a.test").unwrap();
    let (room_id, _) = rooms
        .create_room(&alice, RoomVersion::V11, serde_json::Map::new())
        .await
        .unwrap();
    for (ty, sk, content) in [
        (
            "m.room.member",
            alice.as_str(),
            json!({"membership": "join"}),
        ),
        (
            "m.room.power_levels",
            "",
            json!({"users": {alice.as_str(): 100}}),
        ),
        ("m.room.join_rules", "", json!({"join_rule": "public"})),
    ] {
        rooms
            .send_state(&room_id, &alice, ty, sk, content)
            .await
            .unwrap();
    }

    let b_key_base = spawn(router(Arc::new(FedState::new(
        b_name.clone(),
        b_signer.clone(),
        Vec::<OldVerifyKey>::new(),
    ))))
    .await;
    let a_state = Arc::new(FedState {
        server_name: a_name.clone(),
        signer: a_signer.clone(),
        old_keys: Vec::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(b_key_base)),
        rooms: Some(rooms.clone()),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
    });
    let a_base = spawn(router(a_state)).await;

    let client = FederationClient::with_base_url(b_signer.clone(), a_base);
    // B joins, then leaves.
    join_remote_room(
        &client,
        &b_signer,
        "a.test",
        room_id.as_str(),
        "@bob:b.test",
    )
    .await
    .expect("join");
    assert_eq!(
        rooms
            .remote_servers_in_room(room_id.as_str(), "a.test")
            .unwrap(),
        vec!["b.test".to_owned()],
        "b.test should be a member after join"
    );

    leave_remote_room(
        &client,
        &b_signer,
        "a.test",
        room_id.as_str(),
        "@bob:b.test",
    )
    .await
    .expect("leave");
    assert!(
        rooms
            .remote_servers_in_room(room_id.as_str(), "a.test")
            .unwrap()
            .is_empty(),
        "b.test should be gone after leave"
    );
}

/// The make_knock/send_knock handshake: B knocks on A's knock_restricted
/// room, A applies the knock and returns stripped `knock_room_state` that
/// carries the create event and B's own knock membership (with reason). A
/// non-knock room (public) rejects the knock with a propagated 403.
#[tokio::test]
async fn knock_client_drives_the_full_handshake() {
    use saltator_federation::{knock_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let a_name: OwnedServerName = "a.test".try_into().unwrap();
    let b_name: OwnedServerName = "b.test".try_into().unwrap();
    let (a_signer, _) = ServerSigner::generate(a_name.clone(), "1".to_owned());
    let (b_signer, _) = ServerSigner::generate(b_name.clone(), "1".to_owned());
    let a_signer = Arc::new(a_signer);
    let b_signer = Arc::new(b_signer);

    // A hosts a v10 knock_restricted room, plus a public room to reject on.
    let rooms = start_rooms("ka", a_signer.clone(), dir.path()).await;
    let alice = ruma::OwnedUserId::try_from("@alice:a.test").unwrap();
    let make_room = |join_rule: &'static str| {
        let rooms = rooms.clone();
        let alice = alice.clone();
        async move {
            let (room_id, _) = rooms
                .create_room(&alice, RoomVersion::V10, serde_json::Map::new())
                .await
                .unwrap();
            for (ty, sk, content) in [
                (
                    "m.room.member",
                    alice.as_str(),
                    json!({"membership": "join"}),
                ),
                (
                    "m.room.power_levels",
                    "",
                    json!({"users": {alice.as_str(): 100}}),
                ),
                ("m.room.join_rules", "", json!({"join_rule": join_rule})),
            ] {
                rooms
                    .send_state(&room_id, &alice, ty, sk, content)
                    .await
                    .unwrap();
            }
            room_id
        }
    };
    let knock_room_id = make_room("knock_restricted").await;
    let public_room_id = make_room("public").await;

    let b_key_base = spawn(router(Arc::new(FedState::new(
        b_name.clone(),
        b_signer.clone(),
        Vec::<OldVerifyKey>::new(),
    ))))
    .await;
    let a_state = Arc::new(FedState {
        server_name: a_name.clone(),
        signer: a_signer.clone(),
        old_keys: Vec::new(),
        key_cache: std::sync::Arc::new(KeyCache::with_base_url(b_key_base)),
        rooms: Some(rooms.clone()),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
    });
    let a_base = spawn(router(a_state)).await;
    let client = FederationClient::with_base_url(b_signer.clone(), a_base);

    // --- Success: knock on the knock_restricted room.
    let resp = knock_remote_room(
        &client,
        &b_signer,
        "a.test",
        knock_room_id.as_str(),
        "@bob:b.test",
        Some("let me in"),
    )
    .await
    .expect("knock handshake succeeds");

    assert_eq!(resp.room_version, RoomVersion::V10);
    let has_create = resp
        .knock_room_state
        .iter()
        .any(|e| e.get("type").and_then(|t| t.as_str()) == Some("m.room.create"));
    assert!(
        has_create,
        "knock_room_state missing create: {:?}",
        resp.knock_room_state
    );
    let bob_knock = resp
        .knock_room_state
        .iter()
        .find(|e| {
            e.get("type").and_then(|t| t.as_str()) == Some("m.room.member")
                && e.get("state_key").and_then(|s| s.as_str()) == Some("@bob:b.test")
        })
        .expect("bob's knock member event in stripped state");
    assert_eq!(
        bob_knock
            .pointer("/content/membership")
            .and_then(|m| m.as_str()),
        Some("knock")
    );
    assert_eq!(
        bob_knock
            .pointer("/content/reason")
            .and_then(|m| m.as_str()),
        Some("let me in"),
        "reason should ride on the knock content"
    );

    // A knocked user knocking again is idempotent (accepted, not an error).
    knock_remote_room(
        &client,
        &b_signer,
        "a.test",
        knock_room_id.as_str(),
        "@bob:b.test",
        Some("again"),
    )
    .await
    .expect("re-knock succeeds");

    // --- Rejection: the public room does not accept knocks -> 403.
    let err = knock_remote_room(
        &client,
        &b_signer,
        "a.test",
        public_room_id.as_str(),
        "@bob:b.test",
        None,
    )
    .await
    .expect_err("knock on a public room is rejected");
    assert_eq!(
        err.remote_status(),
        Some(403),
        "a room that doesn't accept knocks returns 403: {err}"
    );
}

/// RoomServer::event_auth_chain returns an event's transitive auth events
/// (the /event_auth endpoint's body); unknown events give None.
#[tokio::test]
async fn event_auth_chain_includes_the_create_event() {
    let dir = tempfile::tempdir().unwrap();
    let a_name: OwnedServerName = "a.test".try_into().unwrap();
    let (a_signer, _) = ServerSigner::generate(a_name, "1".to_owned());
    let rooms = start_rooms("a", Arc::new(a_signer), dir.path()).await;
    let alice = ruma::OwnedUserId::try_from("@alice:a.test").unwrap();
    let (room_id, _) = rooms
        .create_room(&alice, RoomVersion::V11, serde_json::Map::new())
        .await
        .unwrap();
    rooms
        .send_state(
            &room_id,
            &alice,
            "m.room.member",
            alice.as_str(),
            json!({"membership":"join"}),
        )
        .await
        .unwrap();
    let pl = rooms
        .send_state(
            &room_id,
            &alice,
            "m.room.power_levels",
            "",
            json!({"users": {alice.as_str(): 100}}),
        )
        .await
        .unwrap();
    let pl_id = match pl {
        Outcome::Accepted { event_id, .. } => event_id.to_string(),
        other => panic!("{other:?}"),
    };

    let chain = rooms
        .event_auth_chain(&pl_id)
        .unwrap()
        .expect("known event has an auth chain");
    assert!(
        chain.iter().any(|o| matches!(
            o.get("type"),
            Some(CanonicalJsonValue::String(t)) if t == "m.room.create"
        )),
        "auth chain must include the create event"
    );
    assert!(rooms.event_auth_chain("$missing").unwrap().is_none());

    rooms.shutdown().await.unwrap();
}
