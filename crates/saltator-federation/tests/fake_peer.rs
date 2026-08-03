//! Exercises the mock federation peer ([`support::MockPeer`]): our server
//! joins a peer-hosted room, ingests a message the peer pushes, and rejects
//! a PDU the peer deliberately malforms. This is the local capability that
//! stands in for Complement's synthetic-peer tests (Groups 6b/8/…).

use std::sync::Arc;
use std::time::Duration;

use ruma::OwnedServerName;
use serde_json::json;

use saltator_core::RoomVersion;
use saltator_federation::{router, FedState, KeyCache, OldVerifyKey};
use saltator_roomserver::{Outcome, RoomServer, ServerSigner};
use saltator_shard::NoopNetworkFactory;
use saltator_store::RocksEngine;

use saltator_testsupport::{strip_signatures, MockPeer};

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

/// The peer hosts a public room; our server drives the make_join/send_join
/// handshake against it and imports the returned state — proving the peer
/// builds a room + join response our pipeline accepts.
#[tokio::test]
async fn our_server_joins_peer_hosted_room() {
    use saltator_federation::{join_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test").await;
    let room_id = peer.make_room(RoomVersion::V11, "charlie");

    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let client = FederationClient::with_base_url(hs_signer.clone(), peer.base_url.clone());
    let resp = join_remote_room(&client, &hs_signer, "peer.test", &room_id, "@alice:hs.test")
        .await
        .expect("join handshake against the mock peer");

    assert_eq!(resp.room_version, RoomVersion::V11);
    // The resident omits `event` (like Synapse), so we fall back to the join
    // we submitted — signed by us.
    let sigs = resp.event.get("signatures").unwrap().as_object().unwrap();
    assert!(sigs.contains_key("hs.test"), "our signature missing");
    assert!(
        resp.state
            .iter()
            .any(|e| matches!(e.get("type"), Some(ruma::CanonicalJsonValue::String(t)) if t == "m.room.create")),
        "state missing create event"
    );

    let outcome = our_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import the peer's room");
    assert!(matches!(outcome, Outcome::Accepted { .. }), "{outcome:?}");

    // Our server now hosts a copy with the peer as a remote member.
    let peers = our_rooms
        .remote_servers_in_room(&room_id, "hs.test")
        .unwrap();
    assert_eq!(peers, vec!["peer.test".to_owned()]);

    our_rooms.shutdown().await.unwrap();
}

/// After the join, the peer pushes a genuinely-signed message over `/send`;
/// our server fetches the peer's keys and ingests it.
#[tokio::test]
async fn peer_pushed_message_is_ingested() {
    use saltator_federation::{join_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test").await;
    let room_id = peer.make_room(RoomVersion::V11, "charlie");

    // Our server joins + imports the room.
    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let client = FederationClient::with_base_url(hs_signer.clone(), peer.base_url.clone());
    let resp = join_remote_room(&client, &hs_signer, "peer.test", &room_id, "@alice:hs.test")
        .await
        .expect("join");
    our_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import");

    // Our federation surface: authenticates callers against the peer's keys
    // (fetched from the peer's key server) and routes PDUs to our rooms.
    let our_fed = Arc::new(FedState {
        server_name: hs.clone(),
        signer: hs_signer.clone(),
        old_keys: Vec::<OldVerifyKey>::new(),
        key_cache: KeyCache::with_base_url(peer.base_url.clone()),
        rooms: Some(our_rooms.clone()),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
    });
    let our_base = spawn(router(our_fed)).await;

    // The peer authors a message (prev = alice's join, which we hold).
    let charlie = "@charlie:peer.test";
    let msg_id = peer.with_room(&room_id, |room| {
        room.message(
            charlie,
            json!({"msgtype": "m.text", "body": "hi from the peer"}),
        )
    });
    let msg = peer.with_room(&room_id, |room| room.raw(&msg_id));

    let out = peer.send_transaction(&our_base, "hs.test", vec![msg]).await;
    assert_eq!(
        &out["pdus"][&msg_id],
        &json!({}),
        "peer message should verify and ingest: {out}"
    );
    assert!(
        our_rooms.store().event(&msg_id).unwrap().is_some(),
        "message not persisted"
    );

    our_rooms.shutdown().await.unwrap();
}

/// An event whose `auth_events` cite a *rejected* event is itself rejected,
/// while a normal sentinel alongside it is accepted (the core rule behind
/// Complement's TestInboundFederationRejectsEventsWithRejectedAuthEvents).
#[tokio::test]
async fn event_citing_rejected_auth_event_is_rejected() {
    use saltator_federation::{join_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test").await;
    let room_id = peer.make_room(RoomVersion::V11, "charlie");

    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let client = FederationClient::with_base_url(hs_signer.clone(), peer.base_url.clone());
    let resp = join_remote_room(&client, &hs_signer, "peer.test", &room_id, "@alice:hs.test")
        .await
        .expect("join");
    our_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import");

    let our_fed = Arc::new(FedState {
        server_name: hs.clone(),
        signer: hs_signer.clone(),
        old_keys: Vec::<OldVerifyKey>::new(),
        key_cache: KeyCache::with_base_url(peer.base_url.clone()),
        rooms: Some(our_rooms.clone()),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
    });
    let our_base = spawn(router(our_fed)).await;

    // Gather the state event IDs to hand-build auth chains.
    let (tip, create, pl, charlie_m) = peer.with_room(&room_id, |r| {
        (
            r.tip(),
            r.state_event_id("m.room.create", "").unwrap(),
            r.state_event_id("m.room.power_levels", "").unwrap(),
            r.state_event_id("m.room.member", "@charlie:peer.test")
                .unwrap(),
        )
    });

    // R: a power-levels event from @mallory, who is NOT a member — our server
    // rejects it on auth (the sender is not joined / lacks power).
    let (r_id, r_raw) = peer.with_room(&room_id, |r| {
        r.craft(
            "@mallory:peer.test",
            "m.room.power_levels",
            Some(""),
            json!({"users": {}}),
            tip.clone(),
            vec![create.clone(), pl.clone()],
        )
    });
    // X: a well-formed message from charlie, but citing the rejected R in the
    // (type-permitted) power-levels slot of its auth_events — must be rejected
    // as a consequence of R being rejected.
    let (x_id, x_raw) = peer.with_room(&room_id, |r| {
        r.craft(
            "@charlie:peer.test",
            "m.room.message",
            None,
            json!({"body": "X cites rejected R"}),
            tip.clone(),
            vec![create.clone(), r_id.clone(), charlie_m.clone()],
        )
    });
    // S: a genuine sentinel (cites the real power levels) that must be accepted.
    let (s_id, s_raw) = peer.with_room(&room_id, |r| {
        r.craft(
            "@charlie:peer.test",
            "m.room.message",
            None,
            json!({"body": "sentinel"}),
            tip.clone(),
            vec![create, pl, charlie_m],
        )
    });

    let out = peer
        .send_transaction(&our_base, "hs.test", vec![r_raw, x_raw, s_raw])
        .await;

    let rejected = |id: &str| {
        our_rooms
            .store()
            .event(id)
            .unwrap()
            .map(|e| e.rejected.is_some())
    };
    assert_eq!(rejected(&r_id), Some(true), "R must be rejected: {out}");
    assert_eq!(
        rejected(&x_id),
        Some(true),
        "X cites rejected R and must be rejected: {out}"
    );
    assert_eq!(
        rejected(&s_id),
        Some(false),
        "sentinel S must be accepted: {out}"
    );

    our_rooms.shutdown().await.unwrap();
}

/// After joining the peer's room, a message our local user sends is
/// delivered outbound to the peer (which shares the room) — the outbound
/// half of Complement's TestOutboundFederationSend.
#[tokio::test]
async fn outbound_send_reaches_remote_members() {
    use saltator_federation::{join_remote_room, spawn_sender, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test").await;
    let room_id = peer.make_room(RoomVersion::V11, "charlie");

    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;

    // Start the outbound sender *before* the join, as a real server would
    // (it runs continuously). This puts the imported join within the
    // sender's window, so the co-signer-skip is actually exercised.
    let sender = spawn_sender(
        our_rooms.clone(),
        Arc::new(FederationClient::with_base_url(
            hs_signer.clone(),
            peer.base_url.clone(),
        )),
        hs.clone(),
    );

    let client = FederationClient::with_base_url(hs_signer.clone(), peer.base_url.clone());
    let resp = join_remote_room(&client, &hs_signer, "peer.test", &room_id, "@alice:hs.test")
        .await
        .expect("join");
    our_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import");

    // Our local user (joined via the handshake) sends a message.
    let alice = ruma::UserId::parse("@alice:hs.test").unwrap();
    let room = ruma::RoomId::parse(&room_id).unwrap();
    let sent = our_rooms
        .send_message(
            &room,
            &alice,
            "m.room.message",
            json!({"msgtype": "m.text", "body": "Hello world!"}),
        )
        .await
        .expect("send");
    let msg_id = match sent {
        Outcome::Accepted { event_id, .. } => event_id.to_string(),
        other => panic!("message not accepted: {other:?}"),
    };

    // The peer should receive it in a transaction (delivery is async).
    let mut delivered = false;
    for _ in 0..50 {
        if peer.received().iter().any(|txn| {
            txn.origin == "hs.test"
                && txn.pdus.iter().any(|p| {
                    p.get("type").and_then(|t| t.as_str()) == Some("m.room.message")
                        && p.get("content")
                            .and_then(|c| c.get("body"))
                            .and_then(|b| b.as_str())
                            == Some("Hello world!")
                })
        }) {
            delivered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        delivered,
        "peer never received the outbound message {msg_id}; got {:?}",
        peer.received()
    );

    // Our co-signed join must NOT be echoed back to the resident (it already
    // co-signed and distributed it): the peer should see no m.room.member
    // from us in any received transaction.
    let echoed_membership = peer.received().iter().any(|txn| {
        txn.pdus.iter().any(|p| {
            p.get("type").and_then(|t| t.as_str()) == Some("m.room.member")
                && p.get("sender").and_then(|s| s.as_str()) == Some("@alice:hs.test")
        })
    });
    assert!(
        !echoed_membership,
        "our join membership was echoed back to the resident: {:?}",
        peer.received()
    );

    sender.abort();
    our_rooms.shutdown().await.unwrap();
}

/// After importing a room hosted on a server whose name carries a *port*
/// (`peer.test:1099`), our local user can still send into it — a regression
/// guard for the ported-server-name send bug (Complement's servers are all
/// `host.docker.internal:PORT`).
#[tokio::test]
async fn local_send_in_imported_ported_room() {
    use saltator_federation::{join_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test:1099").await;
    let room_id = peer.make_room(RoomVersion::V11, "charlie");

    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let client = FederationClient::with_base_url(hs_signer.clone(), peer.base_url.clone());
    let resp = join_remote_room(
        &client,
        &hs_signer,
        "peer.test:1099",
        &room_id,
        "@alice:hs.test",
    )
    .await
    .expect("join");
    our_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import");

    let alice = ruma::UserId::parse("@alice:hs.test").unwrap();
    let room = ruma::RoomId::parse(&room_id).unwrap();
    let sent = our_rooms
        .send_message(
            &room,
            &alice,
            "m.room.message",
            json!({"msgtype": "m.text", "body": "hi"}),
        )
        .await;
    assert!(
        matches!(sent, Ok(Outcome::Accepted { .. })),
        "send into a ported-server imported room should be accepted: {sent:?}"
    );

    our_rooms.shutdown().await.unwrap();
}

/// The peer crafts a PDU with its signature stripped; our server must reject
/// it on `/send` and not persist it (the Group 6b/8 capability).
#[tokio::test]
async fn peer_malformed_pdu_is_rejected() {
    use saltator_federation::{join_remote_room, FederationClient};

    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);

    let peer = MockPeer::start("peer.test").await;
    let room_id = peer.make_room(RoomVersion::V11, "charlie");

    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let client = FederationClient::with_base_url(hs_signer.clone(), peer.base_url.clone());
    let resp = join_remote_room(&client, &hs_signer, "peer.test", &room_id, "@alice:hs.test")
        .await
        .expect("join");
    our_rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .expect("import");

    let our_fed = Arc::new(FedState {
        server_name: hs.clone(),
        signer: hs_signer.clone(),
        old_keys: Vec::<OldVerifyKey>::new(),
        key_cache: KeyCache::with_base_url(peer.base_url.clone()),
        rooms: Some(our_rooms.clone()),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
    });
    let our_base = spawn(router(our_fed)).await;

    // Author a valid message, then strip its signatures before delivery.
    let charlie = "@charlie:peer.test";
    let msg_id = peer.with_room(&room_id, |room| {
        room.message(charlie, json!({"msgtype": "m.text", "body": "unsigned"}))
    });
    let forged = strip_signatures(peer.with_room(&room_id, |room| room.raw(&msg_id)));

    let out = peer
        .send_transaction(&our_base, "hs.test", vec![forged])
        .await;
    assert_ne!(
        &out["pdus"][&msg_id],
        &json!({}),
        "an unsigned PDU must not report success: {out}"
    );
    assert!(
        our_rooms.store().event(&msg_id).unwrap().is_none(),
        "an unsigned PDU must not be persisted"
    );

    our_rooms.shutdown().await.unwrap();
}

/// A PDU whose origin is denied by the room's m.room.server_acl is dropped
/// on inbound /send, while the same origin is unaffected in a room that
/// allows it (Complement TestACLs).
#[tokio::test]
async fn inbound_pdu_from_acl_denied_server_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let hs: OwnedServerName = "hs.test".try_into().unwrap();
    let (hs_signer, _) = ServerSigner::generate(hs.clone(), "1".to_owned());
    let hs_signer = Arc::new(hs_signer);
    // A ported name, as Complement/deployments use — the ACL entry and the
    // sending origin must match on the full `host:port`.
    let peer = MockPeer::start("peer.test:9001").await;

    let our_rooms = start_rooms("hs", hs_signer.clone(), dir.path()).await;
    let alice = ruma::OwnedUserId::try_from("@alice:hs.test").unwrap();

    // A room whose ACL denies the peer (by its full host:port), and one that allows it.
    let mk_room = |acl_deny: &'static str| {
        let rooms = our_rooms.clone();
        let alice = alice.clone();
        async move {
            let (room, _) = rooms
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
                (
                    "m.room.server_acl",
                    "",
                    json!({"allow": ["*"], "deny": [acl_deny]}),
                ),
            ] {
                rooms
                    .send_state(&room, &alice, ty, sk, content)
                    .await
                    .unwrap();
            }
            room.to_string()
        }
    };
    let denied_room = mk_room("peer.test:9001").await;
    let open_room = mk_room("other.test").await;

    let our_fed = Arc::new(FedState {
        server_name: hs.clone(),
        signer: hs_signer.clone(),
        old_keys: Vec::<OldVerifyKey>::new(),
        key_cache: KeyCache::with_base_url(peer.base_url.clone()),
        rooms: Some(our_rooms.clone()),
        users: None,
        client: None,
        edu_sink: None,
        media: None,
    });
    let our_base = spawn(router(our_fed)).await;

    // A signed message PDU for `room` from a user on the peer.
    let make_pdu = |room: &str| {
        let mut raw = match ruma::CanonicalJsonValue::try_from(json!({
            "room_id": room,
            "sender": "@mallory:peer.test:9001",
            "type": "m.room.message",
            "content": {"msgtype": "m.text", "body": "hi"},
            "auth_events": [],
            "prev_events": [],
            "depth": 5,
            "origin_server_ts": 1_700_000_000_000u64,
        }))
        .unwrap()
        {
            ruma::CanonicalJsonValue::Object(o) => o,
            _ => unreachable!(),
        };
        peer.signer
            .hash_and_sign_event(&mut raw, RoomVersion::V11)
            .unwrap();
        raw
    };

    // Denied room: the PDU is ACL-rejected and not persisted.
    let denied_pdu = make_pdu(&denied_room);
    let denied_id = saltator_core::event::event_id(&denied_pdu, RoomVersion::V11)
        .unwrap()
        .to_string();
    let out = peer
        .send_transaction(&our_base, "hs.test", vec![denied_pdu])
        .await;
    assert!(
        out["pdus"][&denied_id]["error"]
            .as_str()
            .unwrap_or_default()
            .contains("server ACL"),
        "denied PDU should be ACL-rejected: {out}"
    );
    assert!(our_rooms.store().event(&denied_id).unwrap().is_none());

    // Allowed room: the same origin is NOT ACL-rejected (it fails ingest for
    // a different reason — missing events — proving the ACL let it through).
    let open_pdu = make_pdu(&open_room);
    let open_id = saltator_core::event::event_id(&open_pdu, RoomVersion::V11)
        .unwrap()
        .to_string();
    let out = peer
        .send_transaction(&our_base, "hs.test", vec![open_pdu])
        .await;
    assert!(
        !out["pdus"][&open_id]["error"]
            .as_str()
            .unwrap_or_default()
            .contains("server ACL"),
        "allowed server must not be ACL-rejected: {out}"
    );

    our_rooms.shutdown().await.unwrap();
}
