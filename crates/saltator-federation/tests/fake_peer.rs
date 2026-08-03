//! Exercises the mock federation peer ([`support::MockPeer`]): our server
//! joins a peer-hosted room, ingests a message the peer pushes, and rejects
//! a PDU the peer deliberately malforms. This is the local capability that
//! stands in for Complement's synthetic-peer tests (Groups 6b/8/…).

mod support;

use std::sync::Arc;
use std::time::Duration;

use ruma::OwnedServerName;
use serde_json::json;

use saltator_core::RoomVersion;
use saltator_federation::{router, FedState, KeyCache, OldVerifyKey};
use saltator_roomserver::{Outcome, RoomServer, ServerSigner};
use saltator_shard::NoopNetworkFactory;
use saltator_store::RocksEngine;

use support::{strip_signatures, MockPeer};

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
    // Co-signed by the peer (resident) and us (joiner).
    let sigs = resp.event.get("signatures").unwrap().as_object().unwrap();
    assert!(sigs.contains_key("peer.test"), "peer co-signature missing");
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
